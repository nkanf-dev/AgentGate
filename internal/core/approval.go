package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/agentgate/agentgate/internal/types"
)

type ApprovalStore interface {
	Create(ctx context.Context, approval types.ApprovalRecord, event types.EventEnvelope) error
	Resolve(ctx context.Context, command types.ApprovalResolveCommand, event types.EventEnvelope) (types.ApprovalResolveResult, error)
	Expire(ctx context.Context, approvalID string, expiredAt time.Time, event types.EventEnvelope) (types.ApprovalRecord, error)
	Await(ctx context.Context, approvalID string, expiresAt time.Time) (types.ApprovalRecord, error)
	FindPending(ctx context.Context, sessionID, taskID, attemptID string, now time.Time) (*types.ApprovalRecord, error)
	ValidGrant(ctx context.Context, session types.SessionContext, now time.Time) (types.AttemptGrant, bool, error)
	Hydrate(ctx context.Context) error
	List(ctx context.Context, limit int) ([]types.ApprovalRecord, error)
}

type sqliteApprovalStore struct {
	stateStore StateStore
	eventStore EventStore

	mu        sync.RWMutex
	approvals map[string]types.ApprovalRecord
	resolved  map[string]types.ApprovalRecord
	grants    map[string]types.AttemptGrant
	waiters   map[string][]chan types.ApprovalRecord
	timers    map[string]*time.Timer
	contexts  map[string]approvalEventContext
}

type approvalEventContext struct {
	surface     types.Surface
	requestKind types.RequestKind
}

var approvalExpirationRetryDelay = 1 * time.Second

func newApprovalStore(stateStore StateStore, eventStore EventStore) ApprovalStore {
	return &sqliteApprovalStore{
		stateStore: stateStore,
		eventStore: eventStore,
		approvals:  make(map[string]types.ApprovalRecord),
		resolved:   make(map[string]types.ApprovalRecord),
		grants:     make(map[string]types.AttemptGrant),
		waiters:    make(map[string][]chan types.ApprovalRecord),
		timers:     make(map[string]*time.Timer),
		contexts:   make(map[string]approvalEventContext),
	}
}

func (s *sqliteApprovalStore) Hydrate(ctx context.Context) error {
	if s.stateStore == nil {
		return nil
	}
	const limit = 1000000
	records, err := s.stateStore.ListApprovals(ctx, limit)
	if err != nil {
		return err
	}
	grants, err := s.stateStore.ListAttemptGrants(ctx)
	if err != nil {
		return err
	}
	contexts, err := s.loadApprovalEventContexts(ctx, records)
	if err != nil {
		return err
	}
	pending := make([]types.ApprovalRecord, 0, len(records))
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range records {
		if record.Status == types.ApprovalPending {
			s.approvals[record.ApprovalID] = record
			s.contexts[record.ApprovalID] = contexts[record.ApprovalID]
			pending = append(pending, record)
			continue
		}
		s.resolved[record.ApprovalID] = record
	}
	for _, grant := range grants {
		s.grants[attemptKey(grant.SessionID, grant.TaskID, grant.AttemptID)] = grant.Grant
	}
	for _, record := range pending {
		s.scheduleExpirationLocked(record)
	}
	return nil
}

func (s *sqliteApprovalStore) Create(ctx context.Context, approval types.ApprovalRecord, event types.EventEnvelope) error {
	if s.stateStore != nil {
		if err := s.stateStore.CreateApprovalAtomic(ctx, approval, event); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.approvals[approval.ApprovalID] = approval
	delete(s.resolved, approval.ApprovalID)
	s.contexts[approval.ApprovalID] = approvalEventContextFromEvent(event)
	s.scheduleExpirationLocked(approval)
	s.mu.Unlock()
	return nil
}

func (s *sqliteApprovalStore) Resolve(ctx context.Context, command types.ApprovalResolveCommand, event types.EventEnvelope) (types.ApprovalResolveResult, error) {
	if s.stateStore != nil {
		result, err := s.stateStore.ResolveApprovalAtomic(ctx, command, event)
		if err != nil {
			return types.ApprovalResolveResult{}, err
		}
		s.cacheResolved(result.Approval, result.Grant)
		return result, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.approvals[command.ApprovalID]
	if !ok {
		return types.ApprovalResolveResult{}, errStatus(http.StatusNotFound, "approval_not_found", "approval was not found")
	}
	if record.Status != types.ApprovalPending {
		return types.ApprovalResolveResult{}, errStatus(http.StatusConflict, "approval_already_resolved", "approval is already resolved")
	}
	if !record.ExpiresAt.After(command.ResolvedAt) {
		record.Status = types.ApprovalExpired
		record.ResolvedAt = &command.ResolvedAt
		record.OperatorID = command.OperatorID
		record.Channel = command.Channel
		s.finishLocked(record, nil)
		return types.ApprovalResolveResult{}, errStatus(http.StatusConflict, "approval_expired", "approval has expired")
	}
	switch strings.ToLower(strings.TrimSpace(command.Decision)) {
	case "approve", "approved", "allow", "allow_once":
		record.Status = types.ApprovalApproved
	case "deny", "denied", "reject", "rejected":
		record.Status = types.ApprovalDenied
	default:
		return types.ApprovalResolveResult{}, errBadRequest("invalid_approval_decision", "decision must be approve/allow_once or deny")
	}
	record.ResolvedAt = &command.ResolvedAt
	record.OperatorID = command.OperatorID
	record.Channel = command.Channel
	result := types.ApprovalResolveResult{Approval: record}
	if record.Status == types.ApprovalApproved {
		grant := types.AttemptGrant{ApprovalID: record.ApprovalID, ExpiresAt: record.ExpiresAt}
		result.Grant = &grant
	}
	s.finishLocked(record, result.Grant)
	return result, nil
}

func (s *sqliteApprovalStore) Expire(ctx context.Context, approvalID string, expiredAt time.Time, event types.EventEnvelope) (types.ApprovalRecord, error) {
	if s.stateStore != nil {
		record, err := s.stateStore.ExpireApprovalAtomic(ctx, approvalID, expiredAt, event)
		if err != nil {
			return types.ApprovalRecord{}, err
		}
		s.cacheResolved(record, nil)
		return record, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.approvals[approvalID]
	if !ok {
		if resolved, ok := s.resolved[approvalID]; ok {
			return resolved, nil
		}
		return types.ApprovalRecord{}, errStatus(http.StatusNotFound, "approval_not_found", "approval was not found")
	}
	if record.Status != types.ApprovalPending {
		return record, nil
	}
	record.Status = types.ApprovalExpired
	record.ResolvedAt = &expiredAt
	s.finishLocked(record, nil)
	return record, nil
}

func (s *sqliteApprovalStore) Await(ctx context.Context, approvalID string, expiresAt time.Time) (types.ApprovalRecord, error) {
	if record, found, err := s.currentRecord(ctx, approvalID); err != nil {
		return types.ApprovalRecord{}, err
	} else if found && record.Status != types.ApprovalPending {
		return record, nil
	}

	ch := make(chan types.ApprovalRecord, 1)
	s.addWaiter(approvalID, ch)
	defer s.removeWaiter(approvalID, ch)

	// Re-check after waiter registration to avoid missing a concurrent resolve.
	if record, found, err := s.currentRecord(ctx, approvalID); err != nil {
		return types.ApprovalRecord{}, err
	} else if found && record.Status != types.ApprovalPending {
		return record, nil
	}

	waitDuration := time.Until(expiresAt)
	if waitDuration <= 0 {
		return s.expirePending(context.Background(), approvalID, time.Now().UTC())
	}
	timer := time.NewTimer(waitDuration)
	defer timer.Stop()

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case record := <-ch:
			return record, nil
		case <-ctx.Done():
			return types.ApprovalRecord{}, ctx.Err()
		case <-timer.C:
			return s.expirePending(context.Background(), approvalID, time.Now().UTC())
		case <-ticker.C:
			record, found, err := s.currentRecord(ctx, approvalID)
			if err != nil {
				return types.ApprovalRecord{}, err
			}
			if found && record.Status != types.ApprovalPending {
				return record, nil
			}
		}
	}
}

func (s *sqliteApprovalStore) FindPending(ctx context.Context, sessionID, taskID, attemptID string, now time.Time) (*types.ApprovalRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, approval := range s.approvals {
		if !approval.ExpiresAt.After(now) {
			delete(s.approvals, id)
			s.resolved[id] = types.ApprovalRecord{
				ApprovalID: approval.ApprovalID,
				RequestID:  approval.RequestID,
				SessionID:  approval.SessionID,
				TaskID:     approval.TaskID,
				AttemptID:  approval.AttemptID,
				Status:     types.ApprovalExpired,
				Reason:     approval.Reason,
				Channel:    approval.Channel,
				CreatedAt:  approval.CreatedAt,
				ExpiresAt:  approval.ExpiresAt,
			}
			continue
		}
		if approval.SessionID == sessionID &&
			approval.TaskID == taskID &&
			approval.AttemptID == attemptID {
			copy := approval
			return &copy, nil
		}
	}
	return nil, nil
}

func (s *sqliteApprovalStore) ValidGrant(ctx context.Context, session types.SessionContext, now time.Time) (types.AttemptGrant, bool, error) {
	key := attemptKey(session.SessionID, session.TaskID, session.AttemptID)
	s.mu.Lock()
	grant, ok := s.grants[key]
	if ok && !grant.ExpiresAt.After(now) {
		delete(s.grants, key)
		ok = false
	}
	s.mu.Unlock()
	if !ok && s.stateStore != nil {
		stored, found, err := s.stateStore.GetAttemptGrant(ctx, session.SessionID, session.TaskID, session.AttemptID)
		if err != nil {
			return types.AttemptGrant{}, false, err
		}
		if found {
			if !stored.ExpiresAt.After(now) {
				return types.AttemptGrant{}, false, nil
			}
			s.mu.Lock()
			s.grants[key] = stored
			s.mu.Unlock()
			grant = stored
			ok = true
		}
	}
	if ok {
		return grant, true, nil
	}
	return types.AttemptGrant{}, false, nil
}

func (s *sqliteApprovalStore) List(ctx context.Context, limit int) ([]types.ApprovalRecord, error) {
	if s.stateStore != nil {
		return s.stateStore.ListApprovals(ctx, limit)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	results := make([]types.ApprovalRecord, 0, len(s.approvals)+len(s.resolved))
	for _, a := range s.approvals {
		results = append(results, a)
	}
	for _, a := range s.resolved {
		results = append(results, a)
	}
	return results, nil
}

func (s *sqliteApprovalStore) OverrideApproval(ctx context.Context, approval types.ApprovalRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if approval.Status == types.ApprovalPending {
		s.approvals[approval.ApprovalID] = approval
		delete(s.resolved, approval.ApprovalID)
		return
	}
	delete(s.approvals, approval.ApprovalID)
	s.resolved[approval.ApprovalID] = approval
}

func (s *sqliteApprovalStore) SnapshotApprovals(ctx context.Context) map[string]types.ApprovalRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copyMap := make(map[string]types.ApprovalRecord, len(s.approvals))
	for k, v := range s.approvals {
		copyMap[k] = v
	}
	return copyMap
}

func (s *sqliteApprovalStore) SnapshotGrants(ctx context.Context) map[string]types.AttemptGrant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copyMap := make(map[string]types.AttemptGrant, len(s.grants))
	for k, v := range s.grants {
		copyMap[k] = v
	}
	return copyMap
}

func (s *sqliteApprovalStore) currentRecord(ctx context.Context, approvalID string) (types.ApprovalRecord, bool, error) {
	s.mu.RLock()
	if record, ok := s.resolved[approvalID]; ok {
		s.mu.RUnlock()
		return record, true, nil
	}
	if record, ok := s.approvals[approvalID]; ok {
		s.mu.RUnlock()
		return record, true, nil
	}
	s.mu.RUnlock()

	if s.stateStore == nil {
		return types.ApprovalRecord{}, false, nil
	}
	record, found, err := s.stateStore.GetApproval(ctx, approvalID)
	if err != nil {
		return types.ApprovalRecord{}, false, err
	}
	if !found {
		return types.ApprovalRecord{}, false, nil
	}
	if record.Status == types.ApprovalPending {
		s.mu.Lock()
		s.approvals[approvalID] = record
		if _, exists := s.timers[approvalID]; !exists {
			s.scheduleExpirationLocked(record)
		}
		s.mu.Unlock()
		return record, true, nil
	}
	s.cacheResolved(record, nil)
	return record, true, nil
}

func (s *sqliteApprovalStore) cacheResolved(record types.ApprovalRecord, grant *types.AttemptGrant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finishLocked(record, grant)
}

func (s *sqliteApprovalStore) finishLocked(record types.ApprovalRecord, grant *types.AttemptGrant) {
	delete(s.approvals, record.ApprovalID)
	s.resolved[record.ApprovalID] = record
	if timer := s.timers[record.ApprovalID]; timer != nil {
		timer.Stop()
		delete(s.timers, record.ApprovalID)
	}
	delete(s.contexts, record.ApprovalID)
	if grant != nil {
		key := attemptKey(record.SessionID, record.TaskID, record.AttemptID)
		s.grants[key] = *grant
	}
	waiters := append([]chan types.ApprovalRecord(nil), s.waiters[record.ApprovalID]...)
	delete(s.waiters, record.ApprovalID)
	for _, ch := range waiters {
		select {
		case ch <- record:
		default:
		}
		close(ch)
	}
}

func (s *sqliteApprovalStore) scheduleExpirationLocked(approval types.ApprovalRecord) {
	if approval.Status != types.ApprovalPending {
		return
	}
	if existing := s.timers[approval.ApprovalID]; existing != nil {
		existing.Stop()
	}
	delay := time.Until(approval.ExpiresAt)
	if delay < 0 {
		delay = 0
	}
	s.timers[approval.ApprovalID] = time.AfterFunc(delay, func() {
		s.expireInBackground(approval.ApprovalID)
	})
}

func (s *sqliteApprovalStore) expireInBackground(approvalID string) {
	if _, err := s.expirePending(context.Background(), approvalID, time.Now().UTC()); err != nil {
		s.rescheduleExpirationRetry(approvalID, approvalExpirationRetryDelay)
		var coreErr *Error
		if errors.As(err, &coreErr) && coreErr.Code == "approval_not_found" {
			return
		}
		log.Printf("expire approval %s: %v", approvalID, err)
	}
}

func (s *sqliteApprovalStore) rescheduleExpirationRetry(approvalID string, delay time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.approvals[approvalID]
	if !ok || record.Status != types.ApprovalPending {
		delete(s.timers, approvalID)
		return
	}
	if existing := s.timers[approvalID]; existing != nil {
		existing.Stop()
	}
	if delay < 0 {
		delay = 0
	}
	s.timers[approvalID] = time.AfterFunc(delay, func() {
		s.expireInBackground(approvalID)
	})
}

func (s *sqliteApprovalStore) expirePending(ctx context.Context, approvalID string, expiredAt time.Time) (types.ApprovalRecord, error) {
	record, found, err := s.currentRecord(ctx, approvalID)
	if err != nil {
		return types.ApprovalRecord{}, err
	}
	if !found {
		return types.ApprovalRecord{}, errStatus(http.StatusNotFound, "approval_not_found", "approval was not found")
	}
	if record.Status != types.ApprovalPending {
		return record, nil
	}
	return s.Expire(ctx, approvalID, expiredAt, s.approvalExpiredEvent(record, expiredAt))
}

func (s *sqliteApprovalStore) approvalExpiredEvent(approval types.ApprovalRecord, occurredAt time.Time) types.EventEnvelope {
	approvalCtx := s.approvalContext(approval.ApprovalID)
	metadata := map[string]interface{}{
		"approval_id": approval.ApprovalID,
		"channel":     approval.Channel,
		"task_id":     approval.TaskID,
		"attempt_id":  approval.AttemptID,
	}
	if approvalCtx.requestKind != "" {
		metadata["request_kind"] = approvalCtx.requestKind
	}
	return types.EventEnvelope{
		EventID:    newID("evt_approval"),
		EventType:  "approval_expired",
		RequestID:  approval.RequestID,
		SessionID:  approval.SessionID,
		Surface:    approvalCtx.surface,
		Effect:     types.EffectDeny,
		Summary:    "approval_expired",
		Metadata:   metadata,
		OccurredAt: occurredAt,
	}
}

func (s *sqliteApprovalStore) approvalContext(approvalID string) approvalEventContext {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.contexts[approvalID]
}

func approvalEventContextFromEvent(event types.EventEnvelope) approvalEventContext {
	ctx := approvalEventContext{surface: event.Surface}
	switch value := event.Metadata["request_kind"].(type) {
	case string:
		ctx.requestKind = types.RequestKind(value)
	case types.RequestKind:
		ctx.requestKind = value
	}
	return ctx
}

func (s *sqliteApprovalStore) loadApprovalEventContexts(ctx context.Context, approvals []types.ApprovalRecord) (map[string]approvalEventContext, error) {
	contexts := make(map[string]approvalEventContext, len(approvals))
	if s.eventStore == nil || len(approvals) == 0 {
		return contexts, nil
	}

	pendingIDs := make(map[string]struct{}, len(approvals))
	for _, approval := range approvals {
		if approval.Status == types.ApprovalPending {
			pendingIDs[approval.ApprovalID] = struct{}{}
		}
	}
	if len(pendingIDs) == 0 {
		return contexts, nil
	}

	events, err := s.eventStore.ListEvents(ctx, 1000000)
	if err != nil {
		return nil, err
	}
	for _, event := range events {
		if event.EventType != "approval_requested" {
			continue
		}
		approvalID, _ := event.Metadata["approval_id"].(string)
		if _, ok := pendingIDs[approvalID]; !ok {
			continue
		}
		contexts[approvalID] = approvalEventContextFromEvent(event)
	}
	return contexts, nil
}

func (s *sqliteApprovalStore) addWaiter(approvalID string, ch chan types.ApprovalRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.waiters[approvalID] = append(s.waiters[approvalID], ch)
}

func (s *sqliteApprovalStore) removeWaiter(approvalID string, ch chan types.ApprovalRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	waiters := s.waiters[approvalID]
	for idx, waiter := range waiters {
		if waiter != ch {
			continue
		}
		s.waiters[approvalID] = append(waiters[:idx], waiters[idx+1:]...)
		if len(s.waiters[approvalID]) == 0 {
			delete(s.waiters, approvalID)
		}
		return
	}
}

func attemptKey(sessionID string, taskID string, attemptID string) string {
	return fmt.Sprintf("%s:%s:%s", sessionID, taskID, attemptID)
}
