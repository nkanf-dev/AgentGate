package core

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/agentgate/agentgate/internal/types"
)

type ApprovalStore interface {
	Create(ctx context.Context, approval types.ApprovalRecord) error
	Resolve(ctx context.Context, command types.ApprovalResolveCommand, event types.EventEnvelope) (types.ApprovalResolveResult, error)
	FindPending(ctx context.Context, sessionID, taskID, attemptID string, now time.Time) (*types.ApprovalRecord, error)
	ValidGrant(ctx context.Context, session types.SessionContext, now time.Time) (types.AttemptGrant, bool, error)
	Hydrate(ctx context.Context) error
	List(ctx context.Context, limit int) ([]types.ApprovalRecord, error)
}

type sqliteApprovalStore struct {
	stateStore StateStore

	mu        sync.RWMutex
	approvals map[string]types.ApprovalRecord // 只缓存 pending 状态
	grants    map[string]types.AttemptGrant   // key = attemptKey
}

func newApprovalStore(stateStore StateStore) ApprovalStore {
	return &sqliteApprovalStore{
		stateStore: stateStore,
		approvals:  make(map[string]types.ApprovalRecord),
		grants:     make(map[string]types.AttemptGrant),
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
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range records {
		if record.Status == types.ApprovalPending {
			s.approvals[record.ApprovalID] = record
		}
	}
	for _, grant := range grants {
		s.grants[attemptKey(grant.SessionID, grant.TaskID, grant.AttemptID)] = grant.Grant
	}
	return nil
}

func (s *sqliteApprovalStore) Create(ctx context.Context, approval types.ApprovalRecord) error {
	if s.stateStore != nil {
		if err := s.stateStore.SaveApproval(ctx, approval); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.approvals[approval.ApprovalID] = approval
	s.mu.Unlock()
	return nil
}

func (s *sqliteApprovalStore) Resolve(ctx context.Context, command types.ApprovalResolveCommand, event types.EventEnvelope) (types.ApprovalResolveResult, error) {
	if s.stateStore != nil {
		result, err := s.stateStore.ResolveApprovalAtomic(ctx, command, event)
		if err != nil {
			return types.ApprovalResolveResult{}, err
		}
		s.mu.Lock()
		delete(s.approvals, result.Approval.ApprovalID) // 从 pending 移除
		if result.Grant != nil {
			key := attemptKey(result.Approval.SessionID, result.Approval.TaskID, result.Approval.AttemptID)
			s.grants[key] = *result.Grant
		}
		s.mu.Unlock()
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
		delete(s.approvals, record.ApprovalID)
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
	delete(s.approvals, record.ApprovalID) // 移出 pending
	result := types.ApprovalResolveResult{Approval: record}
	if record.Status == types.ApprovalApproved {
		grant := types.AttemptGrant{ApprovalID: record.ApprovalID, ExpiresAt: record.ExpiresAt}
		s.grants[attemptKey(record.SessionID, record.TaskID, record.AttemptID)] = grant
		result.Grant = &grant
	}
	return result, nil
}

func (s *sqliteApprovalStore) FindPending(ctx context.Context, sessionID, taskID, attemptID string, now time.Time) (*types.ApprovalRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, approval := range s.approvals {
		if !approval.ExpiresAt.After(now) {
			delete(s.approvals, id)
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
		// Note: we don't auto-expire in DB during List for performance,
		// but the UI/API should handle display.
		return s.stateStore.ListApprovals(ctx, limit)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var results []types.ApprovalRecord
	for id, a := range s.approvals {
		if !a.ExpiresAt.After(time.Now().UTC()) {
			a.Status = types.ApprovalExpired
			delete(s.approvals, id)
		}
		results = append(results, a)
	}
	return results, nil
}

func (s *sqliteApprovalStore) OverrideApproval(ctx context.Context, approval types.ApprovalRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if approval.Status == types.ApprovalPending {
		s.approvals[approval.ApprovalID] = approval
	} else {
		delete(s.approvals, approval.ApprovalID)
	}
}

func (s *sqliteApprovalStore) SnapshotApprovals(ctx context.Context) map[string]types.ApprovalRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copy := make(map[string]types.ApprovalRecord, len(s.approvals))
	for k, v := range s.approvals {
		copy[k] = v
	}
	return copy
}

func (s *sqliteApprovalStore) SnapshotGrants(ctx context.Context) map[string]types.AttemptGrant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copy := make(map[string]types.AttemptGrant, len(s.grants))
	for k, v := range s.grants {
		copy[k] = v
	}
	return copy
}

func attemptKey(sessionID string, taskID string, attemptID string) string {
	return fmt.Sprintf("%s:%s:%s", sessionID, taskID, attemptID)
}
