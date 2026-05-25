package core

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/agentgate/agentgate/internal/policy"
	"github.com/agentgate/agentgate/internal/store"
	"github.com/agentgate/agentgate/internal/types"
)

func TestResolveExpiredApprovalReturnsConflict(t *testing.T) {
	engine := NewEngine()
	now := time.Now().UTC()
	testApprovals(engine).OverrideApproval(context.Background(), types.ApprovalRecord{
		ApprovalID: "appr_expired",
		RequestID:  "req_1",
		SessionID:  "sess_1",
		TaskID:     "task_1",
		AttemptID:  "att_1",
		Status:     types.ApprovalPending,
		Reason:     "runtime_high_risk_requires_approval",
		CreatedAt:  now.Add(-2 * time.Minute),
		ExpiresAt:  now.Add(-time.Minute),
	})

	_, err := engine.ResolveApproval(context.Background(), "appr_expired", types.ApprovalResolveRequest{
		Decision:   "allow_once",
		OperatorID: "operator_1",
		Channel:    "test",
	})
	if err == nil {
		t.Fatal("expected expired approval error")
	}
	var coreErr *Error
	if !errors.As(err, &coreErr) || coreErr.Code != "approval_expired" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHydrateAttemptGrantsFromStore(t *testing.T) {
	stateStore, err := store.OpenSQLite(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer stateStore.Close()

	now := time.Now().UTC()
	if err := stateStore.SaveAttemptGrant(context.Background(), "sess_g", "task_g", "attempt_g", "appr_g", now.Add(10*time.Minute)); err != nil {
		t.Fatalf("save grant: %v", err)
	}

	engine := NewEngine(WithEventStore(stateStore), WithStateStore(stateStore))
	key := "sess_g:task_g:attempt_g"
	grant, ok := testApprovals(engine).SnapshotGrants(context.Background())[key]
	if !ok {
		t.Fatal("attempt grant should be hydrated into memory")
	}
	if grant.ApprovalID != "appr_g" {
		t.Fatalf("grant approval_id = %q, want appr_g", grant.ApprovalID)
	}

	dec, err := engine.Decide(context.Background(), types.PolicyRequest{
		RequestID:   "req_g",
		RequestKind: types.RequestKindToolAttempt,
		Session:     types.SessionContext{SessionID: "sess_g", TaskID: "task_g", AttemptID: "attempt_g"},
		Action:      types.ActionContext{Tool: "bash", Operation: "execute"},
		Target:      types.TargetContext{Kind: "process", Identifier: "shell"},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if dec.Disposition != types.DispositionAllow || dec.ReasonCode != "user_allow_once_valid" {
		t.Fatalf("disposition = %q, reason = %q", dec.Disposition, dec.ReasonCode)
	}
}

func TestResolveApprovalAtomicFailureLeavesNoGhostState(t *testing.T) {
	stateStore, err := store.OpenSQLite(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer stateStore.Close()

	failing := &failingStateStore{StateStore: stateStore, failResolve: true}
	now := time.Now().UTC()
	approval := types.ApprovalRecord{
		ApprovalID: "appr_order",
		RequestID:  "req_1",
		SessionID:  "sess_order",
		TaskID:     "task_1",
		AttemptID:  "attempt_1",
		Status:     types.ApprovalPending,
		Reason:     "test",
		CreatedAt:  now,
		ExpiresAt:  now.Add(10 * time.Minute),
	}
	if err := stateStore.SaveApproval(context.Background(), approval); err != nil {
		t.Fatalf("save approval: %v", err)
	}

	engine := NewEngine(WithEventStore(failing), WithStateStore(failing))
	_, err = engine.ResolveApproval(context.Background(), "appr_order", types.ApprovalResolveRequest{
		Decision:   "approve",
		OperatorID: "op_1",
	})
	if err == nil {
		t.Fatal("expected error from resolve when store fails")
	}

	stored := testApprovals(engine).SnapshotApprovals(context.Background())["appr_order"]
	if stored.Status != types.ApprovalPending {
		t.Fatalf("memory approval status = %q, want pending", stored.Status)
	}
	if grantCount := len(testApprovals(engine).SnapshotGrants(context.Background())); grantCount != 0 {
		t.Fatalf("memory should have no ghost grants: count=%d", grantCount)
	}
}

func TestHydrateApprovalsFromStore(t *testing.T) {
	stateStore, err := store.OpenSQLite(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer stateStore.Close()

	now := time.Now().UTC()
	approval := types.ApprovalRecord{
		ApprovalID: "appr_hydrate",
		RequestID:  "req_hydrate",
		SessionID:  "sess_1",
		TaskID:     "task_1",
		AttemptID:  "attempt_1",
		Status:     types.ApprovalPending,
		Reason:     "high risk",
		CreatedAt:  now,
		ExpiresAt:  now.Add(10 * time.Minute),
	}
	if err := stateStore.SaveApproval(context.Background(), approval); err != nil {
		t.Fatalf("save approval: %v", err)
	}

	engine := NewEngine(WithEventStore(stateStore), WithStateStore(stateStore))
	if _, inMemory := testApprovals(engine).SnapshotApprovals(context.Background())["appr_hydrate"]; !inMemory {
		t.Fatal("approval should be hydrated into memory")
	}

	resp, err := engine.ResolveApproval(context.Background(), "appr_hydrate", types.ApprovalResolveRequest{
		Decision:   "approve",
		OperatorID: "op_1",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resp.Status != types.ApprovalApproved {
		t.Fatalf("status = %q, want approved", resp.Status)
	}
}

func TestApprovalCreateFailureReturnsErrorAndNoGhostApproval(t *testing.T) {
	stateStore, err := store.OpenSQLite(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer stateStore.Close()

	failing := &failingApprovalStateStore{StateStore: stateStore, failCreate: true}
	engine := NewEngine(WithEventStore(stateStore), WithStateStore(failing), WithPolicyBundle(approvalPolicyBundle("runtime_high_risk_requires_approval", 0)))

	_, err = engine.Decide(context.Background(), approvalRequest("req_appr_order", "att_1"))
	if err == nil {
		t.Fatal("expected approval create failure")
	}
	var coreErr *Error
	if !errors.As(err, &coreErr) || coreErr.Code != "approval_store_write_failed" {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(testApprovals(engine).SnapshotApprovals(context.Background())) != 0 {
		t.Fatal("memory should have no ghost approvals")
	}
}

func TestApprovalWorkflowCreatesGrantAndScopesByAttempt(t *testing.T) {
	engine := NewEngine(WithPolicyBundle(approvalPolicyBundle("runtime_high_risk_requires_approval", 0)))
	req := approvalRequest("req_1", "att_1")

	firstResult := make(chan types.PolicyDecision, 1)
	firstErr := make(chan error, 1)
	go func() {
		dec, err := engine.Decide(context.Background(), req)
		if err != nil {
			firstErr <- err
			return
		}
		firstResult <- dec
	}()

	approvalID := waitForPendingApprovalID(t, engine)
	if _, err := engine.ResolveApproval(context.Background(), approvalID, types.ApprovalResolveRequest{Decision: "approve", OperatorID: "op_1"}); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	select {
	case err := <-firstErr:
		t.Fatalf("first decide: %v", err)
	case dec := <-firstResult:
		if dec.Disposition != types.DispositionAllow || dec.ReasonCode != "user_allow_once_valid" {
			t.Fatalf("first disposition = %q reason = %q", dec.Disposition, dec.ReasonCode)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first decision")
	}

	secondDec, err := engine.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("second decide: %v", err)
	}
	if secondDec.Disposition != types.DispositionAllow || secondDec.ReasonCode != "user_allow_once_valid" {
		t.Fatalf("second disposition = %q reason = %q", secondDec.Disposition, secondDec.ReasonCode)
	}

	diffReq := approvalRequest("req_2", "att_2")
	thirdResult := make(chan types.PolicyDecision, 1)
	thirdErr := make(chan error, 1)
	go func() {
		dec, err := engine.Decide(context.Background(), diffReq)
		if err != nil {
			thirdErr <- err
			return
		}
		thirdResult <- dec
	}()

	nextApprovalID := waitForPendingApprovalID(t, engine)
	if nextApprovalID == approvalID {
		t.Fatal("different attempt should create a new approval")
	}
	if _, err := engine.ResolveApproval(context.Background(), nextApprovalID, types.ApprovalResolveRequest{Decision: "deny", OperatorID: "op_2"}); err != nil {
		t.Fatalf("resolve second approval: %v", err)
	}
	select {
	case err := <-thirdErr:
		t.Fatalf("third decide: %v", err)
	case dec := <-thirdResult:
		if dec.Disposition != types.DispositionDeny || dec.ReasonCode != "approval_denied" {
			t.Fatalf("third disposition = %q reason = %q", dec.Disposition, dec.ReasonCode)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for third decision")
	}
}

func TestGrantPreCheckBypassesPolicy(t *testing.T) {
	engine := NewEngine(WithPolicyBundle(coreTestBundle([]policy.Rule{
		{
			ID:           "runtime.bash.deny",
			Priority:     200,
			Surface:      types.SurfaceRuntime,
			RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
			Effect:       types.EffectDeny,
			ReasonCode:   "runtime_bash_denied",
			When:         policy.Condition{Language: "cel", Expression: `action.tool == "bash"`},
		},
	})))

	req := approvalRequest("req_1", "att_1")
	dec1, err := engine.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("decide 1: %v", err)
	}
	if dec1.Disposition != types.DispositionDeny {
		t.Fatalf("initial disposition = %q, want deny", dec1.Disposition)
	}

	approval := types.ApprovalRecord{
		ApprovalID: "appr_bypass",
		Status:     types.ApprovalPending,
		SessionID:  "sess_1",
		TaskID:     "task_1",
		AttemptID:  "att_1",
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}
	if err := testApprovals(engine).Create(context.Background(), approval, types.EventEnvelope{}); err != nil {
		t.Fatalf("create approval: %v", err)
	}
	if _, err := testApprovals(engine).Resolve(context.Background(), types.ApprovalResolveCommand{
		ApprovalID: "appr_bypass",
		Decision:   "approve",
		ResolvedAt: time.Now(),
	}, types.EventEnvelope{}); err != nil {
		t.Fatalf("resolve approval: %v", err)
	}

	dec2, err := engine.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("decide 2: %v", err)
	}
	if dec2.Disposition != types.DispositionAllow || dec2.ReasonCode != "user_allow_once_valid" {
		t.Fatalf("disposition after grant = %q reason = %q", dec2.Disposition, dec2.ReasonCode)
	}
}

func TestGrantPreCheckOnlyForRuntimeSurface(t *testing.T) {
	engine := NewEngine(WithPolicyBundle(coreTestBundle([]policy.Rule{
		{
			ID:           "input.all.deny",
			Priority:     200,
			Surface:      types.SurfaceInput,
			RequestKinds: []types.RequestKind{types.RequestKindInput},
			Effect:       types.EffectDeny,
			ReasonCode:   "input_denied",
			When:         policy.Condition{Language: "cel", Expression: `true`},
		},
	})))

	if err := testApprovals(engine).Create(context.Background(), types.ApprovalRecord{
		ApprovalID: "appr_input",
		Status:     types.ApprovalPending,
		SessionID:  "sess_1",
		TaskID:     "task_1",
		AttemptID:  "att_1",
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}, types.EventEnvelope{}); err != nil {
		t.Fatalf("create approval: %v", err)
	}
	if _, err := testApprovals(engine).Resolve(context.Background(), types.ApprovalResolveCommand{
		ApprovalID: "appr_input",
		Decision:   "approve",
		ResolvedAt: time.Now(),
	}, types.EventEnvelope{}); err != nil {
		t.Fatalf("resolve approval: %v", err)
	}

	dec, err := engine.Decide(context.Background(), types.PolicyRequest{
		RequestID:   "req_input",
		RequestKind: types.RequestKindInput,
		Actor:       types.ActorContext{UserID: "u1"},
		Session:     types.SessionContext{SessionID: "sess_1", TaskID: "task_1", AttemptID: "att_1"},
		Action:      types.ActionContext{Operation: "model_input"},
		Target:      types.TargetContext{Kind: "model_context"},
		Context:     types.DecisionContext{Surface: types.SurfaceInput, Raw: map[string]interface{}{"text": "hi"}},
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if dec.Disposition != types.DispositionDeny || dec.ReasonCode != "input_denied" {
		t.Fatalf("disposition = %q reason = %q", dec.Disposition, dec.ReasonCode)
	}
}

func TestConcurrentSameAttemptSharesSingleApproval(t *testing.T) {
	engine := NewEngine(WithPolicyBundle(approvalPolicyBundle("runtime_high_risk_requires_approval", 0)))
	req1 := approvalRequest("req_dup_1", "att_1")
	req2 := approvalRequest("req_dup_2", "att_1")

	result1 := make(chan types.PolicyDecision, 1)
	result2 := make(chan types.PolicyDecision, 1)
	errCh := make(chan error, 2)
	go func() {
		dec, err := engine.Decide(context.Background(), req1)
		if err != nil {
			errCh <- err
			return
		}
		result1 <- dec
	}()
	go func() {
		dec, err := engine.Decide(context.Background(), req2)
		if err != nil {
			errCh <- err
			return
		}
		result2 <- dec
	}()

	approvalID := waitForPendingApprovalID(t, engine)
	if len(testApprovals(engine).SnapshotApprovals(context.Background())) != 1 {
		t.Fatal("expected exactly one pending approval")
	}
	if _, err := engine.ResolveApproval(context.Background(), approvalID, types.ApprovalResolveRequest{Decision: "allow_once", OperatorID: "op_1"}); err != nil {
		t.Fatalf("resolve approval: %v", err)
	}

	var first, second types.PolicyDecision
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			t.Fatalf("decide failed: %v", err)
		case dec := <-result1:
			first = dec
		case dec := <-result2:
			second = dec
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for concurrent decisions")
		}
	}
	if approvalIDFromDecision(t, first) != approvalID || approvalIDFromDecision(t, second) != approvalID {
		t.Fatalf("concurrent decisions should share approval %q", approvalID)
	}
}

func TestApprovalTimeoutUsesRuntimePolicy(t *testing.T) {
	engine := NewEngine(WithPolicyBundle(approvalPolicyBundle("runtime_high_risk_requires_approval", 50*time.Millisecond)))
	start := time.Now()
	decision, err := engine.Decide(context.Background(), approvalRequest("req_timeout", "att_1"))
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Disposition != types.DispositionDeny || decision.ReasonCode != "approval_expired" {
		t.Fatalf("disposition = %q reason = %q", decision.Disposition, decision.ReasonCode)
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("unexpected approval timeout duration: %v", elapsed)
	}
	if len(testApprovals(engine).SnapshotApprovals(context.Background())) != 0 {
		t.Fatal("expired approval should no longer remain pending")
	}
}

func TestApprovalReasonUsesPolicyReason(t *testing.T) {
	engine := NewEngine(WithPolicyBundle(approvalPolicyBundle("CUSTOM_REASON_CODE", 0)))
	resultCh := make(chan types.PolicyDecision, 1)
	errCh := make(chan error, 1)
	go func() {
		dec, err := engine.Decide(context.Background(), approvalRequest("req_reason", "att_1"))
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- dec
	}()

	approvalID := waitForPendingApprovalID(t, engine)
	approval := testApprovals(engine).SnapshotApprovals(context.Background())[approvalID]
	if approval.Reason != "CUSTOM_REASON_CODE" {
		t.Fatalf("reason = %q, want CUSTOM_REASON_CODE", approval.Reason)
	}
	if _, err := engine.ResolveApproval(context.Background(), approvalID, types.ApprovalResolveRequest{Decision: "deny", OperatorID: "op_1"}); err != nil {
		t.Fatalf("resolve approval: %v", err)
	}
	select {
	case err := <-errCh:
		t.Fatalf("decide: %v", err)
	case <-resultCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for final decision")
	}
}

type failingApprovalStateStore struct {
	StateStore
	failCreate bool
}

func (s *failingApprovalStateStore) CreateApprovalAtomic(ctx context.Context, approval types.ApprovalRecord, event types.EventEnvelope) error {
	if s.failCreate {
		return fmt.Errorf("simulated db failure")
	}
	return s.StateStore.CreateApprovalAtomic(ctx, approval, event)
}

type failingStateStore struct {
	StateStore
	failResolve bool
}

func (s *failingStateStore) AppendEvent(ctx context.Context, event types.EventEnvelope) error {
	return nil
}
func (s *failingStateStore) ListEvents(ctx context.Context, limit int) ([]types.EventEnvelope, error) {
	return nil, nil
}
func (s *failingStateStore) GetEventByDecisionID(ctx context.Context, id string) (types.EventEnvelope, bool, error) {
	return types.EventEnvelope{}, false, nil
}
func (s *failingStateStore) PruneEvents(ctx context.Context, before time.Time) (int64, error) {
	return 0, nil
}

func (s *failingStateStore) ResolveApprovalAtomic(ctx context.Context, command types.ApprovalResolveCommand, event types.EventEnvelope) (types.ApprovalResolveResult, error) {
	if s.failResolve {
		return types.ApprovalResolveResult{}, fmt.Errorf("simulated db failure")
	}
	return s.StateStore.ResolveApprovalAtomic(ctx, command, event)
}

func approvalPolicyBundle(reasonCode string, timeout time.Duration) policy.Bundle {
	bundle := coreTestBundle([]policy.Rule{
		{
			ID:           "runtime.bash.approval",
			Priority:     100,
			Surface:      types.SurfaceRuntime,
			RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
			Effect:       types.EffectApprovalRequired,
			ReasonCode:   reasonCode,
			Obligations:  []policy.Obligation{{Type: "approval_request"}},
			When:         policy.Condition{Language: "cel", Expression: `action.tool == "bash"`},
		},
	})
	if timeout > 0 {
		bundle.RuntimePolicy.ApprovalTimeout = policy.Duration{Duration: timeout}
	}
	return bundle
}

func approvalRequest(requestID string, attemptID string) types.PolicyRequest {
	return types.PolicyRequest{
		RequestID:   requestID,
		RequestKind: types.RequestKindToolAttempt,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Session:     types.SessionContext{SessionID: "sess_1", TaskID: "task_1", AttemptID: attemptID},
		Action:      types.ActionContext{Tool: "bash", Operation: "execute"},
		Target:      types.TargetContext{Kind: "process", Identifier: "shell"},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	}
}
