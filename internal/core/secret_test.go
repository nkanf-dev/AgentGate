package core

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/agentgate/agentgate/internal/policy"
	"github.com/agentgate/agentgate/internal/store"
	"github.com/agentgate/agentgate/internal/types"
)

func TestReportRedactsSensitiveMetadata(t *testing.T) {
	engine := NewEngine()

	_, err := engine.Report(context.Background(), types.ReportRequest{
		RequestID:  "req_report",
		DecisionID: "dec_report",
		AdapterID:  "resource-test",
		Surface:    types.SurfaceResource,
		Outcome:    "secret_handle_resolved",
		Obligations: []types.Obligation{
			{
				Type: "resolve_secret_handle",
				Params: map[string]interface{}{
					"secret_value": "sk-test-1234567890abcdef",
				},
			},
		},
		Metadata: map[string]interface{}{
			"secret_value": "sk-test-1234567890abcdef",
			"nested": map[string]interface{}{
				"token": "sk-test-nested-1234567890",
			},
			"message": "using api_key: sk-test-message-1234567890",
		},
	})
	if err != nil {
		t.Fatalf("report: %v", err)
	}

	events, err := engine.Events(context.Background(), 10)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	payload, err := json.Marshal(events)
	if err != nil {
		t.Fatalf("marshal events: %v", err)
	}
	text := string(payload)
	if strings.Contains(text, "sk-test") {
		t.Fatalf("events contain raw secret: %s", text)
	}
	if !strings.Contains(text, "[REDACTED]") {
		t.Fatalf("events do not show redaction marker: %s", text)
	}
}

func TestResourceDecisionDoesNotPersistSecretValueInEvents(t *testing.T) {
	engine := NewEngine()

	decision, err := engine.Decide(context.Background(), types.PolicyRequest{
		RequestID:   "req_input",
		RequestKind: types.RequestKindInput,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Session:     types.SessionContext{SessionID: "sess_1", TaskID: "task_1"},
		Action:      types.ActionContext{Operation: "model_input"},
		Target:      types.TargetContext{Kind: "model_context"},
		Context: types.DecisionContext{
			Surface: types.SurfaceInput,
			Raw: map[string]interface{}{
				"text": "api_key: sk-test-1234567890abcdef1234567890abcdef1234567890abcdef deploy",
			},
		},
	})
	if err != nil {
		t.Fatalf("input decide: %v", err)
	}
	handleID := handleIDFromDecision(t, decision)

	_, err = engine.Decide(context.Background(), types.PolicyRequest{
		RequestID:   "req_resource",
		RequestKind: types.RequestKindResourceAccess,
		Actor:       types.ActorContext{UserID: "u1", HostID: "resource"},
		Session:     types.SessionContext{SessionID: "sess_1", TaskID: "task_1"},
		Action:      types.ActionContext{Operation: "resolve_secret_handle"},
		Target:      types.TargetContext{Kind: "secret_handle", Identifier: handleID},
		Context:     types.DecisionContext{Surface: types.SurfaceResource},
	})
	if err != nil {
		t.Fatalf("resource decide: %v", err)
	}

	events, err := engine.Events(context.Background(), 10)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	payload, err := json.Marshal(events)
	if err != nil {
		t.Fatalf("marshal events: %v", err)
	}
	if strings.Contains(string(payload), "sk-test") {
		t.Fatalf("decision event stream contains raw secret: %s", string(payload))
	}
}

func TestDecisionWithoutSessionFailsClosedBeforeSecretHandleCreation(t *testing.T) {
	engine := NewEngine()

	decision, err := engine.Decide(context.Background(), types.PolicyRequest{
		RequestID:   "req_missing_session",
		RequestKind: types.RequestKindInput,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Action:      types.ActionContext{Operation: "model_input"},
		Target:      types.TargetContext{Kind: "model_context"},
		Context: types.DecisionContext{
			Surface: types.SurfaceInput,
			Raw: map[string]interface{}{
				"text": "api_key: sk-test-1234567890abcdef1234567890abcdef1234567890abcdef",
			},
		},
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Disposition != types.DispositionDeny {
		t.Fatalf("disposition = %q, want deny", decision.Disposition)
	}
}

func TestInputSecretFailsClosedWithoutPolicyRule(t *testing.T) {
	bundle := coreTestBundle([]policy.Rule{
		{
			ID:           "runtime.only",
			Priority:     1,
			Surface:      types.SurfaceRuntime,
			RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
			Effect:       types.EffectAllowWithAudit,
			ReasonCode:   "runtime_only",
			When:         policy.Condition{Language: "cel", Expression: `action.tool == "read"`},
		},
	})
	engine := NewEngine(WithPolicyBundle(bundle))

	decision, err := engine.Decide(context.Background(), types.PolicyRequest{
		RequestID:   "req_secret_without_policy",
		RequestKind: types.RequestKindInput,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Session:     types.SessionContext{SessionID: "sess_1", TaskID: "task_1"},
		Action:      types.ActionContext{Operation: "model_input"},
		Target:      types.TargetContext{Kind: "model_context"},
		Context: types.DecisionContext{
			Surface: types.SurfaceInput,
			Raw: map[string]interface{}{
				"text": "api_key: sk-test-1234567890abcdef1234567890abcdef1234567890abcdef",
			},
		},
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Disposition != types.DispositionDeny {
		t.Fatalf("disposition = %q, want deny", decision.Disposition)
	}
}

func TestHydrateSecretHandlesFromStore(t *testing.T) {
	stateStore, err := store.OpenSQLite(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer stateStore.Close()

	bundle := coreTestBundle([]policy.Rule{
		{
			ID:           "input.secret.rewrite",
			Priority:     100,
			Surface:      types.SurfaceInput,
			RequestKinds: []types.RequestKind{types.RequestKindInput},
			Effect:       types.EffectAllowWithAudit,
			ReasonCode:   "input_secret_rewritten_to_handles",
			Obligations:  []policy.Obligation{{Type: "rewrite_input"}},
			When:         policy.Condition{Language: "cel", Expression: `content.data_classes.exists(x, x == "secret")`},
		},
		{
			ID:           "resource.secret.resolve",
			Priority:     100,
			Surface:      types.SurfaceResource,
			RequestKinds: []types.RequestKind{types.RequestKindResourceAccess},
			Effect:       types.EffectAllowWithAudit,
			ReasonCode:   "secret_handle_resolve_allowed",
			Obligations:  []policy.Obligation{{Type: "resolve_secret_handle"}},
			When:         policy.Condition{Language: "cel", Expression: `target.kind == "secret_handle"`},
		},
	})

	engine := NewEngine(WithEventStore(stateStore), WithStateStore(stateStore), WithPolicyBundle(bundle))
	inputDec, err := engine.Decide(context.Background(), types.PolicyRequest{
		RequestID:   "req_hydrate_input",
		RequestKind: types.RequestKindInput,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Session:     types.SessionContext{SessionID: "sess_hydrate", TaskID: "task_1"},
		Action:      types.ActionContext{Operation: "model_input"},
		Target:      types.TargetContext{Kind: "model_context"},
		Context: types.DecisionContext{
			Surface: types.SurfaceInput,
			Raw:     map[string]interface{}{"text": "api_key: sk-hydrate-test-1234567890abcdef1234567890abcdef1234567890abcdef"},
		},
	})
	if err != nil {
		t.Fatalf("input decide: %v", err)
	}
	handleID := handleIDFromDecision(t, inputDec)

	restartedEngine := NewEngine(WithEventStore(stateStore), WithStateStore(stateStore), WithPolicyBundle(bundle))
	handles, _ := testVault(restartedEngine).Snapshot(context.Background())
	_, inMemory := handles[handleID]
	if !inMemory {
		t.Fatal("secret handle should be hydrated into memory after restart")
	}

	resourceDecision, err := restartedEngine.Decide(context.Background(), types.PolicyRequest{
		RequestID:   "req_hydrate_resource",
		RequestKind: types.RequestKindResourceAccess,
		Actor:       types.ActorContext{UserID: "u1", HostID: "resource"},
		Session:     types.SessionContext{SessionID: "sess_hydrate", TaskID: "task_1"},
		Action:      types.ActionContext{Operation: "resolve_secret_handle"},
		Target:      types.TargetContext{Kind: "secret_handle", Identifier: handleID},
		Context:     types.DecisionContext{Surface: types.SurfaceResource},
	})
	if err != nil {
		t.Fatalf("resource decide after restart: %v", err)
	}
	if resourceDecision.Disposition != types.DispositionAllow {
		t.Fatalf("resource disposition = %q, want allow", resourceDecision.Disposition)
	}
}

func TestSecretHandleExpiresAt(t *testing.T) {
	bundle := coreTestBundle([]policy.Rule{
		{
			ID:           "input.secret.rewrite",
			Priority:     100,
			Surface:      types.SurfaceInput,
			RequestKinds: []types.RequestKind{types.RequestKindInput},
			Effect:       types.EffectAllowWithAudit,
			ReasonCode:   "input_secret_rewritten_to_handles",
			Obligations:  []policy.Obligation{{Type: "rewrite_input"}},
			When:         policy.Condition{Language: "cel", Expression: `content.data_classes.exists(x, x == "secret")`},
		},
		{
			ID:           "resource.secret.resolve",
			Priority:     100,
			Surface:      types.SurfaceResource,
			RequestKinds: []types.RequestKind{types.RequestKindResourceAccess},
			Effect:       types.EffectAllowWithAudit,
			ReasonCode:   "secret_handle_resolve_allowed",
			Obligations:  []policy.Obligation{{Type: "resolve_secret_handle"}},
			When:         policy.Condition{Language: "cel", Expression: `target.kind == "secret_handle"`},
		},
	})
	engine := NewEngine(WithPolicyBundle(bundle))

	inputDec, err := engine.Decide(context.Background(), types.PolicyRequest{
		RequestID:   "req_input_expire",
		RequestKind: types.RequestKindInput,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Session:     types.SessionContext{SessionID: "sess_expire", TaskID: "task_1"},
		Action:      types.ActionContext{Operation: "model_input"},
		Target:      types.TargetContext{Kind: "model_context"},
		Context: types.DecisionContext{
			Surface: types.SurfaceInput,
			Raw:     map[string]interface{}{"text": "api_key: sk-test-expire-1234567890abcdef1234567890abcdef1234567890abcdef"},
		},
	})
	if err != nil {
		t.Fatalf("input decide: %v", err)
	}
	handleID := handleIDFromDecision(t, inputDec)

	handles, values := testVault(engine).Snapshot(context.Background())
	expired := handles[handleID]
	expired.ExpiresAt = time.Now().Add(-1 * time.Minute)
	testVault(engine).OverrideHandle(context.Background(), expired, values[handleID])

	resolveDec, err := engine.Decide(context.Background(), types.PolicyRequest{
		RequestID:   "req_expire_resolve",
		RequestKind: types.RequestKindResourceAccess,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Session:     types.SessionContext{SessionID: "sess_expire", TaskID: "task_1"},
		Action:      types.ActionContext{Operation: "resolve_secret_handle"},
		Target:      types.TargetContext{Kind: "secret_handle", Identifier: handleID},
		Context:     types.DecisionContext{Surface: types.SurfaceResource},
	})
	if err != nil {
		t.Fatalf("resolve decide: %v", err)
	}
	if resolveDec.Disposition != types.DispositionDeny {
		t.Fatalf("expired resolve disposition = %q, want deny", resolveDec.Disposition)
	}
	if resolveDec.ReasonCode != "secret_handle_expired" {
		t.Fatalf("expired resolve reason = %q, want secret_handle_expired", resolveDec.ReasonCode)
	}
}

func TestDecideInputPathWithoutSecrets(t *testing.T) {
	bundle := coreTestBundle([]policy.Rule{
		{
			ID:           "allow.all",
			Priority:     1,
			Surface:      types.SurfaceInput,
			RequestKinds: []types.RequestKind{types.RequestKindInput},
			Effect:       types.EffectAllow,
			ReasonCode:   "allow_all",
			When:         policy.Condition{Language: "cel", Expression: `true`},
		},
	})
	engine := NewEngine(WithPolicyBundle(bundle))
	req := types.PolicyRequest{
		RequestID:   "req_input_clean",
		RequestKind: types.RequestKindInput,
		Actor:       types.ActorContext{UserID: "u1"},
		Session:     types.SessionContext{SessionID: "sess_1", TaskID: "task_1"},
		Action:      types.ActionContext{Operation: "model_input"},
		Target:      types.TargetContext{Kind: "model_context"},
		Context: types.DecisionContext{
			Surface: types.SurfaceInput,
			Raw:     map[string]interface{}{"text": "hello world, no secrets here"},
		},
	}

	dec, err := engine.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if dec.Disposition != types.DispositionAllow {
		t.Fatalf("disposition = %q, want allow", dec.Disposition)
	}
}
