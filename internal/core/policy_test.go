package core

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/agentgate/agentgate/internal/policy"
	"github.com/agentgate/agentgate/internal/types"
)

func TestPublishPolicyValidatesAndAffectsDecisions(t *testing.T) {
	// Use an engine with an explicit restrictive initial policy to test change.
	bundle := coreTestBundle([]policy.Rule{
		{
			ID:           "runtime.bash.deny",
			Priority:     200,
			Surface:      types.SurfaceRuntime,
			RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
			Effect:       types.EffectDeny,
			ReasonCode:   "runtime_bash_denied",
			When:         policy.Condition{Language: "cel", Expression: `action.tool == "bash"`},
		},
	})
	engine := NewEngine(WithPolicyBundle(bundle))

	dec, err := engine.Decide(context.Background(), types.PolicyRequest{
		RequestID:   "req_1",
		RequestKind: types.RequestKindToolAttempt,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Session:     types.SessionContext{SessionID: "sess_1", TaskID: "task_1"},
		Action:      types.ActionContext{Tool: "bash", Operation: "execute"},
		Target:      types.TargetContext{Kind: "process", Identifier: "shell"},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if dec.Disposition != types.DispositionDeny {
		t.Fatalf("initial disposition = %q, want deny", dec.Disposition)
	}

	// Publish a more restrictive policy with audit.
	bundle2 := coreTestBundle([]policy.Rule{
		{
			ID:           "runtime.bash.audit",
			Priority:     300,
			Surface:      types.SurfaceRuntime,
			RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
			Effect:       types.EffectAllowWithAudit,
			ReasonCode:   "runtime_bash_audited",
			When:         policy.Condition{Language: "cel", Expression: `action.tool == "bash"`},
		},
	})

	publishResp, err := engine.PublishPolicy(context.Background(), PolicyPublishRequest{
		Bundle:     bundle2,
		OperatorID: "admin",
		Message:    "auditing bash",
	})
	if err != nil {
		t.Fatalf("publish policy: %v", err)
	}

	dec2, err := engine.Decide(context.Background(), types.PolicyRequest{
		RequestID:   "req_2",
		RequestKind: types.RequestKindToolAttempt,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Session:     types.SessionContext{SessionID: "sess_1", TaskID: "task_1"},
		Action:      types.ActionContext{Tool: "bash", Operation: "execute"},
		Target:      types.TargetContext{Kind: "process", Identifier: "shell"},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	})
	if err != nil {
		t.Fatalf("decide 2: %v", err)
	}
	if dec2.Disposition != types.DispositionAllow {
		t.Fatalf("disposition after publish = %q, want allow", dec2.Disposition)
	}
	if dec2.Explanation.PolicyTrace.PolicyVersion != publishResp.Record.Version {
		t.Fatalf("policy version = %d, want %d", dec2.Explanation.PolicyTrace.PolicyVersion, publishResp.Record.Version)
	}
}

func TestRollbackPolicyCreatesNewActiveVersion(t *testing.T) {
	stateStore := newMemoryStateStore()
	engine := NewEngine(WithStateStore(stateStore))

	// Seed version 1 in store.
	v1 := coreTestBundle([]policy.Rule{
		{
			ID:           "allow.bash",
			Priority:     1,
			Surface:      types.SurfaceRuntime,
			RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
			Effect:       types.EffectAllow,
			ReasonCode:   "allow_bash",
			When:         policy.Condition{Language: "cel", Expression: `action.tool == "bash"`},
		},
	})
	v1.Version = 1
	stateStore.SavePolicyVersionAtomic(context.Background(), v1, "admin", "v1", 0, time.Now(), types.EventEnvelope{})

	// Publish version 2.
	v2 := coreTestBundle([]policy.Rule{
		{
			ID:           "runtime.bash.deny",
			Priority:     200,
			Surface:      types.SurfaceRuntime,
			RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
			Effect:       types.EffectDeny,
			ReasonCode:   "runtime_bash_denied",
			When:         policy.Condition{Language: "cel", Expression: `action.tool == "bash"`},
		},
	})
	if _, err := engine.PublishPolicy(context.Background(), PolicyPublishRequest{Bundle: v2, OperatorID: "admin"}); err != nil {
		t.Fatalf("publish policy: %v", err)
	}

	rolledBack, err := engine.RollbackPolicy(context.Background(), PolicyRollbackRequest{
		Version:    1,
		OperatorID: "admin",
	})
	if err != nil {
		t.Fatalf("rollback policy: %v", err)
	}
	// version 1: seeded, version 2: published, version 3: rollback to 1
	if rolledBack.Record.Version != 3 || rolledBack.Record.SourceVersion != 1 {
		t.Fatalf("unexpected rollback record: %#v", rolledBack.Record)
	}

	decision, err := engine.Decide(context.Background(), types.PolicyRequest{
		RequestID:   "req_after_rollback",
		RequestKind: types.RequestKindToolAttempt,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Session:     types.SessionContext{SessionID: "sess_1", TaskID: "task_1"},
		Action:      types.ActionContext{Tool: "bash", Operation: "execute"},
		Target:      types.TargetContext{Kind: "process", Identifier: "shell"},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	// Version 1 allows bash (by omission of restrictive rules in coreTestBundle if only one rule is added).
	// Actually coreTestBundle has default deny if rules are empty? No, aggregateBundles adds DefaultBundle rules if empty.
	if decision.Disposition != types.DispositionAllow {
		t.Fatalf("disposition after rollback = %q, want allow", decision.Disposition)
	}
}

func TestPolicyDecisionEventIncludesPolicyTraceMetadata(t *testing.T) {
	engine := NewEngine(WithPolicyBundle(coreTestBundle([]policy.Rule{
		{
			ID:           "runtime.exec.audit",
			Priority:     300,
			Surface:      types.SurfaceRuntime,
			RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
			Effect:       types.EffectAllowWithAudit,
			ReasonCode:   "runtime_bash_audited",
			When:         policy.Condition{Language: "cel", Expression: `action.tool == "bash"`},
		},
	})))

	_, err := engine.Decide(context.Background(), types.PolicyRequest{
		RequestID:   "req_trace",
		RequestKind: types.RequestKindToolAttempt,
		Actor:       types.ActorContext{UserID: "u1"},
		Session:     types.SessionContext{SessionID: "sess_1", TaskID: "task_1", AttemptID: "att_1"},
		Action:      types.ActionContext{Tool: "bash", Operation: "execute"},
		Target:      types.TargetContext{Kind: "process", Identifier: "shell"},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}

	events, err := engine.Events(context.Background(), 10)
	if err != nil {
		t.Fatalf("events: %v", err)
	}

	var found bool
	for _, event := range events {
		if event.EventType == "policy_decision" && event.RequestID == "req_trace" {
			found = true
			if event.Metadata["policy_version"] == nil {
				t.Error("metadata missing policy_version")
			}
			if event.Metadata["policy_status"] == nil {
				t.Error("metadata missing policy_status")
			}
			if event.Metadata["selected_rule"] == nil {
				t.Error("metadata missing selected_rule")
			}
		}
	}
	if !found {
		t.Fatal("policy decision event not found")
	}
}

func TestIntegrationPolicyBindingOverridesGlobalDefault(t *testing.T) {
	stateStore := newMemoryStateStore()
	globalBundle := coreTestBundle([]policy.Rule{
		{
			ID:           "runtime.bash.deny.global",
			Priority:     50,
			Surface:      types.SurfaceRuntime,
			RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
			Effect:       types.EffectDeny,
			ReasonCode:   "runtime_bash_denied_global",
			When:         policy.Condition{Language: "cel", Expression: `action.tool == "bash"`},
		},
	})
	globalBundle.BundleID = "default"
	engine := NewEngine(WithStateStore(stateStore), WithPolicyBundle(globalBundle))

	tenantBundle := coreTestBundle([]policy.Rule{
		{
			ID:           "runtime.bash.allow.integration",
			Priority:     10,
			Surface:      types.SurfaceRuntime,
			RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
			Effect:       types.EffectAllowWithAudit,
			ReasonCode:   "runtime_bash_allowed_integration",
			When:         policy.Condition{Language: "cel", Expression: `action.tool == "bash"`},
		},
	})
	tenantBundle.BundleID = "bundle-allow-bash"
	tenantBundle.Name = "Tenant allow bash"
	tenantBundle.Status = policy.BundleStatusActive
	if err := stateStore.SavePolicyBundle(context.Background(), tenantBundle); err != nil {
		t.Fatalf("save policy bundle: %v", err)
	}
	if _, err := engine.SaveIntegration(context.Background(), types.IntegrationDefinition{
		ID:               "openclaw-main",
		Name:             "OpenClaw main",
		Kind:             "adapter",
		Enabled:          true,
		AgentType:        types.AgentTypeOpenClaw,
		ExpectedSurfaces: []types.Surface{types.SurfaceInput, types.SurfaceRuntime},
		PolicyBundleIDs:  []string{"bundle-allow-bash"},
	}); err != nil {
		t.Fatalf("save integration: %v", err)
	}

	decision, err := engine.Decide(context.Background(), types.PolicyRequest{
		RequestID:   "req_integration_policy",
		RequestKind: types.RequestKindToolAttempt,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Session:     types.SessionContext{SessionID: "sess_1", TaskID: "task_1", AttemptID: "att_1"},
		Action:      types.ActionContext{Tool: "bash", Operation: "execute"},
		Target:      types.TargetContext{Kind: "process", Identifier: "shell"},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
		Policy:      map[string]interface{}{"integration_id": "openclaw-main"},
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Effect != types.EffectAllowWithAudit {
		t.Fatalf("effect = %q, want allow_with_audit", decision.Effect)
	}
	if decision.ReasonCode != "runtime_bash_allowed_integration" {
		t.Fatalf("reason = %q, want runtime_bash_allowed_integration", decision.ReasonCode)
	}

	events, err := engine.Events(context.Background(), 10)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	for _, event := range events {
		if event.EventType != "policy_decision" || event.RequestID != "req_integration_policy" {
			continue
		}
		if got := event.Metadata["policy_source"]; got != "integration" {
			t.Fatalf("policy_source = %#v, want integration", got)
		}
		rawIDs, err := json.Marshal(event.Metadata["integration_policy_bundles"])
		if err != nil {
			t.Fatalf("marshal integration_policy_bundles: %v", err)
		}
		if string(rawIDs) != `["bundle-allow-bash"]` {
			t.Fatalf("integration_policy_bundles = %s", string(rawIDs))
		}
		return
	}
	t.Fatal("policy decision event not found")
}

func TestIntegrationPolicyBindingFallsBackToGlobalDefaultWhenBundleMissing(t *testing.T) {
	stateStore := newMemoryStateStore()
	globalBundle := coreTestBundle([]policy.Rule{
		{
			ID:           "runtime.bash.deny.global",
			Priority:     50,
			Surface:      types.SurfaceRuntime,
			RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
			Effect:       types.EffectDeny,
			ReasonCode:   "runtime_bash_denied_global",
			When:         policy.Condition{Language: "cel", Expression: `action.tool == "bash"`},
		},
	})
	globalBundle.BundleID = "default"
	engine := NewEngine(WithStateStore(stateStore), WithPolicyBundle(globalBundle))

	if _, err := engine.SaveIntegration(context.Background(), types.IntegrationDefinition{
		ID:               "openclaw-main",
		Name:             "OpenClaw main",
		Kind:             "adapter",
		Enabled:          true,
		AgentType:        types.AgentTypeOpenClaw,
		ExpectedSurfaces: []types.Surface{types.SurfaceInput, types.SurfaceRuntime},
		PolicyBundleIDs:  []string{"missing-bundle"},
	}); err != nil {
		t.Fatalf("save integration: %v", err)
	}

	decision, err := engine.Decide(context.Background(), types.PolicyRequest{
		RequestID:   "req_missing_bundle",
		RequestKind: types.RequestKindToolAttempt,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Session:     types.SessionContext{SessionID: "sess_1", TaskID: "task_1", AttemptID: "att_1"},
		Action:      types.ActionContext{Tool: "bash", Operation: "execute"},
		Target:      types.TargetContext{Kind: "process", Identifier: "shell"},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
		Policy:      map[string]interface{}{"integration_id": "openclaw-main"},
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Effect != types.EffectDeny {
		t.Fatalf("effect = %q, want deny", decision.Effect)
	}
	if decision.ReasonCode != "runtime_bash_denied_global" {
		t.Fatalf("reason = %q, want runtime_bash_denied_global", decision.ReasonCode)
	}
}
