package core

import (
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

	dec, err := engine.Decide(types.PolicyRequest{
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
	if dec.Effect != types.EffectDeny {
		t.Fatalf("initial effect = %q, want deny", dec.Effect)
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

	publishResp, err := engine.PublishPolicy(PolicyPublishRequest{
		Bundle:     bundle2,
		OperatorID: "admin",
		Message:    "auditing bash",
	})
	if err != nil {
		t.Fatalf("publish policy: %v", err)
	}

	dec2, err := engine.Decide(types.PolicyRequest{
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
	if dec2.Effect != types.EffectAllowWithAudit {
		t.Fatalf("effect after publish = %q, want allow_with_audit", dec2.Effect)
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
	stateStore.SavePolicyVersionAtomic(v1, "admin", "v1", 0, time.Now(), types.EventEnvelope{})

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
	if _, err := engine.PublishPolicy(PolicyPublishRequest{Bundle: v2, OperatorID: "admin"}); err != nil {
		t.Fatalf("publish policy: %v", err)
	}

	rolledBack, err := engine.RollbackPolicy(PolicyRollbackRequest{
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

	decision, err := engine.Decide(types.PolicyRequest{
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
	if decision.Effect != types.EffectAllow {
		t.Fatalf("effect after rollback = %q, want allow", decision.Effect)
	}
}

func TestPolicyDecisionEventIncludesPolicyTraceMetadata(t *testing.T) {
	engine := NewEngine()

	_, err := engine.Decide(types.PolicyRequest{
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

	events, err := engine.Events(10)
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
