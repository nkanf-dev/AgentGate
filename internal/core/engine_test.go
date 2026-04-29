package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/agentgate/agentgate/internal/policy"
	"github.com/agentgate/agentgate/internal/store"
	"github.com/agentgate/agentgate/internal/types"
)

func TestReportRedactsSensitiveMetadata(t *testing.T) {
	engine := NewEngine()

	_, err := engine.Report(types.ReportRequest{
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

	events, err := engine.Events(10)
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
	if !strings.Contains(text, "resolve_secret_handle") {
		t.Fatalf("events should retain obligation type: %s", text)
	}
}

func TestResourceDecisionDoesNotPersistSecretValueInEvents(t *testing.T) {
	engine := NewEngine()

	decision, err := engine.Decide(types.PolicyRequest{
		RequestID:   "req_input",
		RequestKind: types.RequestKindInput,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Session:     types.SessionContext{SessionID: "sess_1", TaskID: "task_1"},
		Action:      types.ActionContext{Operation: "model_input"},
		Target:      types.TargetContext{Kind: "model_context"},
		Context: types.DecisionContext{
			Surface: types.SurfaceInput,
			Raw: map[string]interface{}{
				"text": "api_key: sk-test-1234567890abcdef deploy",
			},
		},
	})
	if err != nil {
		t.Fatalf("input decide: %v", err)
	}
	if decision.Effect != types.EffectAllowWithAudit {
		t.Fatalf("input effect = %q, want allow_with_audit", decision.Effect)
	}
	if decision.Explanation.PolicyTrace.SelectedRule != "input.secret.rewrite_to_handle" {
		t.Fatalf("input selected policy rule = %q", decision.Explanation.PolicyTrace.SelectedRule)
	}
	handleID := handleIDFromDecision(t, decision)

	resourceDecision, err := engine.Decide(types.PolicyRequest{
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
	if resourceDecision.Effect != types.EffectAllowWithAudit {
		t.Fatalf("resource effect = %q, want allow_with_audit", resourceDecision.Effect)
	}
	if resourceDecision.Explanation.PolicyTrace.SelectedRule != "resource.secret_handle.resolve" {
		t.Fatalf("resource selected policy rule = %q", resourceDecision.Explanation.PolicyTrace.SelectedRule)
	}

	events, err := engine.Events(10)
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

	decision, err := engine.Decide(types.PolicyRequest{
		RequestID:   "req_missing_session",
		RequestKind: types.RequestKindInput,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Action:      types.ActionContext{Operation: "model_input"},
		Target:      types.TargetContext{Kind: "model_context"},
		Context: types.DecisionContext{
			Surface: types.SurfaceInput,
			Raw: map[string]interface{}{
				"text": "api_key: sk-test-1234567890abcdef",
			},
		},
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Effect != types.EffectDeny {
		t.Fatalf("effect = %q, want deny", decision.Effect)
	}
	if decision.ReasonCode != "missing_session_id" {
		t.Fatalf("reason = %q, want missing_session_id", decision.ReasonCode)
	}
	if decision.Explanation.PolicyTrace.SelectedRule != "core.request.validation" {
		t.Fatalf("selected rule = %q, want core.request.validation", decision.Explanation.PolicyTrace.SelectedRule)
	}
	if hasObligation(decision.Obligations, "rewrite_input") {
		t.Fatalf("invalid request must not create rewrite obligations: %#v", decision.Obligations)
	}
}

func TestDecisionWithoutTaskFailsClosed(t *testing.T) {
	engine := NewEngine()

	decision, err := engine.Decide(types.PolicyRequest{
		RequestID:   "req_missing_task",
		RequestKind: types.RequestKindResourceAccess,
		Actor:       types.ActorContext{UserID: "u1", HostID: "resource"},
		Session:     types.SessionContext{SessionID: "sess_1"},
		Action:      types.ActionContext{Operation: "resolve_secret_handle"},
		Target:      types.TargetContext{Kind: "secret_handle", Identifier: "sech_test"},
		Context:     types.DecisionContext{Surface: types.SurfaceResource},
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Effect != types.EffectDeny {
		t.Fatalf("effect = %q, want deny", decision.Effect)
	}
	if decision.ReasonCode != "missing_task_id" {
		t.Fatalf("reason = %q, want missing_task_id", decision.ReasonCode)
	}
	if hasObligation(decision.Obligations, "resolve_secret_handle") {
		t.Fatalf("invalid request must not resolve secret handles: %#v", decision.Obligations)
	}
}

func TestRegisterAdapterRejectsDuplicateSurfaces(t *testing.T) {
	engine := NewEngine()

	_, err := engine.RegisterAdapter(types.AdapterRegistration{
		AdapterID:   "dup-surface",
		AdapterKind: "host_plugin",
		Host:        types.HostDescriptor{Kind: "openclaw"},
		Surfaces:    []types.Surface{types.SurfaceInput, types.SurfaceInput},
		Capabilities: types.AdapterCapabilities{
			CanBlock:            true,
			CanRewriteInput:     true,
			CanRewriteToolArgs:  true,
			CanPauseForApproval: true,
		},
	})
	if err == nil {
		t.Fatal("expected duplicate surface error")
	}
	var coreErr *Error
	if !errors.As(err, &coreErr) || coreErr.Code != "invalid_registration" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRegisterAdapterRejectsSurfaceCapabilityMismatch(t *testing.T) {
	engine := NewEngine()

	_, err := engine.RegisterAdapter(types.AdapterRegistration{
		AdapterID:   "input-without-rewrite",
		AdapterKind: "host_plugin",
		Host:        types.HostDescriptor{Kind: "openclaw"},
		Surfaces:    []types.Surface{types.SurfaceInput},
		Capabilities: types.AdapterCapabilities{
			CanBlock: true,
		},
	})
	if err == nil {
		t.Fatal("expected capability mismatch error")
	}
	var coreErr *Error
	if !errors.As(err, &coreErr) || coreErr.Code != "invalid_registration" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRegisterAdapterRejectsDuplicateSupportingChannels(t *testing.T) {
	engine := NewEngine()

	_, err := engine.RegisterAdapter(types.AdapterRegistration{
		AdapterID:          "feishu-transport",
		AdapterKind:        "approval_transport",
		Host:               types.HostDescriptor{Kind: "feishu"},
		SupportingChannels: []string{"approval_transport", "APPROVAL_TRANSPORT"},
	})
	if err == nil {
		t.Fatal("expected duplicate supporting channel error")
	}
	var coreErr *Error
	if !errors.As(err, &coreErr) || coreErr.Code != "invalid_registration" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecisionCoverageUsesStateStoreAfterEngineRestart(t *testing.T) {
	stateStore, err := store.OpenSQLite(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer stateStore.Close()

	firstEngine := NewEngine(WithStateStore(stateStore))
	_, err = firstEngine.RegisterAdapter(types.AdapterRegistration{
		AdapterID:   "openclaw-test",
		AdapterKind: "host_plugin",
		Host:        types.HostDescriptor{Kind: "openclaw"},
		Surfaces:    []types.Surface{types.SurfaceInput},
		Capabilities: types.AdapterCapabilities{
			CanBlock:        true,
			CanRewriteInput: true,
		},
	})
	if err != nil {
		t.Fatalf("register adapter: %v", err)
	}

	restartedEngine := NewEngine(WithStateStore(stateStore))
	decision, err := restartedEngine.Decide(types.PolicyRequest{
		RequestID:   "req_after_restart",
		RequestKind: types.RequestKindInput,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Session:     types.SessionContext{SessionID: "sess_1", TaskID: "task_1"},
		Action:      types.ActionContext{Operation: "model_input"},
		Target:      types.TargetContext{Kind: "model_context"},
		Context:     types.DecisionContext{Surface: types.SurfaceInput, Raw: map[string]interface{}{"text": "hello"}},
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	for _, warning := range decision.Explanation.Warnings {
		if strings.Contains(warning, "no adapter registration") {
			t.Fatalf("decision should use persisted coverage, got warnings %#v", decision.Explanation.Warnings)
		}
	}
}

func TestIntegrationHealthMatchesByIntegrationIDOnly(t *testing.T) {
	engine := NewEngine()

	definition, err := engine.SaveIntegration(types.IntegrationDefinition{
		ID:               "openclaw-main",
		Name:             "OpenClaw main adapter",
		Kind:             "adapter",
		Enabled:          true,
		ExpectedSurfaces: []types.Surface{types.SurfaceInput, types.SurfaceRuntime},
	})
	if err != nil {
		t.Fatalf("save integration: %v", err)
	}
	if definition.Health.Status != types.IntegrationHealthMissing {
		t.Fatalf("new integration status = %q, want missing", definition.Health.Status)
	}

	_, err = engine.RegisterAdapter(types.AdapterRegistration{
		AdapterID:   "openclaw-main",
		AdapterKind: "host_plugin",
		Host:        types.HostDescriptor{Kind: "openclaw"},
		Surfaces:    []types.Surface{types.SurfaceInput},
		Capabilities: types.AdapterCapabilities{
			CanBlock:        true,
			CanRewriteInput: true,
		},
	})
	if err != nil {
		t.Fatalf("register adapter without integration_id: %v", err)
	}

	result, err := engine.GetIntegration("openclaw-main")
	if err != nil {
		t.Fatalf("get integration: %v", err)
	}
	if result.Health.Status != types.IntegrationHealthMissing {
		t.Fatalf("adapter_id fallback should not match, got status %q", result.Health.Status)
	}
	if len(result.MatchedAdapters) != 0 {
		t.Fatalf("expected no fallback matches, got %#v", result.MatchedAdapters)
	}

	_, err = engine.RegisterAdapter(types.AdapterRegistration{
		AdapterID:     "openclaw-main-01",
		IntegrationID: "openclaw-main",
		AdapterKind:   "host_plugin",
		Host:          types.HostDescriptor{Kind: "openclaw"},
		Surfaces:      []types.Surface{types.SurfaceInput, types.SurfaceRuntime},
		Capabilities: types.AdapterCapabilities{
			CanBlock:            true,
			CanRewriteInput:     true,
			CanRewriteToolArgs:  true,
			CanPauseForApproval: true,
		},
	})
	if err != nil {
		t.Fatalf("register matching adapter: %v", err)
	}

	result, err = engine.GetIntegration("openclaw-main")
	if err != nil {
		t.Fatalf("get integration after match: %v", err)
	}
	if result.Health.Status != types.IntegrationHealthConnected {
		t.Fatalf("matched integration status = %q, want connected", result.Health.Status)
	}
	if result.Health.MatchedAdapterID != "openclaw-main-01" {
		t.Fatalf("matched adapter id = %q", result.Health.MatchedAdapterID)
	}
	if len(result.MatchedAdapters) != 1 {
		t.Fatalf("expected one exact match, got %#v", result.MatchedAdapters)
	}
}

func TestIntegrationHealthDisabledAndMissing(t *testing.T) {
	engine := NewEngine()

	disabled, err := engine.SaveIntegration(types.IntegrationDefinition{
		ID:      "feishu-approval",
		Name:    "Feishu approval transport",
		Kind:    "transport",
		Enabled: false,
	})
	if err != nil {
		t.Fatalf("save disabled integration: %v", err)
	}
	if disabled.Health.Status != types.IntegrationHealthDisabled {
		t.Fatalf("disabled status = %q, want disabled", disabled.Health.Status)
	}

	enabled, err := engine.SaveIntegration(types.IntegrationDefinition{
		ID:      "resource-provider",
		Name:    "Resource provider",
		Kind:    "resource_provider",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("save enabled integration: %v", err)
	}
	if enabled.Health.Status != types.IntegrationHealthMissing {
		t.Fatalf("enabled without adapter status = %q, want missing", enabled.Health.Status)
	}
}

func TestPublishPolicyValidatesAndAffectsDecisions(t *testing.T) {
	engine := NewEngine()
	invalid := policy.DefaultBundle()
	invalid.Rules = nil
	if _, err := engine.PublishPolicy(PolicyPublishRequest{
		Bundle:     invalid,
		OperatorID: "admin",
		Message:    "invalid",
	}); err == nil {
		t.Fatal("expected invalid policy publish to fail")
	}

	bundle := policy.DefaultBundle()
	bundle.Rules = append(bundle.Rules, policy.Rule{
		ID:           "runtime.bash.deny",
		Priority:     200,
		Surface:      types.SurfaceRuntime,
		RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
		Effect:       types.EffectDeny,
		ReasonCode:   "runtime_bash_denied",
		When:         policy.Condition{Language: "cel", Expression: `action.tool == "bash"`},
	})
	published, err := engine.PublishPolicy(PolicyPublishRequest{
		Bundle:     bundle,
		OperatorID: "admin",
		Message:    "deny bash",
	})
	if err != nil {
		t.Fatalf("publish policy: %v", err)
	}
	if published.Record.Version != 2 || !published.Record.Active {
		t.Fatalf("unexpected published record: %#v", published.Record)
	}

	decision, err := engine.Decide(types.PolicyRequest{
		RequestID:   "req_after_policy_publish",
		RequestKind: types.RequestKindToolAttempt,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Session:     types.SessionContext{SessionID: "sess_1", TaskID: "task_1", AttemptID: "attempt_1"},
		Action:      types.ActionContext{Tool: "bash", Operation: "execute"},
		Target:      types.TargetContext{Kind: "process", Identifier: "shell"},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Effect != types.EffectDeny || decision.ReasonCode != "runtime_bash_denied" {
		t.Fatalf("decision did not use published policy: %#v", decision)
	}
	if decision.Explanation.PolicyTrace.PolicyVersion != 2 {
		t.Fatalf("policy version = %d, want 2", decision.Explanation.PolicyTrace.PolicyVersion)
	}
}

func TestRollbackPolicyCreatesNewActiveVersion(t *testing.T) {
	engine := NewEngine()
	bundle := policy.DefaultBundle()
	bundle.Rules = append(bundle.Rules, policy.Rule{
		ID:           "runtime.bash.deny",
		Priority:     200,
		Surface:      types.SurfaceRuntime,
		RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
		Effect:       types.EffectDeny,
		ReasonCode:   "runtime_bash_denied",
		When:         policy.Condition{Language: "cel", Expression: `action.tool == "bash"`},
	})
	if _, err := engine.PublishPolicy(PolicyPublishRequest{Bundle: bundle, OperatorID: "admin"}); err != nil {
		t.Fatalf("publish policy: %v", err)
	}

	rolledBack, err := engine.RollbackPolicy(PolicyRollbackRequest{
		Version:    1,
		OperatorID: "admin",
	})
	if err != nil {
		t.Fatalf("rollback policy: %v", err)
	}
	if rolledBack.Record.Version != 3 || rolledBack.Record.SourceVersion != 1 {
		t.Fatalf("unexpected rollback record: %#v", rolledBack.Record)
	}

	decision, err := engine.Decide(types.PolicyRequest{
		RequestID:   "req_after_policy_rollback",
		RequestKind: types.RequestKindToolAttempt,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Session:     types.SessionContext{SessionID: "sess_1", TaskID: "task_1", AttemptID: "attempt_1"},
		Action:      types.ActionContext{Tool: "bash", Operation: "execute"},
		Target:      types.TargetContext{Kind: "process", Identifier: "shell"},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Effect != types.EffectApprovalRequired {
		t.Fatalf("rollback should restore default bash approval, got %#v", decision)
	}
	if decision.Explanation.PolicyTrace.PolicyVersion != 3 {
		t.Fatalf("policy version = %d, want 3", decision.Explanation.PolicyTrace.PolicyVersion)
	}
}

func TestPolicyDecisionEventIncludesPolicyTraceMetadata(t *testing.T) {
	engine := NewEngine()

	decision, err := engine.Decide(types.PolicyRequest{
		RequestID:   "req_policy_trace_event",
		RequestKind: types.RequestKindToolAttempt,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Session:     types.SessionContext{SessionID: "sess_1", TaskID: "task_1", AttemptID: "attempt_1"},
		Action:      types.ActionContext{Tool: "bash", Operation: "execute", OpenWorld: true},
		Target:      types.TargetContext{Kind: "process", Identifier: "shell"},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Explanation.PolicyTrace.SelectedRule == "" {
		t.Fatalf("decision is missing policy trace: %#v", decision.Explanation.PolicyTrace)
	}

	events, err := engine.Events(10)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	var decisionEvent types.EventEnvelope
	for _, event := range events {
		if event.RequestID == "req_policy_trace_event" && event.EventType == "policy_decision" {
			decisionEvent = event
			break
		}
	}
	if decisionEvent.EventID == "" {
		t.Fatalf("missing policy decision event: %#v", events)
	}
	if decisionEvent.Metadata["selected_rule"] != decision.Explanation.PolicyTrace.SelectedRule {
		t.Fatalf("selected_rule metadata = %#v, want %q", decisionEvent.Metadata["selected_rule"], decision.Explanation.PolicyTrace.SelectedRule)
	}
	if decisionEvent.Metadata["policy_status"] != "active_minimal" {
		t.Fatalf("policy_status metadata = %#v", decisionEvent.Metadata["policy_status"])
	}
	if matchedRules, ok := decisionEvent.Metadata["matched_rules"].([]string); !ok || len(matchedRules) == 0 {
		t.Fatalf("matched_rules metadata missing or malformed: %#v", decisionEvent.Metadata["matched_rules"])
	}
	if decisionEvent.Metadata["approval_scope"] != "attempt" {
		t.Fatalf("approval_scope metadata = %#v, want attempt", decisionEvent.Metadata["approval_scope"])
	}
	if decisionEvent.Metadata["approval_expires_at"] == "" {
		t.Fatalf("approval_expires_at metadata missing: %#v", decisionEvent.Metadata)
	}
}

func TestSessionFactsAreUpdatedAfterReportAndInjectedIntoCEL(t *testing.T) {
	stateStore, err := store.OpenSQLite(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer stateStore.Close()

	bundle := coreTestBundle([]policy.Rule{
		{
			ID:           "runtime.block.target",
			Priority:     200,
			Surface:      types.SurfaceRuntime,
			RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
			Effect:       types.EffectDeny,
			ReasonCode:   "runtime_target_denied",
			When:         policy.Condition{Language: "cel", Expression: `target.identifier == "blocked-api"`},
			Obligations: []policy.Obligation{{
				Type:   "task_control",
				Params: map[string]interface{}{"action": "abort_task"},
			}},
		},
		{
			ID:           "runtime.session.history.approval",
			Priority:     100,
			Surface:      types.SurfaceRuntime,
			RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
			Effect:       types.EffectApprovalRequired,
			ReasonCode:   "runtime_session_history_requires_approval",
			When: policy.Condition{
				Language: "cel",
				Expression: `session_facts.deny_count >= 1 &&
					session_facts.distinct_targets.exists(x, x == "blocked-api") &&
					session_facts.side_effect_sequence.exists(x, x == "network_egress")`,
			},
		},
	})
	engine := NewEngine(WithEventStore(stateStore), WithStateStore(stateStore), WithPolicyBundle(bundle))

	first, err := engine.Decide(types.PolicyRequest{
		RequestID:   "req_history_first",
		RequestKind: types.RequestKindToolAttempt,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Session:     types.SessionContext{SessionID: "sess_history", TaskID: "task_1", AttemptID: "attempt_1"},
		Action:      types.ActionContext{Tool: "fetch", Operation: "fetch", SideEffects: []string{"network_egress"}},
		Target:      types.TargetContext{Kind: "api", Identifier: "blocked-api"},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	})
	if err != nil {
		t.Fatalf("first decide: %v", err)
	}
	if first.Effect != types.EffectDeny {
		t.Fatalf("first effect = %q, want deny", first.Effect)
	}
	if _, err := engine.Report(types.ReportRequest{
		RequestID:  first.RequestID,
		DecisionID: first.DecisionID,
		AdapterID:  "openclaw-main",
		Surface:    types.SurfaceRuntime,
		Outcome:    "blocked",
	}); err != nil {
		t.Fatalf("report: %v", err)
	}
	waitForSessionFacts(t, stateStore, "sess_history", func(facts types.SessionFacts) bool {
		return facts.DenyCount == 1 && len(facts.SideEffectSequence) == 1
	})

	second, err := engine.Decide(types.PolicyRequest{
		RequestID:   "req_history_second",
		RequestKind: types.RequestKindToolAttempt,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Session:     types.SessionContext{SessionID: "sess_history", TaskID: "task_1", AttemptID: "attempt_2"},
		Action:      types.ActionContext{Tool: "fetch", Operation: "fetch", SideEffects: []string{"network_egress"}},
		Target:      types.TargetContext{Kind: "api", Identifier: "new-api"},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	})
	if err != nil {
		t.Fatalf("second decide: %v", err)
	}
	if second.Effect != types.EffectApprovalRequired || second.Explanation.PolicyTrace.SelectedRule != "runtime.session.history.approval" {
		t.Fatalf("session facts were not injected into policy evaluation: %#v", second)
	}
}

func TestSessionFactsIgnoreReportsWithoutDecisionEvent(t *testing.T) {
	stateStore, err := store.OpenSQLite(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer stateStore.Close()
	engine := NewEngine(WithEventStore(stateStore), WithStateStore(stateStore))

	if _, err := engine.Report(types.ReportRequest{
		RequestID:  "req_unknown",
		DecisionID: "dec_unknown",
		AdapterID:  "openclaw-main",
		Surface:    types.SurfaceRuntime,
		Outcome:    "blocked",
	}); err != nil {
		t.Fatalf("report: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	_, found, err := stateStore.GetSessionFacts("sess_unknown")
	if err != nil {
		t.Fatalf("get session facts: %v", err)
	}
	if found {
		t.Fatal("report without matching decision event should not create session facts")
	}
}

func TestSessionFactsSideEffectSequenceIsCapped(t *testing.T) {
	facts := types.SessionFacts{}
	for index := 0; index < 25; index++ {
		facts = updateSessionFacts(facts, types.EventEnvelope{
			Effect:     types.EffectAllowWithAudit,
			Summary:    "allow",
			Metadata:   map[string]interface{}{"side_effects": []string{fmt.Sprintf("effect_%02d", index)}},
			OccurredAt: time.Date(2026, 4, 29, 12, index, 0, 0, time.UTC),
		}, time.Date(2026, 4, 29, 12, index, 1, 0, time.UTC))
	}
	if len(facts.SideEffectSequence) != 20 {
		t.Fatalf("side effect cap = %d, want 20: %#v", len(facts.SideEffectSequence), facts.SideEffectSequence)
	}
	if facts.SideEffectSequence[0] != "effect_05" || facts.SideEffectSequence[19] != "effect_24" {
		t.Fatalf("unexpected capped sequence: %#v", facts.SideEffectSequence)
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

	decision, err := engine.Decide(types.PolicyRequest{
		RequestID:   "req_secret_without_policy",
		RequestKind: types.RequestKindInput,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Session:     types.SessionContext{SessionID: "sess_1", TaskID: "task_1"},
		Action:      types.ActionContext{Operation: "model_input"},
		Target:      types.TargetContext{Kind: "model_context"},
		Context: types.DecisionContext{
			Surface: types.SurfaceInput,
			Raw: map[string]interface{}{
				"text": "api_key: sk-test-1234567890abcdef",
			},
		},
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Effect != types.EffectDeny {
		t.Fatalf("effect = %q, want deny", decision.Effect)
	}
	if decision.ReasonCode != "input_secret_policy_missing" {
		t.Fatalf("reason = %q, want input_secret_policy_missing", decision.ReasonCode)
	}
	if hasObligation(decision.Obligations, "rewrite_input") {
		t.Fatalf("secret should not be rewritten without an explicit policy rule: %#v", decision.Obligations)
	}
}

func TestResourceSecretFailsClosedWithoutPolicyRule(t *testing.T) {
	bundle := coreTestBundle([]policy.Rule{
		{
			ID:           "input.secret.rewrite_to_handle",
			Priority:     100,
			Surface:      types.SurfaceInput,
			RequestKinds: []types.RequestKind{types.RequestKindInput},
			Effect:       types.EffectAllowWithAudit,
			ReasonCode:   "input_secret_rewritten_to_handles",
			When:         policy.Condition{Language: "cel", Expression: `content.data_classes.exists(x, x == "secret")`},
		},
	})
	engine := NewEngine(WithPolicyBundle(bundle))

	inputDecision, err := engine.Decide(types.PolicyRequest{
		RequestID:   "req_input_only_policy",
		RequestKind: types.RequestKindInput,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Session:     types.SessionContext{SessionID: "sess_1", TaskID: "task_1"},
		Action:      types.ActionContext{Operation: "model_input"},
		Target:      types.TargetContext{Kind: "model_context"},
		Context: types.DecisionContext{
			Surface: types.SurfaceInput,
			Raw: map[string]interface{}{
				"text": "api_key: sk-test-1234567890abcdef",
			},
		},
	})
	if err != nil {
		t.Fatalf("input decide: %v", err)
	}
	handleID := handleIDFromDecision(t, inputDecision)

	resourceDecision, err := engine.Decide(types.PolicyRequest{
		RequestID:   "req_resource_without_policy",
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
	if resourceDecision.Effect != types.EffectDeny {
		t.Fatalf("effect = %q, want deny", resourceDecision.Effect)
	}
	if resourceDecision.ReasonCode != "resource_secret_policy_missing" {
		t.Fatalf("reason = %q, want resource_secret_policy_missing", resourceDecision.ReasonCode)
	}
	if hasObligation(resourceDecision.Obligations, "resolve_secret_handle") {
		t.Fatalf("secret should not be resolved without an explicit policy rule: %#v", resourceDecision.Obligations)
	}
}

func TestPolicyDenyOverridesRuntimeApprovalInCore(t *testing.T) {
	bundle := policy.DefaultBundle()
	bundle.Rules = append(bundle.Rules, policy.Rule{
		ID:           "runtime.bash.deny.root",
		Priority:     200,
		Surface:      types.SurfaceRuntime,
		RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
		Effect:       types.EffectDeny,
		ReasonCode:   "runtime_bash_root_denied",
		When:         policy.Condition{Language: "cel", Expression: `action.tool == "bash" && target.identifier == "root-shell"`},
		Obligations: []policy.Obligation{{
			Type: "task_control",
			Params: map[string]interface{}{
				"action": "abort_task",
			},
		}},
	})
	if err := bundle.Validate(); err != nil {
		t.Fatalf("validate policy: %v", err)
	}

	engine := NewEngine(WithPolicyBundle(bundle))
	decision, err := engine.Decide(types.PolicyRequest{
		RequestID:   "req_root_bash",
		RequestKind: types.RequestKindToolAttempt,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Session:     types.SessionContext{SessionID: "sess_1", TaskID: "task_1", AttemptID: "attempt_1"},
		Action:      types.ActionContext{Tool: "bash", Operation: "execute", OpenWorld: true},
		Target:      types.TargetContext{Kind: "process", Identifier: "root-shell"},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Effect != types.EffectDeny {
		t.Fatalf("effect = %q, want deny", decision.Effect)
	}
	if decision.ReasonCode != "runtime_bash_root_denied" {
		t.Fatalf("reason = %q", decision.ReasonCode)
	}
	if !containsAppliedRule(decision.AppliedRules, "runtime.bash.deny.root") {
		t.Fatalf("missing deny rule in applied rules: %#v", decision.AppliedRules)
	}
	if decision.Explanation.PolicyTrace.SelectedRule != "runtime.bash.deny.root" {
		t.Fatalf("selected policy trace rule = %q", decision.Explanation.PolicyTrace.SelectedRule)
	}
	if len(decision.Explanation.PolicyTrace.MatchedRules) == 0 {
		t.Fatalf("policy trace should include matched rules: %#v", decision.Explanation.PolicyTrace)
	}
	if approvalIDFromObligations(decision.Obligations) != "" {
		t.Fatalf("deny decision must not request approval: %#v", decision.Obligations)
	}
}

func TestRuntimeApprovalGrantIsAttemptScoped(t *testing.T) {
	engine := NewEngine()
	req := types.PolicyRequest{
		RequestID:   "req_attempt_1",
		RequestKind: types.RequestKindToolAttempt,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Session:     types.SessionContext{SessionID: "sess_1", TaskID: "task_1", AttemptID: "attempt_1"},
		Action:      types.ActionContext{Tool: "bash", Operation: "execute", OpenWorld: true},
		Target:      types.TargetContext{Kind: "process", Identifier: "shell"},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	}

	firstDecision, err := engine.Decide(req)
	if err != nil {
		t.Fatalf("first decide: %v", err)
	}
	if firstDecision.Effect != types.EffectApprovalRequired {
		t.Fatalf("first effect = %q, want approval_required", firstDecision.Effect)
	}
	approvalID := approvalIDFromObligations(firstDecision.Obligations)
	if approvalID == "" {
		t.Fatalf("missing approval request obligation: %#v", firstDecision.Obligations)
	}

	if _, err := engine.ResolveApproval(approvalID, types.ApprovalResolveRequest{
		Decision:   "allow_once",
		OperatorID: "operator_1",
		Channel:    "test",
	}); err != nil {
		t.Fatalf("resolve approval: %v", err)
	}

	allowedDecision, err := engine.Decide(req)
	if err != nil {
		t.Fatalf("same attempt decide: %v", err)
	}
	if allowedDecision.Effect != types.EffectAllowWithAudit {
		t.Fatalf("same attempt effect = %q, want allow_with_audit", allowedDecision.Effect)
	}
	if allowedDecision.ReasonCode != "user_allow_once_valid" {
		t.Fatalf("same attempt reason = %q, want user_allow_once_valid", allowedDecision.ReasonCode)
	}

	nextAttempt := req
	nextAttempt.RequestID = "req_attempt_2"
	nextAttempt.Session.AttemptID = "attempt_2"
	nextDecision, err := engine.Decide(nextAttempt)
	if err != nil {
		t.Fatalf("next attempt decide: %v", err)
	}
	if nextDecision.Effect != types.EffectApprovalRequired {
		t.Fatalf("next attempt effect = %q, want approval_required", nextDecision.Effect)
	}
	if approvalIDFromObligations(nextDecision.Obligations) == "" {
		t.Fatalf("next attempt should require a fresh approval: %#v", nextDecision.Obligations)
	}
}

func TestExpiredApprovalCannotBeApproved(t *testing.T) {
	engine := NewEngine()
	req := types.PolicyRequest{
		RequestID:   "req_expired_approval",
		RequestKind: types.RequestKindToolAttempt,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Session:     types.SessionContext{SessionID: "sess_1", TaskID: "task_1", AttemptID: "attempt_1"},
		Action:      types.ActionContext{Tool: "bash", Operation: "execute", OpenWorld: true},
		Target:      types.TargetContext{Kind: "process", Identifier: "shell"},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	}

	decision, err := engine.Decide(req)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	approvalID := approvalIDFromObligations(decision.Obligations)
	if approvalID == "" {
		t.Fatalf("missing approval request obligation: %#v", decision.Obligations)
	}
	engine.mu.Lock()
	approval := engine.approvals[approvalID]
	approval.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	engine.approvals[approvalID] = approval
	engine.mu.Unlock()

	_, err = engine.ResolveApproval(approvalID, types.ApprovalResolveRequest{
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

	approvals, err := engine.Approvals(10)
	if err != nil {
		t.Fatalf("approvals: %v", err)
	}
	if len(approvals.Approvals) != 1 || approvals.Approvals[0].Status != types.ApprovalExpired {
		t.Fatalf("approval should be expired: %#v", approvals.Approvals)
	}
}

func TestApprovalsReadExpiresPendingRecords(t *testing.T) {
	engine := NewEngine()
	now := time.Now().UTC()
	engine.approvals["appr_expired"] = approvalState{
		ApprovalID: "appr_expired",
		RequestID:  "req_1",
		SessionID:  "sess_1",
		TaskID:     "task_1",
		AttemptID:  "attempt_1",
		Status:     types.ApprovalPending,
		Reason:     "runtime_high_risk_requires_approval",
		CreatedAt:  now.Add(-2 * time.Minute),
		ExpiresAt:  now.Add(-time.Minute),
	}

	approvals, err := engine.Approvals(10)
	if err != nil {
		t.Fatalf("approvals: %v", err)
	}
	if len(approvals.Approvals) != 1 {
		t.Fatalf("expected one approval, got %#v", approvals.Approvals)
	}
	if approvals.Approvals[0].Status != types.ApprovalExpired {
		t.Fatalf("status = %q, want expired", approvals.Approvals[0].Status)
	}
	if approvals.Approvals[0].ResolvedAt == nil {
		t.Fatal("expired approval should have resolved_at")
	}
	events, err := engine.Events(10)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if !hasEventType(events, "approval_expired") {
		t.Fatalf("expected approval_expired event, got %#v", events)
	}
	if eventEffect(events, "approval_expired") != types.EffectDeny {
		t.Fatalf("approval_expired event effect = %q, want deny", eventEffect(events, "approval_expired"))
	}
}

func TestApprovalsReadExpiresPendingRecordsFromStateStore(t *testing.T) {
	stateStore, err := store.OpenSQLite(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer stateStore.Close()
	now := time.Now().UTC()
	approval := types.ApprovalRecord{
		ApprovalID: "appr_expired_store",
		RequestID:  "req_1",
		SessionID:  "sess_1",
		TaskID:     "task_1",
		AttemptID:  "attempt_1",
		Status:     types.ApprovalPending,
		Reason:     "runtime_high_risk_requires_approval",
		CreatedAt:  now.Add(-2 * time.Minute),
		ExpiresAt:  now.Add(-time.Minute),
	}
	if err := stateStore.SaveApproval(approval); err != nil {
		t.Fatalf("save approval: %v", err)
	}
	engine := NewEngine(WithEventStore(stateStore), WithStateStore(stateStore))

	approvals, err := engine.Approvals(10)
	if err != nil {
		t.Fatalf("approvals: %v", err)
	}
	if len(approvals.Approvals) != 1 || approvals.Approvals[0].Status != types.ApprovalExpired {
		t.Fatalf("approval should be expired: %#v", approvals.Approvals)
	}
	_, found, err := stateStore.GetApproval("appr_expired_store")
	if err != nil {
		t.Fatalf("get approval: %v", err)
	}
	if !found {
		t.Fatal("expected persisted approval")
	}
	events, err := engine.Events(10)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if !hasEventType(events, "approval_expired") {
		t.Fatalf("expected persisted approval_expired event, got %#v", events)
	}
}

func handleIDFromDecision(t *testing.T, decision types.PolicyDecision) string {
	t.Helper()
	for _, obligation := range decision.Obligations {
		if obligation.Type != "rewrite_input" {
			continue
		}
		handles, ok := obligation.Params["secret_handles"].([]types.SecretHandle)
		if !ok || len(handles) == 0 {
			t.Fatalf("missing secret_handles obligation params: %#v", obligation.Params)
		}
		return handles[0].HandleID
	}
	t.Fatalf("missing rewrite_input obligation: %#v", decision.Obligations)
	return ""
}

func containsAppliedRule(rules []string, expected string) bool {
	for _, rule := range rules {
		if rule == expected || strings.HasSuffix(rule, "/"+expected) {
			return true
		}
	}
	return false
}

func hasObligation(obligations []types.Obligation, expected string) bool {
	for _, obligation := range obligations {
		if obligation.Type == expected {
			return true
		}
	}
	return false
}

func hasEventType(events []types.EventEnvelope, expected string) bool {
	for _, event := range events {
		if event.EventType == expected {
			return true
		}
	}
	return false
}

func eventEffect(events []types.EventEnvelope, eventType string) types.Effect {
	for _, event := range events {
		if event.EventType == eventType {
			return event.Effect
		}
	}
	return ""
}

func waitForSessionFacts(t *testing.T, stateStore *store.SQLiteStore, sessionID string, ready func(types.SessionFacts) bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		record, found, err := stateStore.GetSessionFacts(sessionID)
		if err != nil {
			t.Fatalf("get session facts: %v", err)
		}
		if found && ready(record.Facts) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	record, found, err := stateStore.GetSessionFacts(sessionID)
	if err != nil {
		t.Fatalf("get session facts after wait: %v", err)
	}
	t.Fatalf("session facts not ready: found=%v record=%#v", found, record)
}

func coreTestBundle(rules []policy.Rule) policy.Bundle {
	return policy.Bundle{
		Version:  1,
		Status:   "test",
		IssuedAt: time.Date(2026, 4, 24, 0, 0, 0, 0, time.UTC),
		Rules:    rules,
		InputPolicy: policy.InputPolicy{
			SecretMode: "secret_handle",
		},
		ResourcePolicy: policy.ResourcePolicy{
			SecretHandleScope: "session_task",
		},
	}
}
