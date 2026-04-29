package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentgate/agentgate/internal/types"
)

func TestLoadDefaultPolicy(t *testing.T) {
	bundle, err := LoadFile(filepath.Join("..", "..", "config", "default_policy.json"))
	if err != nil {
		t.Fatalf("load default policy: %v", err)
	}

	if bundle.Version != 1 {
		t.Fatalf("version = %d, want 1", bundle.Version)
	}
	bashEvaluation := bundle.Evaluate(types.PolicyRequest{
		RequestKind: types.RequestKindToolAttempt,
		Action:      types.ActionContext{Tool: "bash"},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	})
	if bashEvaluation.Effect != types.EffectApprovalRequired {
		t.Fatalf("bash effect = %q, want approval_required", bashEvaluation.Effect)
	}
	if bashEvaluation.ReasonCode != "runtime_high_risk_requires_approval" {
		t.Fatalf("bash reason = %q", bashEvaluation.ReasonCode)
	}
	if !containsRule(bashEvaluation.AppliedRules, "runtime.bash.requires_approval") {
		t.Fatalf("bash applied rules = %#v", bashEvaluation.AppliedRules)
	}
	secretInputEvaluation := bundle.Evaluate(types.PolicyRequest{
		RequestKind: types.RequestKindInput,
		Content:     types.ContentContext{DataClasses: []types.DataClass{types.DataClassSecret}},
		Context:     types.DecisionContext{Surface: types.SurfaceInput},
	})
	if secretInputEvaluation.Effect != types.EffectAllowWithAudit {
		t.Fatalf("secret input effect = %q, want allow_with_audit", secretInputEvaluation.Effect)
	}
	if secretInputEvaluation.SelectedRule != "input.secret.rewrite_to_handle" {
		t.Fatalf("secret input selected rule = %q", secretInputEvaluation.SelectedRule)
	}
	resourceEvaluation := bundle.Evaluate(types.PolicyRequest{
		RequestKind: types.RequestKindResourceAccess,
		Action:      types.ActionContext{Operation: "resolve_secret_handle"},
		Target:      types.TargetContext{Kind: "secret_handle", Identifier: "sech_test"},
		Context:     types.DecisionContext{Surface: types.SurfaceResource},
	})
	if resourceEvaluation.Effect != types.EffectAllowWithAudit {
		t.Fatalf("resource effect = %q, want allow_with_audit", resourceEvaluation.Effect)
	}
	if resourceEvaluation.SelectedRule != "resource.secret_handle.resolve" {
		t.Fatalf("resource selected rule = %q", resourceEvaluation.SelectedRule)
	}
	if !bundle.RequiresRuntimeApproval(types.PolicyRequest{
		RequestKind: types.RequestKindToolAttempt,
		Action:      types.ActionContext{SideEffects: []string{"network_egress"}},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	}) {
		t.Fatal("network egress should require runtime approval")
	}
	if bundle.RequiresRuntimeApproval(types.PolicyRequest{
		RequestKind: types.RequestKindToolAttempt,
		Action:      types.ActionContext{Tool: "read", SideEffects: []string{"filesystem_read"}},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	}) {
		t.Fatal("read-only action should not require runtime approval")
	}
}

func TestPolicyPriorityAndEffectComposition(t *testing.T) {
	bundle := Bundle{
		Version:  1,
		Status:   "test",
		IssuedAt: mustTime(t, "2026-04-24T00:00:00Z"),
		InputPolicy: InputPolicy{
			SecretMode: "secret_handle",
		},
		ResourcePolicy: ResourcePolicy{
			SecretHandleScope: "session_task",
		},
		Rules: []Rule{
			{
				ID:           "runtime.low.allow",
				Priority:     10,
				Surface:      types.SurfaceRuntime,
				RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
				Effect:       types.EffectAllowWithAudit,
				ReasonCode:   "low_allow",
				When:         celCond(`action.tool == "bash"`),
			},
			{
				ID:           "runtime.high.deny",
				Priority:     100,
				Surface:      types.SurfaceRuntime,
				RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
				Effect:       types.EffectDeny,
				ReasonCode:   "high_deny",
				When:         celCond(`action.open_world == true`),
				Obligations:  []Obligation{{Type: "task_control", Params: map[string]interface{}{"action": "abort_task"}}},
			},
		},
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	evaluation := bundle.Evaluate(types.PolicyRequest{
		RequestKind: types.RequestKindToolAttempt,
		Action:      types.ActionContext{Tool: "bash", OpenWorld: true},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	})
	if evaluation.Effect != types.EffectDeny || evaluation.ReasonCode != "high_deny" {
		t.Fatalf("evaluation = %#v", evaluation)
	}
	if containsRule(evaluation.AppliedRules, "runtime.low.allow") || !containsRule(evaluation.AppliedRules, "runtime.high.deny") {
		t.Fatalf("only top-priority rules should apply: %#v", evaluation.AppliedRules)
	}
	if len(evaluation.MatchedRules) != 2 {
		t.Fatalf("all matched rules should remain traceable: %#v", evaluation.MatchedRules)
	}
}

func TestEvaluateBundlesUsesBundlePriorityBeforeRulePriority(t *testing.T) {
	low := testBundle("low", 10, Rule{
		ID:           "runtime.bash.deny.low_bundle",
		Priority:     999,
		Surface:      types.SurfaceRuntime,
		RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
		Effect:       types.EffectDeny,
		ReasonCode:   "low_bundle_deny",
		When:         celCond(`action.tool == "bash"`),
	})
	high := testBundle("high", 100, Rule{
		ID:           "runtime.bash.approve.high_bundle",
		Priority:     1,
		Surface:      types.SurfaceRuntime,
		RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
		Effect:       types.EffectApprovalRequired,
		ReasonCode:   "high_bundle_approval",
		When:         celCond(`action.tool == "bash"`),
	})

	evaluation := EvaluateBundles([]Bundle{low, high}, types.PolicyRequest{
		RequestKind: types.RequestKindToolAttempt,
		Action:      types.ActionContext{Tool: "bash"},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	})

	if evaluation.Effect != types.EffectApprovalRequired {
		t.Fatalf("effect = %q, want approval_required", evaluation.Effect)
	}
	if evaluation.SelectedBundle != "high" || evaluation.SelectedRule != "runtime.bash.approve.high_bundle" {
		t.Fatalf("unexpected selected rule: %#v", evaluation)
	}
	if containsRule(evaluation.AppliedRules, "runtime.bash.deny.low_bundle") {
		t.Fatalf("lower-priority bundle rule should not apply: %#v", evaluation.AppliedRules)
	}
}

func TestEvaluateBundlesAppliesSameBundleAndRulePriorityTogether(t *testing.T) {
	bundle := testBundle("shared", 100,
		Rule{
			ID:           "runtime.bash.audit",
			Priority:     50,
			Surface:      types.SurfaceRuntime,
			RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
			Effect:       types.EffectAllowWithAudit,
			ReasonCode:   "audit",
			When:         celCond(`action.tool == "bash"`),
		},
		Rule{
			ID:           "runtime.bash.deny",
			Priority:     50,
			Surface:      types.SurfaceRuntime,
			RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
			Effect:       types.EffectDeny,
			ReasonCode:   "deny",
			When:         celCond(`action.tool == "bash"`),
		},
	)

	evaluation := EvaluateBundles([]Bundle{bundle}, types.PolicyRequest{
		RequestKind: types.RequestKindToolAttempt,
		Action:      types.ActionContext{Tool: "bash"},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	})

	if evaluation.Effect != types.EffectDeny {
		t.Fatalf("effect = %q, want deny", evaluation.Effect)
	}
	if !containsRule(evaluation.AppliedRules, "runtime.bash.audit") || !containsRule(evaluation.AppliedRules, "runtime.bash.deny") {
		t.Fatalf("same-priority rules should apply together: %#v", evaluation.AppliedRules)
	}
}

func TestEvaluateBundlesFailsClosedWithoutActiveBundle(t *testing.T) {
	bundle := testBundle("inactive", 100, Rule{
		ID:           "runtime.bash.approve",
		Priority:     1,
		Surface:      types.SurfaceRuntime,
		RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
		Effect:       types.EffectApprovalRequired,
		ReasonCode:   "approval",
		When:         celCond(`action.tool == "bash"`),
	})
	bundle.Status = BundleStatusInactive

	evaluation := EvaluateBundles([]Bundle{bundle}, types.PolicyRequest{
		RequestKind: types.RequestKindToolAttempt,
		Action:      types.ActionContext{Tool: "bash"},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	})

	if evaluation.Effect != types.EffectDeny || evaluation.ReasonCode != "policy_no_active_bundle" {
		t.Fatalf("evaluation = %#v", evaluation)
	}
}

func TestPolicyValidationRejectsDuplicateRules(t *testing.T) {
	bundle := DefaultBundle()
	bundle.Rules = append(bundle.Rules, bundle.Rules[0])
	if err := bundle.Validate(); err == nil {
		t.Fatal("expected duplicate rule validation error")
	}
}

func testBundle(bundleID string, priority int, rules ...Rule) Bundle {
	bundle := DefaultBundle()
	bundle.BundleID = bundleID
	bundle.Name = bundleID
	bundle.Priority = priority
	bundle.Status = BundleStatusActive
	bundle.Rules = append([]Rule(nil), rules...)
	return bundle
}

func TestPolicyValidationRejectsMalformedRules(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(Bundle) Bundle
		want   string
	}{
		{
			name: "negative priority",
			mutate: func(bundle Bundle) Bundle {
				bundle.Rules[0].Priority = -1
				return bundle
			},
			want: "priority",
		},
		{
			name: "padded rule id",
			mutate: func(bundle Bundle) Bundle {
				bundle.Rules[0].ID = " runtime.bad "
				return bundle
			},
			want: "whitespace",
		},
		{
			name: "reason has spaces",
			mutate: func(bundle Bundle) Bundle {
				bundle.Rules[0].ReasonCode = "bad reason"
				return bundle
			},
			want: "compact token",
		},
		{
			name: "missing cel language",
			mutate: func(bundle Bundle) Bundle {
				bundle.Rules[0].When.Language = ""
				return bundle
			},
			want: "unsupported",
		},
		{
			name: "blank cel expression",
			mutate: func(bundle Bundle) Bundle {
				bundle.Rules[0].When.Expression = ""
				return bundle
			},
			want: "requires expression",
		},
		{
			name: "unsupported condition language",
			mutate: func(bundle Bundle) Bundle {
				bundle.Rules[0].When.Language = "structured"
				return bundle
			},
			want: "unsupported",
		},
		{
			name: "sensitive obligation param",
			mutate: func(bundle Bundle) Bundle {
				bundle.Rules[0].Obligations = []Obligation{{
					Type: "audit_event",
					Params: map[string]interface{}{
						"secret_value": "sk-test-123",
					},
				}}
				return bundle
			},
			want: "sensitive",
		},
		{
			name: "core owned obligation",
			mutate: func(bundle Bundle) Bundle {
				bundle.Rules[0].Obligations = []Obligation{{Type: "rewrite_input"}}
				return bundle
			},
			want: "core-owned",
		},
		{
			name: "allow cannot abort",
			mutate: func(bundle Bundle) Bundle {
				bundle.Rules[0].Obligations = []Obligation{{
					Type:   "task_control",
					Params: map[string]interface{}{"action": "abort_task"},
				}}
				return bundle
			},
			want: "cannot use abort_task",
		},
		{
			name: "unknown task control action",
			mutate: func(bundle Bundle) Bundle {
				bundle.Rules[0].Effect = types.EffectDeny
				bundle.Rules[0].Obligations = []Obligation{{
					Type:   "task_control",
					Params: map[string]interface{}{"action": "sleep_until_tomorrow"},
				}}
				return bundle
			},
			want: "unsupported task_control action",
		},
		{
			name: "pause requires approval effect",
			mutate: func(bundle Bundle) Bundle {
				bundle.Rules[0].Obligations = []Obligation{{
					Type:   "task_control",
					Params: map[string]interface{}{"action": "pause_for_approval"},
				}}
				return bundle
			},
			want: "requires approval_required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.mutate(DefaultBundle()).Validate()
			if err == nil {
				t.Fatalf("expected validation error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.want)
			}
		})
	}
}

func TestPolicyLoadRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	payload := `{
		"version": 1,
		"status": "test",
		"issued_at": "2026-04-24T00:00:00Z",
		"unknown": true,
		"rules": [{
			"id": "runtime.test",
			"priority": 1,
			"surface": "runtime",
			"request_kinds": ["tool_attempt"],
			"effect": "allow_with_audit",
			"reason_code": "test_allow"
		}],
		"input_policy": {"secret_mode": "secret_handle"},
		"resource_policy": {"secret_handle_scope": "session_task"},
		"egress_policy": {},
		"path_policy": {}
	}`
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("expected unknown field parse error")
	}
}

func TestPolicyEvaluateInvalidRequestFailsClosed(t *testing.T) {
	evaluation := DefaultBundle().Evaluate(types.PolicyRequest{
		RequestKind: "made_up",
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	})
	if evaluation.Effect != types.EffectDeny {
		t.Fatalf("invalid request effect = %q, want deny", evaluation.Effect)
	}
	if evaluation.ReasonCode != "policy_invalid_request" {
		t.Fatalf("invalid request reason = %q", evaluation.ReasonCode)
	}
}

func TestWildcardDoesNotMatchMissingField(t *testing.T) {
	bundle := minimalBundle([]Rule{
		{
			ID:           "runtime.any_tool.approval",
			Priority:     10,
			Surface:      types.SurfaceRuntime,
			RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
			Effect:       types.EffectApprovalRequired,
			ReasonCode:   "any_tool_requires_approval",
			When:         celCond(`action.tool != ""`),
		},
	})
	if err := bundle.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	evaluation := bundle.Evaluate(types.PolicyRequest{
		RequestKind: types.RequestKindToolAttempt,
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	})
	if evaluation.Effect != types.EffectAllowWithAudit {
		t.Fatalf("wildcard matched missing tool: %#v", evaluation)
	}
}

func TestCELConditionsExpressAndSemantics(t *testing.T) {
	bundle := minimalBundle([]Rule{
		{
			ID:           "runtime.bash.write.approval",
			Priority:     10,
			Surface:      types.SurfaceRuntime,
			RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
			Effect:       types.EffectApprovalRequired,
			ReasonCode:   "bash_write_requires_approval",
			When: celCond(`action.tool == "bash" &&
					action.side_effects.exists(x, x == "filesystem_write") &&
					action.side_effects.exists(x, x == "process_spawn")`),
		},
	})
	if err := bundle.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	miss := bundle.Evaluate(types.PolicyRequest{
		RequestKind: types.RequestKindToolAttempt,
		Action:      types.ActionContext{Tool: "bash", SideEffects: []string{"filesystem_write"}},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	})
	if miss.Effect != types.EffectAllowWithAudit {
		t.Fatalf("cel conjunction should not match partial set: %#v", miss)
	}
	hit := bundle.Evaluate(types.PolicyRequest{
		RequestKind: types.RequestKindToolAttempt,
		Action:      types.ActionContext{Tool: "bash", SideEffects: []string{"filesystem_write", "process_spawn"}},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	})
	if hit.Effect != types.EffectApprovalRequired {
		t.Fatalf("cel conjunction should match full set: %#v", hit)
	}
}

func TestCELConditionMatchesPolicyFacts(t *testing.T) {
	bundle := minimalBundle([]Rule{
		{
			ID:           "runtime.cel.bash.secret.egress",
			Priority:     20,
			Surface:      types.SurfaceRuntime,
			RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
			Effect:       types.EffectApprovalRequired,
			ReasonCode:   "cel_bash_secret_egress",
			When: Condition{
				Language: "cel",
				Expression: `action.tool == "bash" &&
					action.side_effects.exists(x, x in ["network_egress", "filesystem_write"]) &&
					content.data_classes.exists(x, x == "secret")`,
			},
		},
	})
	if err := bundle.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	miss := bundle.Evaluate(types.PolicyRequest{
		RequestKind: types.RequestKindToolAttempt,
		Action: types.ActionContext{
			Tool:        "bash",
			SideEffects: []string{"filesystem_read"},
		},
		Content: types.ContentContext{DataClasses: []types.DataClass{types.DataClassSecret}},
		Context: types.DecisionContext{Surface: types.SurfaceRuntime},
	})
	if miss.Effect != types.EffectAllowWithAudit {
		t.Fatalf("cel should not match read-only side effect: %#v", miss)
	}
	hit := bundle.Evaluate(types.PolicyRequest{
		RequestKind: types.RequestKindToolAttempt,
		Action: types.ActionContext{
			Tool:        "bash",
			SideEffects: []string{"network_egress"},
		},
		Content: types.ContentContext{DataClasses: []types.DataClass{types.DataClassSecret}},
		Context: types.DecisionContext{Surface: types.SurfaceRuntime},
	})
	if hit.Effect != types.EffectApprovalRequired || hit.SelectedRule != "runtime.cel.bash.secret.egress" {
		t.Fatalf("cel should match bash secret egress: %#v", hit)
	}
}

func TestCELConditionMatchesSessionFacts(t *testing.T) {
	bundle := minimalBundle([]Rule{
		{
			ID:           "runtime.session.deny_escalation",
			Priority:     20,
			Surface:      types.SurfaceRuntime,
			RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
			Effect:       types.EffectApprovalRequired,
			ReasonCode:   "session_deny_escalation",
			When: celCond(`session_facts.deny_count > 5 &&
				session_facts.distinct_targets.size() > 2 &&
				session_facts.side_effect_sequence.exists(x, x == "network_egress")`),
		},
	})
	if err := bundle.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	miss := bundle.Evaluate(types.PolicyRequest{
		RequestKind: types.RequestKindToolAttempt,
		Action:      types.ActionContext{Tool: "bash"},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	}, types.SessionFacts{
		DenyCount:          5,
		DistinctTargets:    []string{"a", "b", "c"},
		SideEffectSequence: []string{"network_egress"},
	})
	if miss.Effect != types.EffectAllowWithAudit {
		t.Fatalf("session facts below threshold should not match: %#v", miss)
	}
	hit := bundle.Evaluate(types.PolicyRequest{
		RequestKind: types.RequestKindToolAttempt,
		Action:      types.ActionContext{Tool: "bash"},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	}, types.SessionFacts{
		DenyCount:          6,
		DistinctTargets:    []string{"a", "b", "c"},
		SideEffectSequence: []string{"filesystem_write", "network_egress"},
	})
	if hit.Effect != types.EffectApprovalRequired || hit.SelectedRule != "runtime.session.deny_escalation" {
		t.Fatalf("session facts should match escalation rule: %#v", hit)
	}
}

func TestPolicyValidationRejectsInvalidCELCondition(t *testing.T) {
	bundle := minimalBundle([]Rule{
		{
			ID:           "runtime.bad.cel",
			Priority:     1,
			Surface:      types.SurfaceRuntime,
			RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
			Effect:       types.EffectApprovalRequired,
			ReasonCode:   "bad_cel",
			When: Condition{
				Language:   "cel",
				Expression: `action.tool == `,
			},
		},
	})
	err := bundle.Validate()
	if err == nil || !strings.Contains(err.Error(), "cel expression invalid") {
		t.Fatalf("expected cel validation error, got %v", err)
	}
}

func TestPolicyValidationRejectsImplicitCatchAll(t *testing.T) {
	bundle := minimalBundle([]Rule{
		{
			ID:           "runtime.implicit.catch_all",
			Priority:     1,
			Surface:      types.SurfaceRuntime,
			RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
			Effect:       types.EffectAllowWithAudit,
			ReasonCode:   "implicit_catch_all",
		},
	})
	err := bundle.Validate()
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("expected implicit catch-all validation error, got %v", err)
	}
}

func TestPolicyExplicitAlwaysCatchAll(t *testing.T) {
	bundle := minimalBundle([]Rule{
		{
			ID:           "runtime.explicit.catch_all",
			Priority:     1,
			Surface:      types.SurfaceRuntime,
			RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
			Effect:       types.EffectApprovalRequired,
			ReasonCode:   "explicit_catch_all",
			When:         celCond(`true`),
		},
	})
	if err := bundle.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	evaluation := bundle.Evaluate(types.PolicyRequest{
		RequestKind: types.RequestKindToolAttempt,
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	})
	if evaluation.Effect != types.EffectApprovalRequired || evaluation.SelectedRule != "runtime.explicit.catch_all" {
		t.Fatalf("explicit always did not match: %#v", evaluation)
	}
}

func TestPolicyValidationRejectsBlankCELExpression(t *testing.T) {
	bundle := minimalBundle([]Rule{
		{
			ID:           "runtime.bad.blank_cel",
			Priority:     1,
			Surface:      types.SurfaceRuntime,
			RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
			Effect:       types.EffectApprovalRequired,
			ReasonCode:   "bad_blank_cel",
			When:         Condition{Language: "cel", Expression: ""},
		},
	})
	err := bundle.Validate()
	if err == nil || !strings.Contains(err.Error(), "requires expression") {
		t.Fatalf("expected blank cel validation error, got %v", err)
	}
}

func TestDenyAddsDefaultAbortTaskObligation(t *testing.T) {
	bundle := minimalBundle([]Rule{
		{
			ID:           "runtime.deny.no_obligation",
			Priority:     1,
			Surface:      types.SurfaceRuntime,
			RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
			Effect:       types.EffectDeny,
			ReasonCode:   "deny_without_obligation",
			When:         celCond(`action.tool == "bash"`),
		},
	})
	if err := bundle.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	evaluation := bundle.Evaluate(types.PolicyRequest{
		RequestKind: types.RequestKindToolAttempt,
		Action:      types.ActionContext{Tool: "bash"},
		Context:     types.DecisionContext{Surface: types.SurfaceRuntime},
	})
	if evaluation.Effect != types.EffectDeny {
		t.Fatalf("effect = %q, want deny", evaluation.Effect)
	}
	if !hasTestObligation(evaluation.Obligations, "task_control") {
		t.Fatalf("deny evaluation missing task_control obligation: %#v", evaluation.Obligations)
	}
}

func containsRule(rules []string, expected string) bool {
	for _, rule := range rules {
		if rule == expected || strings.HasSuffix(rule, "/"+expected) {
			return true
		}
	}
	return false
}

func hasTestObligation(obligations []types.Obligation, expected string) bool {
	for _, obligation := range obligations {
		if obligation.Type == expected {
			return true
		}
	}
	return false
}

func minimalBundle(rules []Rule) Bundle {
	return Bundle{
		Version:  1,
		Status:   "test",
		IssuedAt: time.Date(2026, 4, 24, 0, 0, 0, 0, time.UTC),
		Rules:    rules,
		InputPolicy: InputPolicy{
			SecretMode: "secret_handle",
		},
		ResourcePolicy: ResourcePolicy{
			SecretHandleScope: "session_task",
		},
	}
}

func celCond(expression string) Condition {
	return Condition{
		Language:   "cel",
		Expression: expression,
	}
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse time: %v", err)
	}
	return parsed
}
