package policy

import (
	"testing"
	"time"

	"github.com/agentgate/agentgate/internal/types"
)

func TestCompileCELConditionValid(t *testing.T) {
	tests := []string{
		`action.tool == "bash"`,
		`request_kind == "tool_attempt"`,
		`surface == "runtime"`,
		`actor.user_id == "test"`,
		`action.tool == "bash" && surface == "runtime"`,
		`action.open_world == true`,
		`session_facts.request_count > 3`,
		`"bash" in action.side_effects`,
	}
	for _, expr := range tests {
		t.Run(expr, func(t *testing.T) {
			if err := compileCELCondition(expr); err != nil {
				t.Fatalf("compileCELCondition(%q): %v", expr, err)
			}
		})
	}
}

func TestCompileCELConditionInvalid(t *testing.T) {
	tests := []string{
		"undefined_var == true",
	}
	for _, expr := range tests {
		t.Run(expr, func(t *testing.T) {
			if err := compileCELCondition(expr); err == nil {
				t.Fatalf("expected error for %q", expr)
			}
		})
	}
}

func TestCompileCELConditionNonBool(t *testing.T) {
	err := compileCELCondition(`"hello"`)
	if err == nil {
		t.Fatal("expected error for non-bool expression")
	}
}

func TestEvaluateCELConditionBasic(t *testing.T) {
	req := types.PolicyRequest{
		RequestKind: types.RequestKindToolAttempt,
		Action: types.ActionContext{
			Tool: "bash",
		},
	}
	req.Context.Surface = types.SurfaceRuntime

	result, err := evaluateCELCondition(`action.tool == "bash"`, req, types.SessionFacts{})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !result {
		t.Fatal("expected true")
	}

	result, err = evaluateCELCondition(`action.tool == "read"`, req, types.SessionFacts{})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result {
		t.Fatal("expected false")
	}
}

func TestEvaluateCELConditionSessionFacts(t *testing.T) {
	req := types.PolicyRequest{
		RequestKind: types.RequestKindToolAttempt,
	}
	req.Context.Surface = types.SurfaceRuntime

	facts := types.SessionFacts{
		RequestCount: 5,
		DenyCount:    2,
		DistinctTools: []string{"bash", "read"},
	}

	result, err := evaluateCELCondition(`session_facts.request_count > 3`, req, facts)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !result {
		t.Fatal("expected true for request_count > 3")
	}

	result, err = evaluateCELCondition(`session_facts.deny_count > 5`, req, facts)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result {
		t.Fatal("expected false for deny_count > 5")
	}
}

func TestEvaluateCELConditionInvalidExpr(t *testing.T) {
	req := types.PolicyRequest{}
	_, err := evaluateCELCondition(`invalid+++`, req, types.SessionFacts{})
	if err == nil {
		t.Fatal("expected error for invalid expression")
	}
}

func TestTimeString(t *testing.T) {
	if result := timeString(nil); result != "" {
		t.Fatalf("expected empty string for nil, got %q", result)
	}
	zero := time.Time{}
	if result := timeString(&zero); result != "" {
		t.Fatalf("expected empty string for zero time, got %q", result)
	}
	now := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	result := timeString(&now)
	if result == "" {
		t.Fatal("expected non-empty string for valid time")
	}
}

func TestDataClassStrings(t *testing.T) {
	result := dataClassStrings([]types.DataClass{types.DataClassSecret, types.DataClassPII})
	if len(result) != 2 || result[0] != "secret" || result[1] != "pii" {
		t.Fatalf("unexpected data class strings: %v", result)
	}
}

func TestTaintStrings(t *testing.T) {
	result := taintStrings([]types.Taint{types.TaintUntrustedExternal, types.TaintSecretBearing})
	if len(result) != 2 || result[0] != "untrusted_external" {
		t.Fatalf("unexpected taint strings: %v", result)
	}
}
