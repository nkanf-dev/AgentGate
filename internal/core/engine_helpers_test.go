package core

import (
	"testing"
	"time"

	"github.com/agentgate/agentgate/internal/scanner"
	"github.com/agentgate/agentgate/internal/types"
)

func TestNormalizeSessionFactsNilSlices(t *testing.T) {
	facts := types.SessionFacts{}
	normalized := normalizeSessionFacts(facts)
	if normalized.DistinctTargets == nil {
		t.Fatal("DistinctTargets should not be nil after normalization")
	}
	if normalized.DistinctTools == nil {
		t.Fatal("DistinctTools should not be nil after normalization")
	}
	if normalized.DistinctReasonCodes == nil {
		t.Fatal("DistinctReasonCodes should not be nil after normalization")
	}
	if normalized.SideEffectSequence == nil {
		t.Fatal("SideEffectSequence should not be nil after normalization")
	}
}

func TestNormalizeSessionFactsPreservesValues(t *testing.T) {
	facts := types.SessionFacts{
		DistinctTargets:     []string{"api/a"},
		DistinctTools:       []string{"bash"},
		DistinctReasonCodes: []string{"reason"},
		SideEffectSequence:  []string{"network"},
	}
	normalized := normalizeSessionFacts(facts)
	if len(normalized.DistinctTargets) != 1 || normalized.DistinctTargets[0] != "api/a" {
		t.Fatalf("DistinctTargets not preserved: %v", normalized.DistinctTargets)
	}
}

func TestAddDistinct(t *testing.T) {
	values := addDistinct(nil, "")
	if len(values) != 0 {
		t.Fatal("empty candidate should not be added")
	}

	values = addDistinct(nil, "a")
	if len(values) != 1 || values[0] != "a" {
		t.Fatalf("expected [a], got %v", values)
	}

	values = addDistinct(values, "a")
	if len(values) != 1 {
		t.Fatal("duplicate should not be added")
	}

	values = addDistinct(values, "b")
	if len(values) != 2 {
		t.Fatalf("expected 2 elements, got %d", len(values))
	}

	values = addDistinct(values, "  c  ")
	if len(values) != 3 || values[2] != "c" {
		t.Fatalf("expected trimmed c, got %v", values)
	}
}

func TestAppendCapped(t *testing.T) {
	values := appendCapped(nil, []string{"a", "b", "c"}, 2)
	if len(values) != 2 || values[0] != "b" || values[1] != "c" {
		t.Fatalf("expected capped to last 2, got %v", values)
	}

	values = appendCapped(nil, []string{"a", ""}, 10)
	if len(values) != 1 || values[0] != "a" {
		t.Fatalf("empty strings should be filtered out, got %v", values)
	}

	values = appendCapped(nil, []string{"a", "b"}, 0)
	if len(values) != 2 {
		t.Fatalf("cap of 0 should mean unlimited, got %d", len(values))
	}
}

func TestStringValue(t *testing.T) {
	if result := stringValue("hello"); result != "hello" {
		t.Fatalf("expected 'hello', got %q", result)
	}
	if result := stringValue(42); result != "" {
		t.Fatalf("expected empty string for int, got %q", result)
	}
	if result := stringValue(nil); result != "" {
		t.Fatalf("expected empty string for nil, got %q", result)
	}
}

func TestStringSliceValue(t *testing.T) {
	result := stringSliceValue([]string{"a", "b"})
	if len(result) != 2 || result[0] != "a" {
		t.Fatalf("expected [a b], got %v", result)
	}

	result = stringSliceValue([]interface{}{"x", "y"})
	if len(result) != 2 || result[0] != "x" {
		t.Fatalf("expected [x y] from interface slice, got %v", result)
	}

	result = stringSliceValue(42)
	if result != nil {
		t.Fatalf("expected nil for int, got %v", result)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if result := firstNonEmpty("", "b", "c"); result != "b" {
		t.Fatalf("expected b, got %q", result)
	}
	if result := firstNonEmpty("a", "b"); result != "a" {
		t.Fatalf("expected a, got %q", result)
	}
	if result := firstNonEmpty("", "", ""); result != "" {
		t.Fatalf("expected empty, got %q", result)
	}
}

func TestUpdateSessionFacts(t *testing.T) {
	now := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	event := types.EventEnvelope{
		Effect:  types.EffectAllow,
		Summary: "test_reason",
		Metadata: map[string]interface{}{
			"target_identifier": "api/test",
			"tool":              "bash",
			"side_effects":      []interface{}{"network_egress"},
		},
		OccurredAt: now.Add(-time.Minute),
	}

	facts := updateSessionFacts(types.SessionFacts{}, event, now)
	if facts.RequestCount != 1 {
		t.Fatalf("expected RequestCount=1, got %d", facts.RequestCount)
	}
	if facts.AllowCount != 1 {
		t.Fatalf("expected AllowCount=1, got %d", facts.AllowCount)
	}
	if facts.LastEffect != "allow" {
		t.Fatalf("expected LastEffect=allow, got %q", facts.LastEffect)
	}
	if facts.FirstRequestAt == nil || !facts.FirstRequestAt.Equal(event.OccurredAt) {
		t.Fatalf("expected FirstRequestAt=%v, got %v", event.OccurredAt, facts.FirstRequestAt)
	}
	if facts.LastRequestAt == nil || !facts.LastRequestAt.Equal(now) {
		t.Fatalf("expected LastRequestAt=%v, got %v", now, facts.LastRequestAt)
	}
	if len(facts.DistinctTargets) != 1 || facts.DistinctTargets[0] != "api/test" {
		t.Fatalf("expected DistinctTargets=[api/test], got %v", facts.DistinctTargets)
	}
	if len(facts.DistinctReasonCodes) != 1 || facts.DistinctReasonCodes[0] != "test_reason" {
		t.Fatalf("expected DistinctReasonCodes=[test_reason], got %v", facts.DistinctReasonCodes)
	}
	if len(facts.SideEffectSequence) != 1 || facts.SideEffectSequence[0] != "network_egress" {
		t.Fatalf("expected SideEffectSequence=[network_egress], got %v", facts.SideEffectSequence)
	}
}

func TestUpdateSessionFactsDeny(t *testing.T) {
	now := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	event := types.EventEnvelope{
		Effect: types.EffectDeny,
		Metadata: map[string]interface{}{
			"target_identifier": "api/blocked",
		},
	}

	facts := updateSessionFacts(types.SessionFacts{}, event, now)
	if facts.DenyCount != 1 {
		t.Fatalf("expected DenyCount=1, got %d", facts.DenyCount)
	}
	if facts.AllowCount != 0 {
		t.Fatalf("expected AllowCount=0, got %d", facts.AllowCount)
	}
}

func TestUpdateSessionFactsApproval(t *testing.T) {
	now := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	event := types.EventEnvelope{
		Effect:   types.EffectApprovalRequired,
		Metadata: map[string]interface{}{},
	}

	facts := updateSessionFacts(types.SessionFacts{}, event, now)
	if facts.ApprovalCount != 1 {
		t.Fatalf("expected ApprovalCount=1, got %d", facts.ApprovalCount)
	}
}

func TestRedactAuditString(t *testing.T) {
	det := scanner.RegexDetector{}
	if result := redactAuditString("", det); result != "" {
		t.Fatalf("empty string should stay empty, got %q", result)
	}
	if result := redactAuditString("hello world", det); result != "hello world" {
		t.Fatalf("clean string should not be redacted, got %q", result)
	}
	if result := redactAuditString("sk-1234567890abcdef1234567890abcdef1234567890abcdef", det); result == "sk-1234567890abcdef1234567890abcdef1234567890abcdef" {
		t.Fatal("expected secret-like string to be redacted")
	}
}

func TestIsSensitiveAuditKey(t *testing.T) {
	sensitive := []string{"secret", "SECRET", "Secret", "token", "TOKEN", "api_key", "API_KEY", "Api-Key", "password", "PASSWORD", "authorization", "access_token", "refresh_token"}
	for _, key := range sensitive {
		if !isSensitiveAuditKey(key) {
			t.Fatalf("expected %q to be sensitive", key)
		}
	}
	notSensitive := []string{"name", "id", "description", "user_id", "host_id"}
	for _, key := range notSensitive {
		if isSensitiveAuditKey(key) {
			t.Fatalf("expected %q to not be sensitive", key)
		}
	}
}

func TestDecisionSummary(t *testing.T) {
	tests := map[string]string{
		"input_secret_rewritten_to_handles":   "Input contained secret-like material",
		"policy_allow_with_audit":             "Policy allowed the request with audit.",
		"secret_handle_resolve_allowed":       "SecretHandle scope matched",
		"secret_handle_not_found":             "SecretHandle was not found.",
		"secret_handle_scope_mismatch":        "SecretHandle exists",
		"missing_task_id":                     "task_id is required",
		"runtime_high_risk_requires_approval": "requires an attempt-scoped approval",
		"unknown_reason_code":                 "unknown_reason_code",
	}
	for code, expectedSubstring := range tests {
		summary := decisionSummary(code)
		if !containsSubstring(summary, expectedSubstring) {
			t.Fatalf("decisionSummary(%q) = %q, unexpected", code, summary)
		}
	}
}

func TestInferSurface(t *testing.T) {
	tests := map[types.RequestKind]types.Surface{
		types.RequestKindInput:             types.SurfaceInput,
		types.RequestKindInitialEnvelope:   types.SurfaceInput,
		types.RequestKindToolAttempt:       types.SurfaceRuntime,
		types.RequestKindEnvelopeAmendment: types.SurfaceRuntime,
		types.RequestKindResourceEgress:    types.SurfaceResource,
		types.RequestKindResourceAccess:    types.SurfaceResource,
	}
	for kind, expected := range tests {
		if result := inferSurface(kind); result != expected {
			t.Fatalf("inferSurface(%q) = %q, expected %q", kind, result, expected)
		}
	}

	if result := inferSurface("unknown"); result != "" {
		t.Fatalf("inferSurface(unknown) = %q, expected empty", result)
	}
}

func TestRedactAuditValue(t *testing.T) {
	det := scanner.RegexDetector{}
	result, changed := redactAuditValue(map[string]interface{}{
		"name":   "test",
		"secret": "sk-sensitive",
	}, det)
	if !changed {
		t.Fatal("expected redaction")
	}
	m, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if m["secret"] != "[REDACTED]" {
		t.Fatalf("expected [REDACTED], got %v", m["secret"])
	}
	if m["name"] != "test" {
		t.Fatalf("expected name preserved, got %v", m["name"])
	}
}

func TestRedactAuditValueNoChange(t *testing.T) {
	det := scanner.RegexDetector{}
	_, changed := redactAuditValue(map[string]interface{}{
		"name": "test",
		"id":   "123",
	}, det)
	if changed {
		t.Fatal("expected no redaction")
	}
}

func containsSubstring(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
