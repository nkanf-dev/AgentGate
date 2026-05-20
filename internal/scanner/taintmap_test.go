package scanner

import (
	"testing"

	"github.com/agentgate/agentgate/internal/types"
)

func TestFindingsToTaintsSecretToSecretBearing(t *testing.T) {
	taints := FindingsToTaints(
		[]SecretFinding{{Kind: "openai_api_key"}},
		nil,
	)
	if len(taints) != 1 || taints[0] != types.TaintSecretBearing {
		t.Fatalf("expected [TaintSecretBearing], got %v", taints)
	}
}

func TestFindingsToTaintsInjectionMapping(t *testing.T) {
	cases := []struct {
		name     string
		kind     string
		expected types.Taint
	}{
		{"prompt_injection", "prompt_injection", types.TaintPossibleInjection},
		{"role_play", "role_play", types.TaintPossibleInjection},
		{"embedded_instruction", "embedded_instruction", types.TaintEmbeddedInstruction},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			taints := FindingsToTaints(nil, []InjectionFinding{{Kind: tc.kind}})
			if len(taints) != 1 || taints[0] != tc.expected {
				t.Fatalf("expected [%s], got %v", tc.expected, taints)
			}
		})
	}
}

func TestFindingsToTaintsDeduplication(t *testing.T) {
	t.Run("multiple secrets one taint", func(t *testing.T) {
		taints := FindingsToTaints(
			[]SecretFinding{{Kind: "openai_api_key"}, {Kind: "generic_api_key"}},
			nil,
		)
		if len(taints) != 1 || taints[0] != types.TaintSecretBearing {
			t.Fatalf("expected [TaintSecretBearing], got %v", taints)
		}
	})
	t.Run("prompt_injection and role_play merge", func(t *testing.T) {
		taints := FindingsToTaints(nil, []InjectionFinding{
			{Kind: "prompt_injection"},
			{Kind: "role_play"},
		})
		if len(taints) != 1 || taints[0] != types.TaintPossibleInjection {
			t.Fatalf("expected [TaintPossibleInjection], got %v", taints)
		}
	})
	t.Run("secret and injection separate", func(t *testing.T) {
		taints := FindingsToTaints(
			[]SecretFinding{{Kind: "openai_api_key"}},
			[]InjectionFinding{{Kind: "embedded_instruction"}},
		)
		if len(taints) != 2 {
			t.Fatalf("expected 2 taints, got %d: %v", len(taints), taints)
		}
		hasSecret := false
		hasEmbedded := false
		for _, t := range taints {
			if t == types.TaintSecretBearing {
				hasSecret = true
			}
			if t == types.TaintEmbeddedInstruction {
				hasEmbedded = true
			}
		}
		if !hasSecret || !hasEmbedded {
			t.Fatalf("expected both TaintSecretBearing and TaintEmbeddedInstruction, got %v", taints)
		}
	})
}

func TestFindingsToTaintsNeverProducesUntrustedExternal(t *testing.T) {
	taints := FindingsToTaints(
		[]SecretFinding{{Kind: "openai_api_key"}},
		[]InjectionFinding{{Kind: "prompt_injection"}, {Kind: "embedded_instruction"}},
	)
	for _, taint := range taints {
		if taint == types.TaintUntrustedExternal {
			t.Fatal("FindingsToTaints should never produce TaintUntrustedExternal")
		}
	}
}

func TestFindingsToTaintsEmpty(t *testing.T) {
	taints := FindingsToTaints(nil, nil)
	if len(taints) != 0 {
		t.Fatalf("expected no taints for empty findings, got %v", taints)
	}
}
