package scanner

import "github.com/agentgate/agentgate/internal/types"

// FindingsToTaints maps detector outputs to semantic taint labels.
//
// TaintUntrustedExternal is NOT handled here — it is a source-level annotation
// set by engine.Decide() based on surface/context, not by content detection.
func FindingsToTaints(
	secrets []SecretFinding,
	injections []InjectionFinding,
) []types.Taint {
	var taints []types.Taint
	if len(secrets) > 0 {
		taints = appendTaintOnce(taints, types.TaintSecretBearing)
	}
	for _, f := range injections {
		switch f.Kind {
		case "prompt_injection", "role_play":
			taints = appendTaintOnce(taints, types.TaintPossibleInjection)
		case "embedded_instruction":
			taints = appendTaintOnce(taints, types.TaintEmbeddedInstruction)
		}
	}
	return taints
}

func appendTaintOnce(taints []types.Taint, t types.Taint) []types.Taint {
	for _, existing := range taints {
		if existing == t {
			return taints
		}
	}
	return append(taints, t)
}
