package policy

import (
	"time"

	"github.com/agentgate/agentgate/internal/types"
)

func CorePolicyBundle() Bundle {
	return Bundle{
		BundleID: "core",
		Name:     "AgentGate Core Policy",
		Priority: 0,
		Status:   BundleStatusActive,
		Version:  1,
		IssuedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		InputPolicy: InputPolicy{
			SecretMode: "secret_handle",
		},
		ResourcePolicy: ResourcePolicy{
			SecretHandleScope: "session_task",
		},
		Rules: []Rule{
			{
				ID:           "core.default_deny",
				Description:  "Catch-all deny when no other rule matches.",
				Priority:     0,
				Surface:      types.Surface("*"),
				RequestKinds: []types.RequestKind{types.RequestKind("*")},
				Effect:       types.EffectDeny,
				ReasonCode:   "policy_no_matching_rule",
				When:         Condition{Language: "cel", Expression: "true"},
			},
			{
				ID:           "resource.unsupported_target",
				Description:  "Only secret_handle targets are supported on the resource surface.",
				Priority:     10000,
				Surface:      types.SurfaceResource,
				RequestKinds: []types.RequestKind{types.RequestKindResourceAccess},
				Effect:       types.EffectDeny,
				ReasonCode:   "resource_access_unsupported_target",
				When:         Condition{Language: "cel", Expression: `target.kind != "secret_handle"`},
			},
		},
	}
}
