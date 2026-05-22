package core

import (
	"testing"

	"github.com/agentgate/agentgate/internal/types"
)

func TestIntegrationHealthMatchesByIntegrationIDOnly(t *testing.T) {
	engine := NewEngine(WithStateStore(newMemoryStateStore()))

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
		t.Fatalf("get integration again: %v", err)
	}
	if result.Health.Status != types.IntegrationHealthConnected {
		t.Fatalf("integration status = %q, want connected", result.Health.Status)
	}
	if len(result.MatchedAdapters) != 1 {
		t.Fatalf("expected 1 matched adapter, got %d", len(result.MatchedAdapters))
	}
}

func TestIntegrationHealthDisabledAndMissing(t *testing.T) {
	engine := NewEngine(WithStateStore(newMemoryStateStore()))

	_, err := engine.SaveIntegration(types.IntegrationDefinition{
		ID:      "disabled-int",
		Name:    "Disabled",
		Kind:    "adapter",
		Enabled: false,
	})
	if err != nil {
		t.Fatalf("save disabled: %v", err)
	}

	disabled, err := engine.GetIntegration("disabled-int")
	if err != nil {
		t.Fatalf("get disabled: %v", err)
	}
	if disabled.Health.Status != types.IntegrationHealthDisabled {
		t.Fatalf("disabled status = %q, want disabled", disabled.Health.Status)
	}

	_, err = engine.SaveIntegration(types.IntegrationDefinition{
		ID:      "enabled-int",
		Name:    "Enabled",
		Kind:    "adapter",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("save enabled: %v", err)
	}
	enabled, err := engine.GetIntegration("enabled-int")
	if err != nil {
		t.Fatalf("get enabled: %v", err)
	}
	if enabled.Health.Status != types.IntegrationHealthMissing {
		t.Fatalf("enabled without adapter status = %q, want missing", enabled.Health.Status)
	}
}

func TestRuntimeApprovalUsesIntegrationApprovalChannel(t *testing.T) {
	engine := NewEngine(WithStateStore(newMemoryStateStore()))

	_, err := engine.SaveIntegration(types.IntegrationDefinition{
		ID:               "openclaw-main",
		Name:             "OpenClaw main adapter",
		Kind:             "adapter",
		Enabled:          true,
		ApprovalChannel:  "approval-feishu",
		ExpectedSurfaces: []types.Surface{types.SurfaceInput, types.SurfaceRuntime},
	})
	if err != nil {
		t.Fatalf("save integration: %v", err)
	}

	// Register adapter
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
		t.Fatalf("register adapter: %v", err)
	}

	dec, err := engine.Decide(types.PolicyRequest{
		RequestID:   "req_approval_channel",
		RequestKind: types.RequestKindToolAttempt,
		Actor:       types.ActorContext{UserID: "u1", HostID: "openclaw"},
		Session:     types.SessionContext{SessionID: "sess_1", TaskID: "task_1", AttemptID: "att_1"},
		Action: types.ActionContext{
			Tool:        "bash",
			Operation:   "execute",
			SideEffects: []types.SideEffect{types.SideEffectProcessSpawn},
		},
		Target:  types.TargetContext{Kind: "process", Identifier: "shell"},
		Context: types.DecisionContext{Surface: types.SurfaceRuntime},
		Policy: map[string]interface{}{
			"integration_id": "openclaw-main",
		},
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}

	if dec.Effect != types.EffectApprovalRequired {
		t.Fatalf("effect = %q, want approval_required", dec.Effect)
	}

	var channel string
	for _, ob := range dec.Obligations {
		if ob.Type == types.ObligationApprovalRequest {
			channel = ob.Params["channel"].(string)
		}
	}

	if channel != "approval-feishu" {
		t.Fatalf("approval channel = %q, want approval-feishu", channel)
	}
}
