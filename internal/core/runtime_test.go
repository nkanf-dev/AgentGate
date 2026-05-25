package core

import (
	"context"
	"testing"
	"time"

	"github.com/agentgate/agentgate/internal/types"
)

func TestIntegrationHealthMatchesByIntegrationIDOnly(t *testing.T) {
	engine := NewEngine(WithStateStore(newMemoryStateStore()))

	definition, err := engine.SaveIntegration(context.Background(), types.IntegrationDefinition{
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

	_, err = engine.RegisterAdapter(context.Background(), types.AdapterRegistration{
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

	result, err := engine.GetIntegration(context.Background(), "openclaw-main")
	if err != nil {
		t.Fatalf("get integration: %v", err)
	}
	if result.Health.Status != types.IntegrationHealthMissing {
		t.Fatalf("adapter_id fallback should not match, got status %q", result.Health.Status)
	}
	if len(result.MatchedAdapters) != 0 {
		t.Fatalf("expected no fallback matches, got %#v", result.MatchedAdapters)
	}

	_, err = engine.RegisterAdapter(context.Background(), types.AdapterRegistration{
		AdapterID:     "openclaw-main-01",
		IntegrationID: "openclaw-main",
		AdapterKind:   "host_plugin",
		Host:          types.HostDescriptor{Kind: "openclaw"},
		Surfaces:      []types.Surface{types.SurfaceInput, types.SurfaceRuntime},
		Capabilities: types.AdapterCapabilities{
			CanBlock:           true,
			CanRewriteInput:    true,
			CanRewriteToolArgs: true,
		},
	})
	if err != nil {
		t.Fatalf("register matching adapter: %v", err)
	}

	result, err = engine.GetIntegration(context.Background(), "openclaw-main")
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

	_, err := engine.SaveIntegration(context.Background(), types.IntegrationDefinition{
		ID:      "disabled-int",
		Name:    "Disabled",
		Kind:    "adapter",
		Enabled: false,
	})
	if err != nil {
		t.Fatalf("save disabled: %v", err)
	}

	disabled, err := engine.GetIntegration(context.Background(), "disabled-int")
	if err != nil {
		t.Fatalf("get disabled: %v", err)
	}
	if disabled.Health.Status != types.IntegrationHealthDisabled {
		t.Fatalf("disabled status = %q, want disabled", disabled.Health.Status)
	}

	_, err = engine.SaveIntegration(context.Background(), types.IntegrationDefinition{
		ID:      "enabled-int",
		Name:    "Enabled",
		Kind:    "adapter",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("save enabled: %v", err)
	}
	enabled, err := engine.GetIntegration(context.Background(), "enabled-int")
	if err != nil {
		t.Fatalf("get enabled: %v", err)
	}
	if enabled.Health.Status != types.IntegrationHealthMissing {
		t.Fatalf("enabled without adapter status = %q, want missing", enabled.Health.Status)
	}
}

func TestRuntimeApprovalUsesIntegrationApprovalChannel(t *testing.T) {
	engine := NewEngine(WithStateStore(newMemoryStateStore()))

	_, err := engine.SaveIntegration(context.Background(), types.IntegrationDefinition{
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
	_, err = engine.RegisterAdapter(context.Background(), types.AdapterRegistration{
		AdapterID:     "openclaw-main-01",
		IntegrationID: "openclaw-main",
		AdapterKind:   "host_plugin",
		Host:          types.HostDescriptor{Kind: "openclaw"},
		Surfaces:      []types.Surface{types.SurfaceInput, types.SurfaceRuntime},
		Capabilities: types.AdapterCapabilities{
			CanBlock:           true,
			CanRewriteInput:    true,
			CanRewriteToolArgs: true,
		},
	})
	if err != nil {
		t.Fatalf("register adapter: %v", err)
	}

	resultCh := make(chan types.PolicyDecision, 1)
	errCh := make(chan error, 1)
	go func() {
		dec, err := engine.Decide(context.Background(), types.PolicyRequest{
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
			errCh <- err
			return
		}
		resultCh <- dec
	}()

	approvalID := waitForPendingApprovalID(t, engine)
	approval := testApprovals(engine).SnapshotApprovals(context.Background())[approvalID]
	if approval.Channel != "approval-feishu" {
		t.Fatalf("approval channel = %q, want approval-feishu", approval.Channel)
	}
	if _, err := engine.ResolveApproval(context.Background(), approvalID, types.ApprovalResolveRequest{Decision: "deny"}); err != nil {
		t.Fatalf("resolve approval: %v", err)
	}
	select {
	case err := <-errCh:
		t.Fatalf("decide: %v", err)
	case dec := <-resultCh:
		if dec.Disposition != types.DispositionDeny {
			t.Fatalf("disposition = %q, want deny", dec.Disposition)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for decision")
	}
}
