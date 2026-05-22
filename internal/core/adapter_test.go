package core

import (
	"context"
	"errors"
	"testing"

	"github.com/agentgate/agentgate/internal/types"
)

func TestRegisterAdapterRejectsDuplicateSurfaces(t *testing.T) {
	engine := NewEngine()

	_, err := engine.RegisterAdapter(context.Background(), types.AdapterRegistration{
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

	_, err := engine.RegisterAdapter(context.Background(), types.AdapterRegistration{
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

	_, err := engine.RegisterAdapter(context.Background(), types.AdapterRegistration{
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
