package store

import (
	"context"
	"testing"
	"time"

	"github.com/agentgate/agentgate/internal/policy"
	"github.com/agentgate/agentgate/internal/types"
)

func TestSQLiteStoreEventEnvelopeRoundTrip(t *testing.T) {
	store, err := OpenSQLite(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	first := types.EventEnvelope{
		EventID:    "evt_1",
		EventType:  "policy_decision",
		RequestID:  "req_1",
		DecisionID: "dec_1",
		SessionID:  "sess_1",
		AdapterID:  "adapter_1",
		Surface:    types.SurfaceInput,
		Effect:     types.EffectAllowWithAudit,
		Summary:    "input_secret_rewritten_to_handles",
		Metadata: map[string]interface{}{
			"request_kind": "input",
			"obligations":  []interface{}{"audit_event", "rewrite_input"},
		},
		OccurredAt: time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC),
	}
	second := types.EventEnvelope{
		EventID:    "evt_2",
		EventType:  "adapter_report",
		RequestID:  "req_1",
		Surface:    types.SurfaceInput,
		Summary:    "input_hook_decided",
		Metadata:   map[string]interface{}{},
		OccurredAt: time.Date(2026, 4, 29, 12, 1, 0, 0, time.UTC),
	}

	if err := store.AppendEvent(first); err != nil {
		t.Fatalf("append first event: %v", err)
	}
	if err := store.AppendEvent(second); err != nil {
		t.Fatalf("append second event: %v", err)
	}

	events, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].EventID != "evt_1" || events[1].EventID != "evt_2" {
		t.Fatalf("events should be returned oldest-to-newest, got %q then %q", events[0].EventID, events[1].EventID)
	}
	if events[0].Metadata["request_kind"] != "input" {
		t.Fatalf("metadata did not round trip: %#v", events[0].Metadata)
	}
	if events[0].Surface != types.SurfaceInput || events[0].Effect != types.EffectAllowWithAudit {
		t.Fatalf("surface/effect did not round trip: %#v", events[0])
	}
	decisionEvent, found, err := store.GetEventByDecisionID("dec_1")
	if err != nil {
		t.Fatalf("get decision event: %v", err)
	}
	if !found || decisionEvent.EventID != "evt_1" {
		t.Fatalf("decision event lookup failed: found=%v event=%#v", found, decisionEvent)
	}
}

func TestSQLiteStoreSessionFactsRoundTrip(t *testing.T) {
	store, err := OpenSQLite(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	now := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	first := now.Add(-time.Minute)
	record := types.SessionFactsRecord{
		SessionID: "sess_facts",
		AdapterID: "openclaw-main",
		UpdatedAt: now,
		Facts: types.SessionFacts{
			RequestCount:        2,
			DenyCount:           1,
			ApprovalCount:       1,
			DistinctTargets:     []string{"api/a", "api/b"},
			DistinctTools:       []string{"bash"},
			DistinctReasonCodes: []string{"runtime_high_risk_requires_approval"},
			SideEffectSequence:  []string{"network_egress"},
			LastEffect:          "approval_required",
			LastRequestAt:       &now,
			FirstRequestAt:      &first,
		},
	}
	if err := store.UpsertSessionFacts(record); err != nil {
		t.Fatalf("upsert session facts: %v", err)
	}
	got, found, err := store.GetSessionFacts("sess_facts")
	if err != nil {
		t.Fatalf("get session facts: %v", err)
	}
	if !found {
		t.Fatal("expected session facts")
	}
	if got.Facts.RequestCount != 2 || got.Facts.DenyCount != 1 || len(got.Facts.DistinctTargets) != 2 {
		t.Fatalf("facts did not round trip: %#v", got)
	}
	if got.Facts.LastRequestAt == nil || !got.Facts.LastRequestAt.Equal(now) {
		t.Fatalf("last_request_at did not round trip: %#v", got.Facts.LastRequestAt)
	}
	if err := store.UpdateSessionFacts("sess_facts", func(existing types.SessionFactsRecord, found bool) (types.SessionFactsRecord, error) {
		if !found {
			t.Fatal("expected existing session facts in update callback")
		}
		existing.Facts.RequestCount++
		existing.Facts.SideEffectSequence = append(existing.Facts.SideEffectSequence, "filesystem_write")
		existing.UpdatedAt = now.Add(time.Minute)
		return existing, nil
	}); err != nil {
		t.Fatalf("update session facts: %v", err)
	}
	updated, found, err := store.GetSessionFacts("sess_facts")
	if err != nil {
		t.Fatalf("get updated session facts: %v", err)
	}
	if !found || updated.Facts.RequestCount != 3 || len(updated.Facts.SideEffectSequence) != 2 {
		t.Fatalf("updated facts did not persist: found=%v record=%#v", found, updated)
	}
}

func TestSQLiteStoreStateRoundTrip(t *testing.T) {
	store, err := OpenSQLite(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	now := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	registration := types.AdapterRegistration{
		AdapterID:     "openclaw-test",
		IntegrationID: "openclaw-main",
		AdapterKind:   "host_plugin",
		Host:          types.HostDescriptor{Kind: "openclaw", Version: "test"},
		Surfaces:      []types.Surface{types.SurfaceInput, types.SurfaceRuntime},
		Capabilities: types.AdapterCapabilities{
			CanBlock:            true,
			CanRewriteInput:     true,
			CanRewriteToolArgs:  true,
			CanPauseForApproval: true,
		},
	}
	if err := store.UpsertAdapterRegistration(registration, now, now); err != nil {
		t.Fatalf("upsert adapter: %v", err)
	}
	adapters, err := store.ListAdapterRegistrations()
	if err != nil {
		t.Fatalf("list adapters: %v", err)
	}
	if len(adapters) != 1 || adapters[0].AdapterID != registration.AdapterID {
		t.Fatalf("adapter did not round trip: %#v", adapters)
	}
	if adapters[0].IntegrationID != "openclaw-main" {
		t.Fatalf("adapter integration_id did not round trip: %#v", adapters[0])
	}

	definition := types.IntegrationDefinition{
		ID:               "openclaw-main",
		Name:             "OpenClaw main adapter",
		Kind:             "adapter",
		Enabled:          true,
		ExpectedSurfaces: []types.Surface{types.SurfaceInput, types.SurfaceRuntime},
	}
	if err := store.SaveIntegrationDefinition(definition, now); err != nil {
		t.Fatalf("save integration definition: %v", err)
	}
	foundDefinition, found, err := store.GetIntegrationDefinition("openclaw-main")
	if err != nil {
		t.Fatalf("get integration definition: %v", err)
	}
	if !found || foundDefinition.ID != definition.ID || !foundDefinition.Enabled {
		t.Fatalf("integration definition did not round trip: found=%v definition=%#v", found, foundDefinition)
	}
	definitions, err := store.ListIntegrationDefinitions()
	if err != nil {
		t.Fatalf("list integration definitions: %v", err)
	}
	if len(definitions) != 1 || definitions[0].ID != definition.ID {
		t.Fatalf("unexpected integration definitions: %#v", definitions)
	}

	approval := types.ApprovalRecord{
		ApprovalID: "appr_1",
		RequestID:  "req_1",
		SessionID:  "sess_1",
		TaskID:     "task_1",
		AttemptID:  "attempt_1",
		Status:     types.ApprovalPending,
		Reason:     "runtime_high_risk_requires_approval",
		CreatedAt:  now,
		ExpiresAt:  now.Add(10 * time.Minute),
	}
	if err := store.SaveApproval(approval); err != nil {
		t.Fatalf("save approval: %v", err)
	}
	foundApproval, found, err := store.GetApproval("appr_1")
	if err != nil {
		t.Fatalf("get approval: %v", err)
	}
	if !found || foundApproval.AttemptID != approval.AttemptID {
		t.Fatalf("approval did not round trip: found=%v approval=%#v", found, foundApproval)
	}
	approvals, err := store.ListApprovals(10)
	if err != nil {
		t.Fatalf("list approvals: %v", err)
	}
	if len(approvals) != 1 {
		t.Fatalf("expected one approval, got %d", len(approvals))
	}

	if err := store.SaveAttemptGrant("sess_1", "task_1", "attempt_1", "appr_1", approval.ExpiresAt); err != nil {
		t.Fatalf("save grant: %v", err)
	}
	grant, found, err := store.GetAttemptGrant("sess_1", "task_1", "attempt_1")
	if err != nil {
		t.Fatalf("get grant: %v", err)
	}
	if !found || grant.ApprovalID != "appr_1" {
		t.Fatalf("grant did not round trip: found=%v grant=%#v", found, grant)
	}

	handle := types.SecretHandle{
		HandleID:    "sech_1",
		SessionID:   "sess_1",
		TaskID:      "task_1",
		Kind:        "api_key",
		Placeholder: "[SECRET_HANDLE:1]",
		SecretHash:  "sha256:test",
		CreatedAt:   now,
	}
	if err := store.SaveSecretHandle(handle, "sk-test-value"); err != nil {
		t.Fatalf("save secret handle: %v", err)
	}
	foundHandle, value, found, err := store.GetSecretHandle("sech_1")
	if err != nil {
		t.Fatalf("get secret handle: %v", err)
	}
	if !found || foundHandle.SecretHash != handle.SecretHash || value != "sk-test-value" {
		t.Fatalf("secret handle did not round trip: found=%v handle=%#v value=%q", found, foundHandle, value)
	}
}

func TestSQLiteStorePolicyVersionLifecycle(t *testing.T) {
	store, err := OpenSQLite(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	first := policy.DefaultBundle()
	first.Version = 1
	first.IssuedAt = time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	if _, err := store.SavePolicyVersion(first, "bootstrap", "initial", 0, first.IssuedAt); err != nil {
		t.Fatalf("save first policy: %v", err)
	}

	second := policy.DefaultBundle()
	second.Version = 2
	second.Status = "active"
	second.IssuedAt = first.IssuedAt.Add(time.Minute)
	second.Rules = append(second.Rules, policy.Rule{
		ID:           "runtime.bash.deny",
		Priority:     200,
		Surface:      types.SurfaceRuntime,
		RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
		Effect:       types.EffectDeny,
		ReasonCode:   "runtime_bash_denied",
		When:         policy.Condition{Language: "cel", Expression: `action.tool == "bash"`},
	})
	if _, err := store.SavePolicyVersion(second, "admin", "deny bash", 0, second.IssuedAt); err != nil {
		t.Fatalf("save second policy: %v", err)
	}

	active, record, found, err := store.GetActivePolicyBundle()
	if err != nil {
		t.Fatalf("get active policy: %v", err)
	}
	if !found || active.Version != 2 || !record.Active {
		t.Fatalf("active policy did not round trip: found=%v bundle=%#v record=%#v", found, active, record)
	}

	versions, err := store.ListPolicyVersions(10)
	if err != nil {
		t.Fatalf("list versions: %v", err)
	}
	if len(versions) != 2 || versions[0].Version != 2 || !versions[0].Active || versions[1].Active {
		t.Fatalf("unexpected versions: %#v", versions)
	}

	versionOne, _, found, err := store.GetPolicyBundleVersion(1)
	if err != nil {
		t.Fatalf("get version 1: %v", err)
	}
	if !found || versionOne.Version != 1 {
		t.Fatalf("version 1 did not round trip: found=%v bundle=%#v", found, versionOne)
	}
}
