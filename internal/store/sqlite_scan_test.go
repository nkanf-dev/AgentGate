package store

import (
	"context"
	"testing"
	"time"

	"github.com/agentgate/agentgate/internal/types"
)

var testTime = time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
var testExpiry = 10 * time.Minute

func TestScanApprovalPending(t *testing.T) {
	store, err := OpenSQLite(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	approval := types.ApprovalRecord{
		ApprovalID: "appr_scan",
		RequestID:  "req_1",
		SessionID:  "sess_1",
		TaskID:     "task_1",
		AttemptID:  "attempt_1",
		Status:     types.ApprovalPending,
		Reason:     "runtime_high_risk",
		CreatedAt:  testTime,
		ExpiresAt:  testTime.Add(testExpiry),
	}
	if err := store.SaveApproval(approval); err != nil {
		t.Fatalf("save approval: %v", err)
	}

	found, foundOk, err := store.GetApproval("appr_scan")
	if err != nil {
		t.Fatalf("get approval: %v", err)
	}
	if !foundOk {
		t.Fatal("approval not found")
	}
	if found.Status != types.ApprovalPending {
		t.Fatalf("expected pending, got %s", found.Status)
	}
	if found.AttemptID != "attempt_1" {
		t.Fatalf("expected attempt_1, got %s", found.AttemptID)
	}
	if found.ExpiresAt.Unix() != approval.ExpiresAt.Unix() {
		t.Fatalf("expires_at mismatch: %v vs %v", found.ExpiresAt, approval.ExpiresAt)
	}
}

func TestSaveAttemptGrantAndGet(t *testing.T) {
	store, err := OpenSQLite(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	if err := store.SaveAttemptGrant("sess_g", "task_g", "att_g", "appr_g", testTime.Add(testExpiry)); err != nil {
		t.Fatalf("save grant: %v", err)
	}

	grant, found, err := store.GetAttemptGrant("sess_g", "task_g", "att_g")
	if err != nil {
		t.Fatalf("get grant: %v", err)
	}
	if !found {
		t.Fatal("grant not found")
	}
	if grant.ApprovalID != "appr_g" {
		t.Fatalf("expected appr_g, got %s", grant.ApprovalID)
	}

	_, found, err = store.GetAttemptGrant("sess_g", "task_g", "nonexistent")
	if err != nil {
		t.Fatalf("get nonexistent grant: %v", err)
	}
	if found {
		t.Fatal("unexpected grant found")
	}
}

func TestListApprovalsEmpty(t *testing.T) {
	store, err := OpenSQLite(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	approvals, err := store.ListApprovals(10)
	if err != nil {
		t.Fatalf("list approvals: %v", err)
	}
	if len(approvals) != 0 {
		t.Fatalf("expected empty list, got %d", len(approvals))
	}
}

func TestGetApprovalNotFound(t *testing.T) {
	store, err := OpenSQLite(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	_, found, err := store.GetApproval("nonexistent")
	if err != nil {
		t.Fatalf("get nonexistent approval: %v", err)
	}
	if found {
		t.Fatal("unexpected approval found")
	}
}

func TestGetIntegrationDefinitionNotFound(t *testing.T) {
	store, err := OpenSQLite(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	_, found, err := store.GetIntegrationDefinition("nonexistent")
	if err != nil {
		t.Fatalf("get nonexistent integration: %v", err)
	}
	if found {
		t.Fatal("unexpected integration found")
	}
}

func TestEmptyListIntegrationDefinitions(t *testing.T) {
	store, err := OpenSQLite(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	definitions, err := store.ListIntegrationDefinitions()
	if err != nil {
		t.Fatalf("list integrations: %v", err)
	}
	if len(definitions) != 0 {
		t.Fatalf("expected empty list, got %d", len(definitions))
	}
}

func TestListPolicyBundlesEmpty(t *testing.T) {
	store, err := OpenSQLite(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	bundles, err := store.ListPolicyBundles(false)
	if err != nil {
		t.Fatalf("list bundles: %v", err)
	}
	if len(bundles) != 0 {
		t.Fatalf("expected empty list, got %d", len(bundles))
	}
}

func TestListPolicyVersionsEmpty(t *testing.T) {
	store, err := OpenSQLite(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	versions, err := store.ListPolicyVersions(10)
	if err != nil {
		t.Fatalf("list versions: %v", err)
	}
	if len(versions) != 0 {
		t.Fatalf("expected empty list, got %d", len(versions))
	}
}

func TestListEventsEmpty(t *testing.T) {
	store, err := OpenSQLite(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	events, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected empty list, got %d", len(events))
	}
}

func TestGetActivePolicyBundleEmpty(t *testing.T) {
	store, err := OpenSQLite(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	_, _, found, err := store.GetActivePolicyBundle()
	if err != nil {
		t.Fatalf("get active policy: %v", err)
	}
	if found {
		t.Fatal("unexpected active policy in empty store")
	}
}
