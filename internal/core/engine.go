package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agentgate/agentgate/internal/policy"
	"github.com/agentgate/agentgate/internal/scanner"
	"github.com/agentgate/agentgate/internal/types"
)

type Engine struct {
	startedAt time.Time
	mu        sync.RWMutex

	registrations map[string]adapterState
	integrations  map[string]types.IntegrationDefinition
	events        []types.EventEnvelope
	eventStore    EventStore
	stateStore    StateStore
	policyBundle  policy.Bundle
	policyBundles []policy.Bundle
	runtimes      map[string]*managedRuntimeState
	secretHandles map[string]types.SecretHandle
	secretValues  map[string]string
	approvals     map[string]approvalState
	attemptGrants map[string]types.AttemptGrant
	policyHistory map[int]policy.Bundle
	policyRecords []policy.VersionRecord
	detector      scanner.Detector

	maxEvents          int
	eventRetentionDays int
	eventStopCh        chan struct{}
}

type EventStore interface {
	AppendEvent(event types.EventEnvelope) error
	ListEvents(limit int) ([]types.EventEnvelope, error)
	GetEventByDecisionID(decisionID string) (types.EventEnvelope, bool, error)
	PruneEvents(before time.Time) (int64, error)
}

type StateStore interface {
	UpsertAdapterRegistration(registration types.AdapterRegistration, registeredAt time.Time, lastSeenAt time.Time) error
	ListAdapterRegistrations() ([]types.AdapterCoverage, error)
	SaveIntegrationDefinition(definition types.IntegrationDefinition, now time.Time) error
	GetIntegrationDefinition(integrationID string) (types.IntegrationDefinition, bool, error)
	ListIntegrationDefinitions() ([]types.IntegrationDefinition, error)
	DeleteIntegrationDefinition(integrationID string) error
	SaveApproval(approval types.ApprovalRecord) error
	GetApproval(approvalID string) (types.ApprovalRecord, bool, error)
	ListApprovals(limit int) ([]types.ApprovalRecord, error)
	SaveAttemptGrant(sessionID string, taskID string, attemptID string, approvalID string, expiresAt time.Time) error
	GetAttemptGrant(sessionID string, taskID string, attemptID string) (types.AttemptGrant, bool, error)
	SaveSecretHandle(handle types.SecretHandle, value string) error
	GetSecretHandle(handleID string) (types.SecretHandle, string, bool, error)
	SavePolicyVersion(bundle policy.Bundle, publishedBy string, message string, sourceVersion int, publishedAt time.Time) (policy.VersionRecord, error)
	GetActivePolicyBundle() (policy.Bundle, policy.VersionRecord, bool, error)
	GetPolicyBundleVersion(version int) (policy.Bundle, policy.VersionRecord, bool, error)
	ListPolicyVersions(limit int) ([]policy.VersionRecord, error)
	SavePolicyBundle(bundle policy.Bundle) error
	GetPolicyBundle(bundleID string) (policy.Bundle, bool, error)
	ListPolicyBundles(includeArchived bool) ([]policy.Bundle, error)
	ArchivePolicyBundle(bundleID string, updatedAt time.Time) error
	GetSessionFacts(sessionID string) (types.SessionFactsRecord, bool, error)
	UpsertSessionFacts(record types.SessionFactsRecord) error
	UpdateSessionFacts(sessionID string, update func(types.SessionFactsRecord, bool) (types.SessionFactsRecord, error)) error
	ListSecretHandles() ([]types.SecretHandleHydration, error)
	ListAttemptGrants() ([]types.AttemptGrantHydration, error)
}

type Option func(*Engine)

type adapterState struct {
	registration types.AdapterRegistration
	registeredAt time.Time
	lastSeenAt   time.Time
}

type decisionPatch struct {
	effect       types.Effect
	reason       string
	appliedRules []string
	obligations  []types.Obligation
}

type inputSecretFacts struct {
	text     string
	findings []scanner.SecretFinding
}

type approvalState struct {
	ApprovalID string
	RequestID  string
	SessionID  string
	TaskID     string
	AttemptID  string
	Status     types.ApprovalStatus
	Reason     string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ResolvedAt *time.Time
	OperatorID string
	Channel    string
}

type managedRuntimeState struct {
	IntegrationID string
	Worker        string
	Status        string
	RestartCount  int
	LastStartedAt *time.Time
	LastExitedAt  *time.Time
	LastHealthyAt *time.Time
	LastError     string
	Pid           int
	cancel        context.CancelFunc
}

type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	return e.Code + ": " + e.Message
}

type PolicyCurrentResponse struct {
	Bundle policy.Bundle        `json:"bundle"`
	Record policy.VersionRecord `json:"record"`
}

type PolicyValidationResponse struct {
	Valid        bool                  `json:"valid"`
	Errors       []string              `json:"errors,omitempty"`
	Warnings     []string              `json:"warnings,omitempty"`
	Version      int                   `json:"version,omitempty"`
	RuleCount    int                   `json:"rule_count,omitempty"`
	SurfaceRules map[types.Surface]int `json:"surface_rules,omitempty"`
}

type PolicyValidateRequest struct {
	Bundle policy.Bundle `json:"bundle"`
}

type PolicyPublishRequest struct {
	Bundle     policy.Bundle `json:"bundle"`
	OperatorID string        `json:"operator_id,omitempty"`
	Message    string        `json:"message,omitempty"`
}

type PolicyRollbackRequest struct {
	Version    int    `json:"version"`
	OperatorID string `json:"operator_id,omitempty"`
	Message    string `json:"message,omitempty"`
}

type PolicyVersionsResponse struct {
	Versions []policy.VersionRecord `json:"versions"`
}

type PolicyBundlesResponse struct {
	Bundles []policy.Bundle `json:"bundles"`
}

const integrationStaleAfter = 5 * time.Minute

var idCounter atomic.Uint64

func NewEngine(options ...Option) *Engine {
	engine := &Engine{
		startedAt:          time.Now().UTC(),
		registrations:      make(map[string]adapterState),
		integrations:       make(map[string]types.IntegrationDefinition),
		events:             make([]types.EventEnvelope, 0, 128),
		policyBundle:       policy.DefaultBundle(),
		policyBundles:      []policy.Bundle{defaultPolicyBundle(policy.DefaultBundle())},
		runtimes:           make(map[string]*managedRuntimeState),
		secretHandles:      make(map[string]types.SecretHandle),
		secretValues:       make(map[string]string),
		approvals:          make(map[string]approvalState),
		attemptGrants:      make(map[string]types.AttemptGrant),
		policyHistory:      make(map[int]policy.Bundle),
		policyRecords:      make([]policy.VersionRecord, 0, 1),
		detector:           scanner.RegexDetector{},
		maxEvents:          10000,
		eventRetentionDays: 30,
	}
	for _, option := range options {
		option(engine)
	}
	engine.seedPolicyHistory()
	engine.bootstrapManagedRuntimes()
	engine.hydrateFromStore()
	engine.startEventCleanup()
	return engine
}

// hydrateFromStore loads approvals, secret handles, and attempt grants from
// SQLite into memory.  No-op when stateStore is nil.
func (e *Engine) hydrateFromStore() {
	if e.stateStore == nil {
		return
	}

	var approvalCount, handleCount, grantCount int

	// Only pending approvals — expired ones are handled lazily with events.
	const hydrationLimit = 1_000_000
	records, err := e.stateStore.ListApprovals(hydrationLimit)
	if err != nil {
		log.Printf("hydrate: list approvals: %v", err)
	} else {
		for _, rec := range records {
			if rec.Status != types.ApprovalPending {
				continue
			}
			e.approvals[rec.ApprovalID] = approvalRecordToState(rec)
			approvalCount++
		}
	}

	handles, err := e.stateStore.ListSecretHandles()
	if err != nil {
		log.Printf("hydrate: list secret handles: %v", err)
	} else {
		for _, h := range handles {
			e.secretHandles[h.Handle.HandleID] = h.Handle
			e.secretValues[h.Handle.HandleID] = h.Value
			handleCount++
		}
	}

	grants, err := e.stateStore.ListAttemptGrants()
	if err != nil {
		log.Printf("hydrate: list attempt grants: %v", err)
	} else {
		for _, g := range grants {
			key := attemptKey(g.SessionID, g.TaskID, g.AttemptID)
			e.attemptGrants[key] = g.Grant
			grantCount++
		}
	}

	log.Printf("hydrate: loaded %d pending approvals, %d secret handles, %d attempt grants",
		approvalCount, handleCount, grantCount)
}

func WithEventStore(store EventStore) Option {
	return func(engine *Engine) {
		engine.eventStore = store
	}
}

func WithStateStore(store StateStore) Option {
	return func(engine *Engine) {
		engine.stateStore = store
	}
}

func WithPolicyBundle(bundle policy.Bundle) Option {
	return func(engine *Engine) {
		engine.policyBundle = bundle
		engine.policyBundles = []policy.Bundle{defaultPolicyBundle(bundle)}
	}
}

func WithPolicyBundles(bundles []policy.Bundle) Option {
	return func(engine *Engine) {
		engine.policyBundles = clonePolicyBundles(bundles)
		if len(bundles) > 0 {
			engine.policyBundle = aggregateBundles(bundles)
		}
	}
}

func WithDetector(d scanner.Detector) Option {
	return func(engine *Engine) {
		engine.detector = d
	}
}

func WithMaxEvents(n int) Option {
	return func(engine *Engine) {
		if n > 0 {
			engine.maxEvents = n
		}
	}
}

func WithEventRetentionDays(n int) Option {
	return func(engine *Engine) {
		if n > 0 {
			engine.eventRetentionDays = n
		}
	}
}

func (e *Engine) startEventCleanup() {
	if e.eventStore == nil {
		return
	}
	e.eventStopCh = make(chan struct{})
	e.pruneOldEvents()
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				func() {
					defer func() {
						if r := recover(); r != nil {
							log.Printf("prune events: panic: %v", r)
						}
					}()
					e.pruneOldEvents()
				}()
			case <-e.eventStopCh:
				return
			}
		}
	}()
}

func (e *Engine) pruneOldEvents() {
	before := time.Now().UTC().Add(-time.Duration(e.eventRetentionDays) * 24 * time.Hour)
	n, err := e.eventStore.PruneEvents(before)
	if err != nil {
		log.Printf("prune events: %v", err)
		return
	}
	if n > 0 {
		log.Printf("prune events: deleted %d events older than %d days", n, e.eventRetentionDays)
	}
}

func (e *Engine) Close() {
	if e.eventStopCh != nil {
		close(e.eventStopCh)
		e.eventStopCh = nil
	}
}

func (e *Engine) StartedAt() time.Time {
	return e.startedAt
}

func (e *Engine) PolicyStatus() map[string]interface{} {
	e.mu.RLock()
	bundle := e.policyBundle
	e.mu.RUnlock()
	return map[string]interface{}{
		"version":   bundle.Version,
		"status":    bundle.StatusValue(),
		"issued_at": bundle.IssuedAt,
	}
}

func (e *Engine) bootstrapManagedRuntimes() {
	if e.stateStore == nil {
		return
	}
	definitions, err := e.stateStore.ListIntegrationDefinitions()
	if err != nil {
		return
	}
	for _, definition := range definitions {
		normalized, normalizeErr := normalizeIntegrationDefinition(definition)
		if normalizeErr != nil {
			continue
		}
		if err := e.reconcileManagedRuntime(normalized); err != nil {
			e.setRuntimeError(normalized.ID, "bootstrap_failed", err)
		}
	}
}

func (e *Engine) reconcileManagedRuntime(definition types.IntegrationDefinition) error {
	if definition.Runtime == nil || !definition.Runtime.Managed || !definition.Runtime.Enabled || !definition.Enabled {
		e.stopManagedRuntime(definition.ID)
		return nil
	}
	return e.ensureManagedRuntime(definition)
}

func (e *Engine) ensureManagedRuntime(definition types.IntegrationDefinition) error {
	e.mu.RLock()
	current := e.runtimes[definition.ID]
	e.mu.RUnlock()
	if current != nil && (current.Status == "starting" || current.Status == "running") {
		return nil
	}
	return e.startManagedRuntime(definition)
}

func (e *Engine) startManagedRuntime(definition types.IntegrationDefinition) error {
	if definition.Runtime == nil {
		return nil
	}
	command, env, err := managedRuntimeCommand(definition)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Dir = resolveRepoRoot()

	now := time.Now().UTC()
	state := &managedRuntimeState{
		IntegrationID: definition.ID,
		Worker:        definition.Runtime.Worker,
		Status:        "starting",
		LastStartedAt: &now,
		cancel:        cancel,
	}

	e.mu.Lock()
	e.runtimes[definition.ID] = state
	e.mu.Unlock()

	if err := cmd.Start(); err != nil {
		cancel()
		e.setRuntimeError(definition.ID, "start_failed", err)
		return err
	}

	e.mu.Lock()
	state.Pid = cmd.Process.Pid
	state.Status = "running"
	started := time.Now().UTC()
	state.LastHealthyAt = &started
	e.mu.Unlock()

	go e.watchManagedRuntime(definition, state, cmd)
	return nil
}

func (e *Engine) watchManagedRuntime(definition types.IntegrationDefinition, state *managedRuntimeState, cmd *exec.Cmd) {
	err := cmd.Wait()
	exitedAt := time.Now().UTC()

	e.mu.Lock()
	current := e.runtimes[definition.ID]
	if current == state {
		state.LastExitedAt = &exitedAt
		state.Pid = 0
		if err != nil {
			state.Status = "degraded"
			state.LastError = err.Error()
		} else {
			state.Status = "stopped"
			state.LastError = ""
		}
	}
	e.mu.Unlock()

	if definition.Runtime == nil || !definition.Runtime.Restart.Enabled {
		return
	}

	e.mu.RLock()
	current = e.runtimes[definition.ID]
	e.mu.RUnlock()
	if current != state {
		return
	}

	if definition.Runtime.Restart.MaxAttempts > 0 && state.RestartCount >= definition.Runtime.Restart.MaxAttempts {
		return
	}

	backoff := definition.Runtime.Restart.BackoffMs
	if backoff <= 0 {
		backoff = 2000
	}

	time.Sleep(time.Duration(backoff) * time.Millisecond)

	e.mu.Lock()
	if latest := e.runtimes[definition.ID]; latest == state {
		state.RestartCount++
	}
	e.mu.Unlock()

	_ = e.startManagedRuntime(definition)
}

func (e *Engine) stopManagedRuntime(integrationID string) {
	e.mu.Lock()
	state := e.runtimes[integrationID]
	if state != nil {
		delete(e.runtimes, integrationID)
	}
	e.mu.Unlock()
	if state != nil && state.cancel != nil {
		state.cancel()
	}
}

func (e *Engine) setRuntimeError(integrationID string, status string, err error) {
	now := time.Now().UTC()
	e.mu.Lock()
	state := e.runtimes[integrationID]
	if state == nil {
		state = &managedRuntimeState{IntegrationID: integrationID}
		e.runtimes[integrationID] = state
	}
	state.Status = status
	state.LastExitedAt = &now
	if err != nil {
		state.LastError = err.Error()
	}
	e.mu.Unlock()
}

func managedRuntimeCommand(definition types.IntegrationDefinition) ([]string, []string, error) {
	if definition.Runtime == nil {
		return nil, nil, nil
	}
	switch definition.Runtime.Worker {
	case "feishu":
		env, err := feishuRuntimeEnv(definition)
		if err != nil {
			return nil, nil, err
		}
		return []string{"bun", "packages/feishu-adapter/dist/cli.js"}, env, nil
	default:
		return nil, nil, fmt.Errorf("unsupported managed runtime worker %q", definition.Runtime.Worker)
	}
}

func feishuRuntimeEnv(definition types.IntegrationDefinition) ([]string, error) {
	if definition.Runtime == nil {
		return nil, fmt.Errorf("missing runtime spec")
	}
	config := definition.Runtime.Config
	required := []string{
		"app_id",
		"app_secret",
		"receive_id",
		"receive_id_type",
	}
	for _, key := range required {
		if strings.TrimSpace(mapStringValue(config, key)) == "" {
			return nil, fmt.Errorf("runtime config %q is required", key)
		}
	}
	env := []string{
		fmt.Sprintf("AGENTGATE_BASE_URL=%s", strings.TrimSpace(os.Getenv("AGENTGATE_MANAGED_BASE_URL"))),
		fmt.Sprintf("AGENTGATE_ADAPTER_TOKEN=%s", strings.TrimSpace(os.Getenv("AGENTGATE_MANAGED_ADAPTER_TOKEN"))),
		fmt.Sprintf("AGENTGATE_OPERATOR_TOKEN=%s", strings.TrimSpace(os.Getenv("AGENTGATE_MANAGED_OPERATOR_TOKEN"))),
		fmt.Sprintf("AGENTGATE_FEISHU_ADAPTER_ID=%s", definition.ApprovalChannel),
		fmt.Sprintf("AGENTGATE_FEISHU_INTEGRATION_ID=%s", definition.ID),
		fmt.Sprintf("FEISHU_APP_ID=%s", mapStringValue(config, "app_id")),
		fmt.Sprintf("FEISHU_APP_SECRET=%s", mapStringValue(config, "app_secret")),
		fmt.Sprintf("FEISHU_RECEIVE_ID=%s", mapStringValue(config, "receive_id")),
		fmt.Sprintf("FEISHU_RECEIVE_ID_TYPE=%s", mapStringValue(config, "receive_id_type")),
		fmt.Sprintf("FEISHU_DOMAIN=%s", defaultString(mapStringValue(config, "domain"), "feishu")),
		fmt.Sprintf("AGENTGATE_FEISHU_POLL_MS=%s", defaultString(mapStringValue(config, "poll_interval_ms"), "2000")),
	}
	return env, nil
}

func resolveRepoRoot() string {
	cwd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return cwd
}

func defaultString(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func (e *Engine) CurrentPolicy() PolicyCurrentResponse {
	e.mu.RLock()
	bundle := clonePolicyBundle(e.policyBundle)
	record := e.activePolicyRecordLocked()
	e.mu.RUnlock()
	return PolicyCurrentResponse{Bundle: bundle, Record: record}
}

func (e *Engine) PolicyBundles(includeArchived bool) (PolicyBundlesResponse, error) {
	if e.stateStore != nil {
		bundles, err := e.stateStore.ListPolicyBundles(includeArchived)
		if err != nil {
			return PolicyBundlesResponse{}, errStatus(http.StatusInternalServerError, "state_store_read_failed", err.Error())
		}
		return PolicyBundlesResponse{Bundles: bundles}, nil
	}
	e.mu.RLock()
	bundles := clonePolicyBundles(e.policyBundles)
	e.mu.RUnlock()
	if !includeArchived {
		filtered := bundles[:0]
		for _, bundle := range bundles {
			if bundle.Status != policy.BundleStatusArchived {
				filtered = append(filtered, bundle)
			}
		}
		bundles = filtered
	}
	sort.SliceStable(bundles, func(i, j int) bool {
		if bundles[i].Priority == bundles[j].Priority {
			return bundles[i].UpdatedAt.After(bundles[j].UpdatedAt)
		}
		return bundles[i].Priority > bundles[j].Priority
	})
	return PolicyBundlesResponse{Bundles: bundles}, nil
}

func (e *Engine) GetPolicyBundle(bundleID string) (policy.Bundle, error) {
	if bundleID == "" {
		return policy.Bundle{}, errBadRequest("missing_bundle_id", "bundle_id is required")
	}
	if e.stateStore != nil {
		bundle, found, err := e.stateStore.GetPolicyBundle(bundleID)
		if err != nil {
			return policy.Bundle{}, errStatus(http.StatusInternalServerError, "state_store_read_failed", err.Error())
		}
		if !found {
			return policy.Bundle{}, errStatus(http.StatusNotFound, "policy_bundle_not_found", "policy bundle was not found")
		}
		return bundle, nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, bundle := range e.policyBundles {
		if bundle.BundleID == bundleID {
			return clonePolicyBundle(bundle), nil
		}
	}
	return policy.Bundle{}, errStatus(http.StatusNotFound, "policy_bundle_not_found", "policy bundle was not found")
}

func (e *Engine) CreatePolicyBundle(bundle policy.Bundle) (policy.Bundle, error) {
	now := time.Now().UTC()
	bundle = normalizeManagedBundle(bundle, now)
	if bundle.BundleID == "" {
		bundle.BundleID = newID("bundle")
	}
	bundle.CreatedAt = now
	bundle.UpdatedAt = now
	if err := validateManagedBundle(bundle); err != nil {
		return policy.Bundle{}, err
	}
	if err := e.savePolicyBundle(bundle); err != nil {
		return policy.Bundle{}, err
	}
	return bundle, nil
}

func (e *Engine) UpdatePolicyBundle(bundleID string, bundle policy.Bundle) (policy.Bundle, error) {
	current, err := e.GetPolicyBundle(bundleID)
	if err != nil {
		return policy.Bundle{}, err
	}
	bundle = normalizeManagedBundle(bundle, time.Now().UTC())
	bundle.BundleID = bundleID
	bundle.CreatedAt = current.CreatedAt
	bundle.UpdatedAt = time.Now().UTC()
	if err := validateManagedBundle(bundle); err != nil {
		return policy.Bundle{}, err
	}
	if err := e.savePolicyBundle(bundle); err != nil {
		return policy.Bundle{}, err
	}
	return bundle, nil
}

func (e *Engine) DeletePolicyBundle(bundleID string) error {
	if bundleID == "" {
		return errBadRequest("missing_bundle_id", "bundle_id is required")
	}
	now := time.Now().UTC()
	if e.stateStore != nil {
		if err := e.stateStore.ArchivePolicyBundle(bundleID, now); err != nil {
			return errStatus(http.StatusInternalServerError, "state_store_write_failed", err.Error())
		}
	}
	e.mu.Lock()
	for index := range e.policyBundles {
		if e.policyBundles[index].BundleID == bundleID {
			e.policyBundles[index].Status = policy.BundleStatusArchived
			e.policyBundles[index].UpdatedAt = now
			e.policyBundle = aggregateBundles(e.policyBundles)
			e.mu.Unlock()
			return nil
		}
	}
	e.mu.Unlock()
	if e.stateStore == nil {
		return errStatus(http.StatusNotFound, "policy_bundle_not_found", "policy bundle was not found")
	}
	return nil
}

func (e *Engine) ValidatePolicyBundle(bundleID string) (PolicyValidationResponse, error) {
	bundle, err := e.GetPolicyBundle(bundleID)
	if err != nil {
		return PolicyValidationResponse{}, err
	}
	return e.ValidatePolicy(bundle), nil
}

func (e *Engine) PublishPolicyBundle(bundleID string) (policy.Bundle, error) {
	bundle, err := e.GetPolicyBundle(bundleID)
	if err != nil {
		return policy.Bundle{}, err
	}
	bundle.Status = policy.BundleStatusActive
	bundle.UpdatedAt = time.Now().UTC()
	if err := validateManagedBundle(bundle); err != nil {
		return policy.Bundle{}, err
	}
	if err := e.savePolicyBundle(bundle); err != nil {
		return policy.Bundle{}, err
	}
	if err := e.appendPolicyBundleEvent("policy_bundle_published", bundle); err != nil {
		return policy.Bundle{}, errStatus(http.StatusInternalServerError, "event_store_write_failed", err.Error())
	}
	return bundle, nil
}

func (e *Engine) ValidatePolicy(bundle policy.Bundle) PolicyValidationResponse {
	if err := bundle.Validate(); err != nil {
		return PolicyValidationResponse{
			Valid:  false,
			Errors: []string{err.Error()},
		}
	}
	return policyValidationSuccess(bundle)
}

func (e *Engine) PolicyVersions(limit int) (PolicyVersionsResponse, error) {
	if e.stateStore != nil {
		records, err := e.stateStore.ListPolicyVersions(limit)
		if err != nil {
			return PolicyVersionsResponse{}, errStatus(http.StatusInternalServerError, "state_store_read_failed", err.Error())
		}
		return PolicyVersionsResponse{Versions: records}, nil
	}
	e.mu.RLock()
	records := append([]policy.VersionRecord(nil), e.policyRecords...)
	e.mu.RUnlock()
	sort.SliceStable(records, func(i, j int) bool {
		return records[i].Version > records[j].Version
	})
	if limit > 0 && len(records) > limit {
		records = records[:limit]
	}
	return PolicyVersionsResponse{Versions: records}, nil
}

func (e *Engine) PublishPolicy(req PolicyPublishRequest) (PolicyCurrentResponse, error) {
	if err := req.Bundle.Validate(); err != nil {
		return PolicyCurrentResponse{}, errBadRequest("invalid_policy_bundle", err.Error())
	}

	now := time.Now().UTC()
	e.mu.Lock()
	nextVersion := e.nextPolicyVersionLocked()
	bundle := clonePolicyBundle(req.Bundle)
	bundle.Version = nextVersion
	bundle.Status = "active"
	bundle.IssuedAt = now
	if e.stateStore != nil {
		record, err := e.stateStore.SavePolicyVersion(bundle, req.OperatorID, req.Message, 0, now)
		if err != nil {
			e.mu.Unlock()
			return PolicyCurrentResponse{}, errStatus(http.StatusInternalServerError, "state_store_write_failed", err.Error())
		}
		e.activatePolicyLocked(bundle, record)
	} else {
		record := policy.VersionRecord{
			Version:     bundle.Version,
			Status:      bundle.StatusValue(),
			Active:      true,
			RuleCount:   len(bundle.Rules),
			PublishedAt: now,
			PublishedBy: req.OperatorID,
			Message:     req.Message,
		}
		e.activatePolicyLocked(bundle, record)
	}
	e.policyBundles = []policy.Bundle{defaultPolicyBundle(bundle)}
	record := e.activePolicyRecordLocked()
	e.mu.Unlock()

	if err := e.appendPolicyLifecycleEvent("policy_published", bundle, record, req.OperatorID, req.Message, 0, now); err != nil {
		return PolicyCurrentResponse{}, errStatus(http.StatusInternalServerError, "event_store_write_failed", err.Error())
	}
	return PolicyCurrentResponse{Bundle: clonePolicyBundle(bundle), Record: record}, nil
}

func (e *Engine) RollbackPolicy(req PolicyRollbackRequest) (PolicyCurrentResponse, error) {
	if req.Version <= 0 {
		return PolicyCurrentResponse{}, errBadRequest("invalid_policy_version", "version must be positive")
	}

	now := time.Now().UTC()
	e.mu.Lock()
	sourceBundle, found, err := e.policyBundleForVersionLocked(req.Version)
	if err != nil {
		e.mu.Unlock()
		return PolicyCurrentResponse{}, err
	}
	if !found {
		e.mu.Unlock()
		return PolicyCurrentResponse{}, errStatus(http.StatusNotFound, "policy_version_not_found", "policy version was not found")
	}

	nextVersion := e.nextPolicyVersionLocked()
	bundle := clonePolicyBundle(sourceBundle)
	bundle.Version = nextVersion
	bundle.Status = "active"
	bundle.IssuedAt = now
	message := req.Message
	if message == "" {
		message = fmt.Sprintf("rollback to policy version %d", req.Version)
	}
	if e.stateStore != nil {
		record, err := e.stateStore.SavePolicyVersion(bundle, req.OperatorID, message, req.Version, now)
		if err != nil {
			e.mu.Unlock()
			return PolicyCurrentResponse{}, errStatus(http.StatusInternalServerError, "state_store_write_failed", err.Error())
		}
		e.activatePolicyLocked(bundle, record)
	} else {
		record := policy.VersionRecord{
			Version:       bundle.Version,
			Status:        bundle.StatusValue(),
			Active:        true,
			RuleCount:     len(bundle.Rules),
			PublishedAt:   now,
			PublishedBy:   req.OperatorID,
			Message:       message,
			SourceVersion: req.Version,
		}
		e.activatePolicyLocked(bundle, record)
	}
	record := e.activePolicyRecordLocked()
	e.policyBundles = []policy.Bundle{defaultPolicyBundle(bundle)}
	e.mu.Unlock()

	if err := e.appendPolicyLifecycleEvent("policy_rolled_back", bundle, record, req.OperatorID, message, req.Version, now); err != nil {
		return PolicyCurrentResponse{}, errStatus(http.StatusInternalServerError, "event_store_write_failed", err.Error())
	}
	return PolicyCurrentResponse{Bundle: clonePolicyBundle(bundle), Record: record}, nil
}

func (e *Engine) seedPolicyHistory() {
	bundle := clonePolicyBundle(e.policyBundle)
	record := policy.VersionRecord{
		Version:     bundle.Version,
		Status:      bundle.StatusValue(),
		Active:      true,
		RuleCount:   len(bundle.Rules),
		PublishedAt: bundle.IssuedAt,
		Message:     "initial policy",
	}
	e.policyHistory[bundle.Version] = bundle
	e.policyRecords = append(e.policyRecords, record)
}

func (e *Engine) activePolicyRecordLocked() policy.VersionRecord {
	for _, record := range e.policyRecords {
		if record.Active && record.Version == e.policyBundle.Version {
			return record
		}
	}
	return policy.VersionRecord{
		Version:     e.policyBundle.Version,
		Status:      e.policyBundle.StatusValue(),
		Active:      true,
		RuleCount:   len(e.policyBundle.Rules),
		PublishedAt: e.policyBundle.IssuedAt,
	}
}

func (e *Engine) nextPolicyVersionLocked() int {
	next := e.policyBundle.Version + 1
	if e.stateStore != nil {
		if records, err := e.stateStore.ListPolicyVersions(1); err == nil && len(records) > 0 {
			next = records[0].Version + 1
		}
	}
	for _, record := range e.policyRecords {
		if record.Version >= next {
			next = record.Version + 1
		}
	}
	return next
}

func (e *Engine) activatePolicyLocked(bundle policy.Bundle, record policy.VersionRecord) {
	for index := range e.policyRecords {
		e.policyRecords[index].Active = false
		e.policyRecords[index].Status = "superseded"
	}
	record.Active = true
	e.policyBundle = clonePolicyBundle(bundle)
	e.policyHistory[bundle.Version] = clonePolicyBundle(bundle)
	replaced := false
	for index := range e.policyRecords {
		if e.policyRecords[index].Version == record.Version {
			e.policyRecords[index] = record
			replaced = true
			break
		}
	}
	if !replaced {
		e.policyRecords = append(e.policyRecords, record)
	}
}

func (e *Engine) policyBundleForVersionLocked(version int) (policy.Bundle, bool, error) {
	if bundle, ok := e.policyHistory[version]; ok {
		return clonePolicyBundle(bundle), true, nil
	}
	if e.stateStore == nil {
		return policy.Bundle{}, false, nil
	}
	bundle, _, found, err := e.stateStore.GetPolicyBundleVersion(version)
	if err != nil {
		return policy.Bundle{}, false, errStatus(http.StatusInternalServerError, "state_store_read_failed", err.Error())
	}
	if !found {
		return policy.Bundle{}, false, nil
	}
	e.policyHistory[version] = clonePolicyBundle(bundle)
	return clonePolicyBundle(bundle), true, nil
}

func (e *Engine) appendPolicyLifecycleEvent(eventType string, bundle policy.Bundle, record policy.VersionRecord, operatorID string, message string, sourceVersion int, now time.Time) error {
	return e.appendEvent(types.EventEnvelope{
		EventID:   newID("evt_policy"),
		EventType: eventType,
		Summary:   fmt.Sprintf("policy version %d active", bundle.Version),
		Metadata: map[string]interface{}{
			"policy_version": bundle.Version,
			"policy_status":  bundle.StatusValue(),
			"rule_count":     len(bundle.Rules),
			"operator_id":    operatorID,
			"message":        message,
			"source_version": sourceVersion,
			"published_at":   record.PublishedAt.Format(time.RFC3339Nano),
		},
		OccurredAt: now,
	})
}

func policyValidationSuccess(bundle policy.Bundle) PolicyValidationResponse {
	surfaceRules := map[types.Surface]int{
		types.SurfaceInput:    0,
		types.SurfaceRuntime:  0,
		types.SurfaceResource: 0,
	}
	for _, rule := range bundle.Rules {
		surfaceRules[rule.Surface]++
	}
	warnings := make([]string, 0)
	for _, surface := range []types.Surface{types.SurfaceInput, types.SurfaceRuntime, types.SurfaceResource} {
		if surfaceRules[surface] == 0 {
			warnings = append(warnings, fmt.Sprintf("policy has no rules for %s surface", surface))
		}
	}
	return PolicyValidationResponse{
		Valid:        true,
		Warnings:     warnings,
		Version:      bundle.Version,
		RuleCount:    len(bundle.Rules),
		SurfaceRules: surfaceRules,
	}
}

func clonePolicyBundle(bundle policy.Bundle) policy.Bundle {
	payload, err := json.Marshal(bundle)
	if err != nil {
		return bundle
	}
	var cloned policy.Bundle
	if err := json.Unmarshal(payload, &cloned); err != nil {
		return bundle
	}
	return cloned
}

func defaultPolicyBundle(bundle policy.Bundle) policy.Bundle {
	issuedAt := bundle.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = time.Now().UTC()
	}
	result := clonePolicyBundle(bundle)
	result.BundleID = "default"
	result.Name = "Default bundle"
	result.Description = "Bootstrap policy bundle"
	result.Priority = 100
	result.Status = policy.BundleStatusActive
	result.CreatedAt = issuedAt
	result.UpdatedAt = issuedAt
	return result
}

func normalizeManagedBundle(bundle policy.Bundle, now time.Time) policy.Bundle {
	bundle.BundleID = strings.TrimSpace(bundle.BundleID)
	bundle.Name = strings.TrimSpace(bundle.Name)
	bundle.Description = strings.TrimSpace(bundle.Description)
	bundle.Status = strings.TrimSpace(bundle.Status)
	if bundle.Status == "" {
		bundle.Status = policy.BundleStatusInactive
	}
	if bundle.IssuedAt.IsZero() {
		bundle.IssuedAt = now
	}
	return bundle
}

func validateManagedBundle(bundle policy.Bundle) error {
	if bundle.Name == "" {
		return errBadRequest("invalid_policy_bundle", "name is required")
	}
	switch bundle.Status {
	case policy.BundleStatusActive, policy.BundleStatusInactive, policy.BundleStatusArchived:
	default:
		return errBadRequest("invalid_policy_bundle", "status must be active, inactive, or archived")
	}
	if bundle.Priority < 0 {
		return errBadRequest("invalid_policy_bundle", "priority must be non-negative")
	}
	if err := bundle.Validate(); err != nil {
		return errBadRequest("invalid_policy_bundle", err.Error())
	}
	return nil
}

func (e *Engine) savePolicyBundle(bundle policy.Bundle) error {
	if e.stateStore != nil {
		if err := e.stateStore.SavePolicyBundle(bundle); err != nil {
			return errStatus(http.StatusInternalServerError, "state_store_write_failed", err.Error())
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	replaced := false
	for index := range e.policyBundles {
		if e.policyBundles[index].BundleID == bundle.BundleID {
			e.policyBundles[index] = clonePolicyBundle(bundle)
			replaced = true
			break
		}
	}
	if !replaced {
		e.policyBundles = append(e.policyBundles, clonePolicyBundle(bundle))
	}
	e.policyBundle = aggregateBundles(e.policyBundles)
	return nil
}

func (e *Engine) appendPolicyBundleEvent(eventType string, bundle policy.Bundle) error {
	now := time.Now().UTC()
	return e.appendEvent(types.EventEnvelope{
		EventID:   newID("evt_policy_bundle"),
		EventType: eventType,
		Summary:   bundle.Name,
		Metadata: map[string]interface{}{
			"bundle_id":       bundle.BundleID,
			"bundle_name":     bundle.Name,
			"bundle_priority": bundle.Priority,
			"bundle_status":   bundle.Status,
			"rule_count":      len(bundle.Rules),
		},
		OccurredAt: now,
	})
}

func clonePolicyBundles(bundles []policy.Bundle) []policy.Bundle {
	result := make([]policy.Bundle, 0, len(bundles))
	for _, bundle := range bundles {
		result = append(result, clonePolicyBundle(bundle))
	}
	return result
}

func aggregateBundles(bundles []policy.Bundle) policy.Bundle {
	bundle := policy.DefaultBundle()
	bundle.Version = 0
	bundle.Status = "bundles_active"
	bundle.IssuedAt = time.Now().UTC()
	bundle.Rules = nil
	for _, managedBundle := range bundles {
		if managedBundle.Status != policy.BundleStatusActive {
			continue
		}
		bundle.Rules = append(bundle.Rules, managedBundle.Rules...)
	}
	if len(bundle.Rules) == 0 {
		bundle.Rules = policy.DefaultBundle().Rules
	}
	return bundle
}

func (e *Engine) Integrations() (types.IntegrationsResponse, error) {
	definitions, err := e.integrationDefinitions()
	if err != nil {
		return types.IntegrationsResponse{}, err
	}
	if definitions == nil {
		definitions = []types.IntegrationDefinition{}
	}
	adapters, err := e.adapterCoverages()
	if err != nil {
		return types.IntegrationsResponse{}, err
	}
	now := time.Now().UTC()
	for index := range definitions {
		definitions[index] = e.hydrateIntegrationHealth(definitions[index], adapters, now)
	}
	sort.SliceStable(definitions, func(i, j int) bool {
		if definitions[i].Enabled == definitions[j].Enabled {
			return definitions[i].ID < definitions[j].ID
		}
		return definitions[i].Enabled
	})
	return types.IntegrationsResponse{Integrations: definitions}, nil
}

func (e *Engine) GetIntegration(integrationID string) (types.IntegrationDefinition, error) {
	if integrationID == "" {
		return types.IntegrationDefinition{}, errBadRequest("missing_integration_id", "integration id is required")
	}
	definition, found, err := e.integrationDefinition(integrationID)
	if err != nil {
		return types.IntegrationDefinition{}, err
	}
	if !found {
		return types.IntegrationDefinition{}, errStatus(http.StatusNotFound, "integration_not_found", "integration definition was not found")
	}
	adapters, err := e.adapterCoverages()
	if err != nil {
		return types.IntegrationDefinition{}, err
	}
	return e.hydrateIntegrationHealth(definition, adapters, time.Now().UTC()), nil
}

func (e *Engine) SaveIntegration(definition types.IntegrationDefinition) (types.IntegrationDefinition, error) {
	normalized, err := normalizeIntegrationDefinition(definition)
	if err != nil {
		return types.IntegrationDefinition{}, errBadRequest("invalid_integration_definition", err.Error())
	}
	now := time.Now().UTC()
	if e.stateStore != nil {
		if err := e.stateStore.SaveIntegrationDefinition(normalized, now); err != nil {
			return types.IntegrationDefinition{}, errStatus(http.StatusInternalServerError, "state_store_write_failed", err.Error())
		}
	} else {
		e.mu.Lock()
		e.integrations[normalized.ID] = normalized
		e.mu.Unlock()
	}
	adapters, err := e.adapterCoverages()
	if err != nil {
		return types.IntegrationDefinition{}, err
	}
	if err := e.reconcileManagedRuntime(normalized); err != nil {
		return types.IntegrationDefinition{}, errStatus(http.StatusInternalServerError, "managed_runtime_reconcile_failed", err.Error())
	}
	return e.hydrateIntegrationHealth(normalized, adapters, now), nil
}

func (e *Engine) DeleteIntegration(integrationID string) error {
	if integrationID == "" {
		return errBadRequest("missing_integration_id", "integration id is required")
	}
	e.stopManagedRuntime(integrationID)
	if e.stateStore != nil {
		if err := e.stateStore.DeleteIntegrationDefinition(integrationID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errStatus(http.StatusNotFound, "integration_not_found", "integration definition was not found")
			}
			return errStatus(http.StatusInternalServerError, "state_store_write_failed", err.Error())
		}
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, found := e.integrations[integrationID]; !found {
		return errStatus(http.StatusNotFound, "integration_not_found", "integration definition was not found")
	}
	delete(e.integrations, integrationID)
	return nil
}

func (e *Engine) integrationDefinitions() ([]types.IntegrationDefinition, error) {
	if e.stateStore != nil {
		definitions, err := e.stateStore.ListIntegrationDefinitions()
		if err != nil {
			return nil, errStatus(http.StatusInternalServerError, "state_store_read_failed", err.Error())
		}
		return definitions, nil
	}
	e.mu.RLock()
	definitions := make([]types.IntegrationDefinition, 0, len(e.integrations))
	for _, definition := range e.integrations {
		definitions = append(definitions, definition)
	}
	e.mu.RUnlock()
	return definitions, nil
}

func (e *Engine) integrationDefinition(integrationID string) (types.IntegrationDefinition, bool, error) {
	if e.stateStore != nil {
		definition, found, err := e.stateStore.GetIntegrationDefinition(integrationID)
		if err != nil {
			return types.IntegrationDefinition{}, false, errStatus(http.StatusInternalServerError, "state_store_read_failed", err.Error())
		}
		return definition, found, nil
	}
	e.mu.RLock()
	definition, found := e.integrations[integrationID]
	e.mu.RUnlock()
	return definition, found, nil
}

func (e *Engine) adapterCoverages() ([]types.AdapterCoverage, error) {
	if e.stateStore != nil {
		adapters, err := e.stateStore.ListAdapterRegistrations()
		if err != nil {
			return nil, errStatus(http.StatusInternalServerError, "state_store_read_failed", err.Error())
		}
		return adapters, nil
	}
	e.mu.RLock()
	adapters := make([]types.AdapterCoverage, 0, len(e.registrations))
	for _, state := range e.registrations {
		reg := state.registration
		adapters = append(adapters, types.AdapterCoverage{
			AdapterID:          reg.AdapterID,
			IntegrationID:      reg.IntegrationID,
			AdapterKind:        reg.AdapterKind,
			Host:               reg.Host,
			Surfaces:           append([]types.Surface(nil), reg.Surfaces...),
			SupportingChannels: append([]string(nil), reg.SupportingChannels...),
			RegisteredAt:       state.registeredAt,
			LastSeenAt:         state.lastSeenAt,
		})
	}
	e.mu.RUnlock()
	return adapters, nil
}

func (e *Engine) hydrateIntegrationHealth(definition types.IntegrationDefinition, adapters []types.AdapterCoverage, now time.Time) types.IntegrationDefinition {
	definition.Health = types.IntegrationHealth{ComputedAt: now}
	definition.MatchedAdapters = nil
	definition.Health.Runtime = e.runtimeView(definition.ID)
	if !definition.Enabled {
		definition.Health.Status = types.IntegrationHealthDisabled
		return definition
	}
	matched := make([]types.IntegrationMatchedAdapter, 0)
	for _, adapter := range adapters {
		if adapter.IntegrationID != definition.ID {
			continue
		}
		status := adapterHealthStatus(adapter, now)
		matched = append(matched, types.IntegrationMatchedAdapter{
			AdapterID:          adapter.AdapterID,
			IntegrationID:      adapter.IntegrationID,
			AdapterKind:        adapter.AdapterKind,
			Host:               adapter.Host,
			Surfaces:           append([]types.Surface(nil), adapter.Surfaces...),
			SupportingChannels: append([]string(nil), adapter.SupportingChannels...),
			Status:             status,
			RegisteredAt:       adapter.RegisteredAt,
			LastSeenAt:         adapter.LastSeenAt,
		})
	}
	sort.SliceStable(matched, func(i, j int) bool {
		leftRank := integrationStatusRank(matched[i].Status)
		rightRank := integrationStatusRank(matched[j].Status)
		if leftRank == rightRank {
			return matched[i].LastSeenAt.After(matched[j].LastSeenAt)
		}
		return leftRank < rightRank
	})
	definition.MatchedAdapters = matched
	definition.Health.MatchedAdapterCount = len(matched)
	if len(matched) == 0 {
		if runtimeStatus := runtimeHealthStatus(definition.Health.Runtime); runtimeStatus != "" {
			definition.Health.Status = runtimeStatus
		} else {
			definition.Health.Status = types.IntegrationHealthMissing
		}
		return definition
	}
	primary := matched[0]
	definition.Health.Status = primary.Status
	if runtimeStatus := runtimeHealthStatus(definition.Health.Runtime); runtimeStatus == types.IntegrationHealthDegraded || runtimeStatus == types.IntegrationHealthStarting {
		definition.Health.Status = runtimeStatus
	}
	definition.Health.MatchedAdapterID = primary.AdapterID
	lastSeen := primary.LastSeenAt
	definition.Health.LastSeenAt = &lastSeen
	return definition
}

func (e *Engine) runtimeView(integrationID string) *types.IntegrationRuntimeView {
	e.mu.RLock()
	state := e.runtimes[integrationID]
	e.mu.RUnlock()
	if state == nil {
		return nil
	}
	view := &types.IntegrationRuntimeView{
		Managed:      true,
		Worker:       state.Worker,
		Status:       state.Status,
		RestartCount: state.RestartCount,
		LastError:    state.LastError,
		Pid:          state.Pid,
	}
	if state.LastStartedAt != nil {
		startedAt := *state.LastStartedAt
		view.LastStartedAt = &startedAt
	}
	if state.LastExitedAt != nil {
		exitedAt := *state.LastExitedAt
		view.LastExitedAt = &exitedAt
	}
	if state.LastHealthyAt != nil {
		healthyAt := *state.LastHealthyAt
		view.LastHealthyAt = &healthyAt
	}
	return view
}

func runtimeHealthStatus(view *types.IntegrationRuntimeView) types.IntegrationHealthStatus {
	if view == nil || !view.Managed {
		return ""
	}
	switch view.Status {
	case "starting":
		return types.IntegrationHealthStarting
	case "degraded", "error":
		return types.IntegrationHealthDegraded
	default:
		return ""
	}
}

func adapterHealthStatus(adapter types.AdapterCoverage, now time.Time) types.IntegrationHealthStatus {
	if now.Sub(adapter.LastSeenAt) > integrationStaleAfter {
		return types.IntegrationHealthStale
	}
	return types.IntegrationHealthConnected
}

func integrationStatusRank(status types.IntegrationHealthStatus) int {
	switch status {
	case types.IntegrationHealthConnected:
		return 0
	case types.IntegrationHealthStarting:
		return 1
	case types.IntegrationHealthDegraded:
		return 2
	case types.IntegrationHealthStale:
		return 3
	case types.IntegrationHealthMissing:
		return 4
	case types.IntegrationHealthUnmanaged:
		return 5
	case types.IntegrationHealthDisabled:
		return 6
	default:
		return 7
	}
}

func normalizeIntegrationDefinition(definition types.IntegrationDefinition) (types.IntegrationDefinition, error) {
	definition.ID = strings.TrimSpace(definition.ID)
	definition.Name = strings.TrimSpace(definition.Name)
	definition.Kind = strings.TrimSpace(definition.Kind)
	definition.ApprovalChannel = strings.TrimSpace(definition.ApprovalChannel)
	definition.Health = types.IntegrationHealth{}
	definition.MatchedAdapters = nil
	if definition.ID == "" {
		return types.IntegrationDefinition{}, fmt.Errorf("id is required")
	}
	if !isCompactToken(definition.ID) {
		return types.IntegrationDefinition{}, fmt.Errorf("id must be a compact token")
	}
	if definition.Name == "" {
		return types.IntegrationDefinition{}, fmt.Errorf("name is required")
	}
	if definition.Kind == "" {
		return types.IntegrationDefinition{}, fmt.Errorf("kind is required")
	}
	if !isCompactToken(definition.Kind) {
		return types.IntegrationDefinition{}, fmt.Errorf("kind must be a compact token")
	}
	if definition.ApprovalChannel != "" && !isCompactToken(definition.ApprovalChannel) {
		return types.IntegrationDefinition{}, fmt.Errorf("approval_channel must be a compact token")
	}
	if definition.Runtime != nil {
		if err := validateIntegrationRuntimeSpec(*definition.Runtime); err != nil {
			return types.IntegrationDefinition{}, err
		}
	}
	seenSurfaces := make(map[types.Surface]struct{}, len(definition.ExpectedSurfaces))
	for _, surface := range definition.ExpectedSurfaces {
		if !isValidSurface(surface) {
			return types.IntegrationDefinition{}, fmt.Errorf("unsupported expected surface %q", surface)
		}
		if _, exists := seenSurfaces[surface]; exists {
			return types.IntegrationDefinition{}, fmt.Errorf("duplicate expected surface %q", surface)
		}
		seenSurfaces[surface] = struct{}{}
	}
	return definition, nil
}

func validateIntegrationRuntimeSpec(spec types.IntegrationRuntimeSpec) error {
	spec.Worker = strings.TrimSpace(spec.Worker)
	if spec.Worker == "" {
		return fmt.Errorf("runtime.worker is required")
	}
	if !isCompactToken(spec.Worker) {
		return fmt.Errorf("runtime.worker must be a compact token")
	}
	if spec.Restart.MaxAttempts < 0 {
		return fmt.Errorf("runtime.restart.max_attempts must be >= 0")
	}
	if spec.Restart.BackoffMs < 0 {
		return fmt.Errorf("runtime.restart.backoff_ms must be >= 0")
	}
	return nil
}

func (e *Engine) RegisterAdapter(req types.AdapterRegistration) (types.RegistrationResult, error) {
	if req.AdapterID == "" {
		return types.RegistrationResult{}, errBadRequest("missing_adapter_id", "adapter_id is required")
	}
	if err := validateRegistration(req); err != nil {
		return types.RegistrationResult{}, errBadRequest("invalid_registration", err.Error())
	}
	if len(req.Surfaces) == 0 && len(req.SupportingChannels) == 0 {
		return types.RegistrationResult{}, errBadRequest("missing_coverage", "at least one surface or supporting channel is required")
	}

	now := time.Now().UTC()
	e.mu.Lock()
	e.registrations[req.AdapterID] = adapterState{
		registration: req,
		registeredAt: now,
		lastSeenAt:   now,
	}
	e.mu.Unlock()

	if e.stateStore != nil {
		if err := e.stateStore.UpsertAdapterRegistration(req, now, now); err != nil {
			return types.RegistrationResult{}, errStatus(http.StatusInternalServerError, "state_store_write_failed", err.Error())
		}
	}

	metadata := map[string]interface{}{"adapter_kind": req.AdapterKind, "host_kind": req.Host.Kind}
	if req.IntegrationID != "" {
		metadata["integration_id"] = req.IntegrationID
	}
	if err := e.appendEvent(types.EventEnvelope{
		EventID:    newID("evt_register"),
		EventType:  "adapter_registered",
		AdapterID:  req.AdapterID,
		Summary:    "adapter registered",
		Metadata:   metadata,
		OccurredAt: now,
	}); err != nil {
		return types.RegistrationResult{}, errStatus(http.StatusInternalServerError, "event_store_write_failed", err.Error())
	}

	return types.RegistrationResult{
		AdapterID:    req.AdapterID,
		RegisteredAt: now,
		Accepted:     true,
	}, nil
}

func (e *Engine) Coverage() types.CoverageResponse {
	now := time.Now().UTC()
	response := types.CoverageResponse{
		GeneratedAt: now,
		Adapters:    []types.AdapterCoverage{},
		Surfaces: map[types.Surface]int{
			types.SurfaceInput:    0,
			types.SurfaceRuntime:  0,
			types.SurfaceResource: 0,
		},
	}

	if e.stateStore != nil {
		adapters, err := e.stateStore.ListAdapterRegistrations()
		if err == nil {
			response.Adapters = adapters
			for _, adapter := range adapters {
				for _, surface := range adapter.Surfaces {
					response.Surfaces[surface]++
				}
			}
			for _, surface := range []types.Surface{types.SurfaceInput, types.SurfaceRuntime, types.SurfaceResource} {
				if response.Surfaces[surface] == 0 {
					response.Warnings = append(response.Warnings, fmt.Sprintf("no adapter registered for %s surface", surface))
				}
			}
			return response
		}
		response.Warnings = append(response.Warnings, "coverage state store unavailable")
	}

	e.mu.RLock()
	for _, state := range e.registrations {
		reg := state.registration
		response.Adapters = append(response.Adapters, types.AdapterCoverage{
			AdapterID:          reg.AdapterID,
			IntegrationID:      reg.IntegrationID,
			AdapterKind:        reg.AdapterKind,
			Host:               reg.Host,
			Surfaces:           append([]types.Surface(nil), reg.Surfaces...),
			SupportingChannels: append([]string(nil), reg.SupportingChannels...),
			RegisteredAt:       state.registeredAt,
			LastSeenAt:         state.lastSeenAt,
		})
		for _, surface := range reg.Surfaces {
			response.Surfaces[surface]++
		}
	}
	e.mu.RUnlock()

	for _, surface := range []types.Surface{types.SurfaceInput, types.SurfaceRuntime, types.SurfaceResource} {
		if response.Surfaces[surface] == 0 {
			response.Warnings = append(response.Warnings, fmt.Sprintf("no adapter registered for %s surface", surface))
		}
	}

	return response
}

func (e *Engine) Approvals(limit int) (types.ApprovalsResponse, error) {
	now := time.Now().UTC()
	expired := make([]approvalState, 0)
	if e.stateStore != nil {
		approvals, err := e.stateStore.ListApprovals(limit)
		if err != nil {
			return types.ApprovalsResponse{}, errStatus(http.StatusInternalServerError, "state_store_read_failed", err.Error())
		}
		for index, approval := range approvals {
			next, changed := expireApprovalIfNeeded(approval, now)
			if changed {
				approvals[index] = next
				if err := e.stateStore.SaveApproval(next); err != nil {
					return types.ApprovalsResponse{}, errStatus(http.StatusInternalServerError, "state_store_write_failed", err.Error())
				}
				e.mu.Lock()
				e.approvals[next.ApprovalID] = approvalRecordToState(next)
				e.mu.Unlock()
				expired = append(expired, approvalRecordToState(next))
			}
		}
		if err := e.appendApprovalExpiryEvents(expired, now); err != nil {
			return types.ApprovalsResponse{}, errStatus(http.StatusInternalServerError, "event_store_write_failed", err.Error())
		}
		return types.ApprovalsResponse{Approvals: approvals}, nil
	}

	e.mu.Lock()
	approvals := make([]types.ApprovalRecord, 0, len(e.approvals))
	for id, approval := range e.approvals {
		record, changed := expireApprovalIfNeeded(approvalStateToRecord(approval), now)
		if changed {
			expiredState := approvalRecordToState(record)
			e.approvals[id] = expiredState
			expired = append(expired, expiredState)
		}
		approvals = append(approvals, record)
	}
	e.mu.Unlock()
	sort.SliceStable(approvals, func(i, j int) bool {
		return approvals[i].CreatedAt.After(approvals[j].CreatedAt)
	})
	if err := e.appendApprovalExpiryEvents(expired, now); err != nil {
		return types.ApprovalsResponse{}, errStatus(http.StatusInternalServerError, "event_store_write_failed", err.Error())
	}
	return types.ApprovalsResponse{Approvals: approvals}, nil
}

func (e *Engine) Decide(req types.PolicyRequest) (types.PolicyDecision, error) {
	if req.RequestID == "" {
		req.RequestID = newID("req")
	}
	if req.RequestKind == types.RequestKindToolAttempt && req.Session.AttemptID == "" {
		req.Session.AttemptID = req.RequestID
	}

	now := time.Now().UTC()
	surface := req.Context.Surface
	if surface == "" {
		surface = inferSurface(req.RequestKind)
	}
	req.Context.Surface = surface

	warnings := make([]string, 0, 2)
	var policyEvaluation policy.Evaluation
	var effect types.Effect
	var reason string
	var appliedRules []string
	var obligations []types.Obligation
	e.mu.RLock()
	activePolicy := e.policyBundle
	activeBundles := clonePolicyBundles(e.policyBundles)
	e.mu.RUnlock()
	if patch := validateDecisionRequest(req, surface); patch != nil {
		policyEvaluation = requestValidationEvaluation(patch)
		effect = patch.effect
		reason = patch.reason
		appliedRules = patch.appliedRules
		obligations = append([]types.Obligation(nil), patch.obligations...)
	} else {
		inputFacts := e.enrichPolicyFacts(&req)
		sessionFacts := e.sessionFactsForDecision(req.Session.SessionID)
		policyEvaluation = policy.EvaluateBundles(activeBundles, req, sessionFacts)
		effect = policyEvaluation.Effect
		reason = policyEvaluation.ReasonCode
		appliedRules = append([]string(nil), policyEvaluation.AppliedRules...)
		obligations = append([]types.Obligation(nil), policyEvaluation.Obligations...)
		if req.RequestKind == types.RequestKindInput && surface == types.SurfaceInput {
			if patch := e.evaluateInputSecrets(req, now, policyEvaluation, inputFacts); patch != nil {
				effect = patch.effect
				reason = patch.reason
				appliedRules = patch.appliedRules
				obligations = append(obligations, patch.obligations...)
			}
		}
		if req.RequestKind == types.RequestKindResourceAccess && surface == types.SurfaceResource {
			if patch := e.evaluateSecretHandleAccess(req, policyEvaluation); patch != nil {
				effect = patch.effect
				reason = patch.reason
				appliedRules = patch.appliedRules
				obligations = append(obligations, patch.obligations...)
			}
		}
		if req.RequestKind == types.RequestKindToolAttempt && surface == types.SurfaceRuntime {
			if patch := e.evaluateToolAttempt(req, now, policyEvaluation); patch != nil {
				effect = patch.effect
				reason = patch.reason
				appliedRules = patch.appliedRules
				obligations = append(obligations, patch.obligations...)
			}
		}
	}

	if !isValidSurface(surface) {
		// Unsupported surfaces are already denied by request validation.
	} else if !e.hasCoverage(surface) {
		warnings = append(warnings, fmt.Sprintf("no adapter registration currently covers %s surface", surface))
	}

	decision := types.PolicyDecision{
		DecisionID:   newID("dec"),
		RequestID:    req.RequestID,
		Effect:       effect,
		ReasonCode:   reason,
		Obligations:  obligations,
		AppliedRules: appliedRules,
		Explanation: types.DecisionExplanation{
			Summary:     decisionSummary(reason),
			Warnings:    warnings,
			PolicyTrace: policyTrace(activePolicy, policyEvaluation),
		},
		DecidedAt: now,
	}
	traceMetadata := decision.Explanation.PolicyTrace

	if err := e.appendEvent(types.EventEnvelope{
		EventID:    newID("evt_decide"),
		EventType:  "policy_decision",
		RequestID:  req.RequestID,
		DecisionID: decision.DecisionID,
		SessionID:  req.Session.SessionID,
		Surface:    surface,
		Effect:     effect,
		Summary:    reason,
		Metadata: map[string]interface{}{
			"request_kind":        req.RequestKind,
			"actor_user":          req.Actor.UserID,
			"host_id":             req.Actor.HostID,
			"integration_id":      mapStringValue(req.Policy, "integration_id"),
			"operation":           req.Action.Operation,
			"tool":                req.Action.Tool,
			"content_summary":     req.Content.Summary,
			"side_effects":        append([]string(nil), req.Action.SideEffects...),
			"open_world":          req.Action.OpenWorld,
			"target_kind":         req.Target.Kind,
			"target_identifier":   req.Target.Identifier,
			"applied_rules":       appliedRules,
			"obligations":         obligationTypes(obligations),
			"task_id":             req.Session.TaskID,
			"attempt_id":          req.Session.AttemptID,
			"approval_id":         approvalIDFromObligations(obligations),
			"approval_scope":      approvalScopeFromObligations(obligations),
			"approval_channel":    approvalChannelFromObligations(obligations),
			"approval_expires_at": approvalExpiresAtFromObligations(obligations),
			"warnings":            warnings,
			"policy_version":      traceMetadata.PolicyVersion,
			"policy_status":       traceMetadata.PolicyStatus,
			"selected_rule":       traceMetadata.SelectedRule,
			"top_priority":        traceMetadata.TopPriority,
			"defaulted":           traceMetadata.Defaulted,
			"matched_rules":       policyRuleTraceIDs(traceMetadata.MatchedRules),
		},
		OccurredAt: now,
	}); err != nil {
		return types.PolicyDecision{}, errStatus(http.StatusInternalServerError, "event_store_write_failed", err.Error())
	}

	return decision, nil
}

func (e *Engine) Report(req types.ReportRequest) (types.ReportResponse, error) {
	if req.RequestID == "" && req.DecisionID == "" {
		return types.ReportResponse{}, errBadRequest("missing_correlation", "request_id or decision_id is required")
	}

	now := time.Now().UTC()
	redactedMetadata, redacted := redactAuditValue(req.Metadata, e.detector)
	if err := e.appendEvent(types.EventEnvelope{
		EventID:    newID("evt_report"),
		EventType:  "adapter_report",
		RequestID:  req.RequestID,
		DecisionID: req.DecisionID,
		AdapterID:  req.AdapterID,
		Surface:    req.Surface,
		Summary:    req.Outcome,
		Metadata: map[string]interface{}{
			"error_message": redactAuditString(req.ErrorMessage, e.detector),
			"metadata":      redactedMetadata,
			"obligations":   obligationTypes(req.Obligations),
			"redacted":      redacted,
		},
		OccurredAt: now,
	}); err != nil {
		return types.ReportResponse{}, errStatus(http.StatusInternalServerError, "event_store_write_failed", err.Error())
	}
	go e.updateSessionFactsFromReport(req, now)

	return types.ReportResponse{Accepted: true, RecordedAt: now}, nil
}

func (e *Engine) ResolveApproval(approvalID string, req types.ApprovalResolveRequest) (types.ApprovalResolveResponse, error) {
	if approvalID == "" {
		return types.ApprovalResolveResponse{}, errBadRequest("missing_approval_id", "approval_id is required")
	}

	now := time.Now().UTC()
	decision := strings.ToLower(strings.TrimSpace(req.Decision))

	e.mu.Lock()
	approval, ok := e.approvals[approvalID]
	if !ok && e.stateStore != nil {
		record, found, err := e.stateStore.GetApproval(approvalID)
		if err != nil {
			e.mu.Unlock()
			return types.ApprovalResolveResponse{}, errStatus(http.StatusInternalServerError, "state_store_read_failed", err.Error())
		}
		if found {
			approval = approvalRecordToState(record)
			ok = true
		}
	}
	if !ok {
		e.mu.Unlock()
		return types.ApprovalResolveResponse{}, errStatus(http.StatusNotFound, "approval_not_found", "approval was not found")
	}
	if approval.Status != types.ApprovalPending {
		e.mu.Unlock()
		return types.ApprovalResolveResponse{}, errStatus(http.StatusConflict, "approval_already_resolved", "approval is already resolved")
	}

	if !approval.ExpiresAt.After(now) {
		approval.Status = types.ApprovalExpired
		approval.ResolvedAt = &now
		approval.OperatorID = req.OperatorID
		approval.Channel = req.Channel
		e.mu.Unlock()

		if e.stateStore != nil {
			if err := e.stateStore.SaveApproval(approvalStateToRecord(approval)); err != nil {
				return types.ApprovalResolveResponse{}, errStatus(http.StatusInternalServerError, "state_store_write_failed", err.Error())
			}
		}
		e.mu.Lock()
		e.approvals[approvalID] = approval
		e.mu.Unlock()

		if err := e.appendApprovalEvent(approval, "approval_expired", now); err != nil {
			return types.ApprovalResolveResponse{}, errStatus(http.StatusInternalServerError, "event_store_write_failed", err.Error())
		}
		return types.ApprovalResolveResponse{}, errStatus(http.StatusConflict, "approval_expired", "approval has expired")
	}

	var grantKey string
	var grant types.AttemptGrant
	needsGrant := false

	switch decision {
	case "approve", "approved", "allow", "allow_once":
		approval.Status = types.ApprovalApproved
		approval.ResolvedAt = &now
		approval.OperatorID = req.OperatorID
		approval.Channel = req.Channel
		grantKey = attemptKey(approval.SessionID, approval.TaskID, approval.AttemptID)
		grant = types.AttemptGrant{ApprovalID: approvalID, ExpiresAt: approval.ExpiresAt}
		needsGrant = true
	case "deny", "denied", "reject", "rejected":
		approval.Status = types.ApprovalDenied
		approval.ResolvedAt = &now
		approval.OperatorID = req.OperatorID
		approval.Channel = req.Channel
	default:
		e.mu.Unlock()
		return types.ApprovalResolveResponse{}, errBadRequest("invalid_approval_decision", "decision must be approve/allow_once or deny")
	}
	e.mu.Unlock()

	// SQLite before memory.  Safe without lock: approvalID is unique and the
	// Pending→Resolved transition is one-way — a concurrent resolver sees
	// Status != Pending and gets Conflict.
	if e.stateStore != nil {
		if err := e.stateStore.SaveApproval(approvalStateToRecord(approval)); err != nil {
			return types.ApprovalResolveResponse{}, errStatus(http.StatusInternalServerError, "state_store_write_failed", err.Error())
		}
		if needsGrant {
			if err := e.stateStore.SaveAttemptGrant(approval.SessionID, approval.TaskID, approval.AttemptID, approvalID, approval.ExpiresAt); err != nil {
				return types.ApprovalResolveResponse{}, errStatus(http.StatusInternalServerError, "state_store_write_failed", err.Error())
			}
		}
	}

	e.mu.Lock()
	e.approvals[approvalID] = approval
	if needsGrant {
		e.attemptGrants[grantKey] = grant
	}
	e.mu.Unlock()

	eventType := "approval_denied"
	if approval.Status == types.ApprovalApproved {
		eventType = "approval_granted"
	}
	if err := e.appendApprovalEvent(approval, eventType, now); err != nil {
		return types.ApprovalResolveResponse{}, errStatus(http.StatusInternalServerError, "event_store_write_failed", err.Error())
	}

	return types.ApprovalResolveResponse{
		ApprovalID: approvalID,
		Status:     approval.Status,
		ResolvedAt: now,
	}, nil
}

func (e *Engine) appendApprovalEvent(approval approvalState, eventType string, now time.Time) error {
	effect := types.EffectDeny
	if approval.Status == types.ApprovalApproved {
		effect = types.EffectAllowWithAudit
	}
	return e.appendEvent(types.EventEnvelope{
		EventID:   newID("evt_approval"),
		EventType: eventType,
		RequestID: approval.RequestID,
		SessionID: approval.SessionID,
		Surface:   types.SurfaceRuntime,
		Effect:    effect,
		Summary:   string(approval.Status),
		Metadata: map[string]interface{}{
			"approval_id": approval.ApprovalID,
			"task_id":     approval.TaskID,
			"attempt_id":  approval.AttemptID,
			"operator_id": approval.OperatorID,
			"channel":     approval.Channel,
		},
		OccurredAt: now,
	})
}

func (e *Engine) appendApprovalExpiryEvents(approvals []approvalState, now time.Time) error {
	for _, approval := range approvals {
		if err := e.appendApprovalEvent(approval, "approval_expired", now); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) Events(limit int) ([]types.EventEnvelope, error) {
	if e.eventStore != nil {
		return e.eventStore.ListEvents(limit)
	}
	e.mu.RLock()
	events := append([]types.EventEnvelope(nil), e.events...)
	e.mu.RUnlock()
	if len(events) > limit {
		events = events[len(events)-limit:]
	}
	return events, nil
}

func (e *Engine) evaluateInputSecrets(req types.PolicyRequest, now time.Time, evaluation policy.Evaluation, facts inputSecretFacts) *decisionPatch {
	if len(facts.findings) == 0 {
		return nil
	}
	if evaluation.Defaulted {
		return &decisionPatch{
			effect:       types.EffectDeny,
			reason:       "input_secret_policy_missing",
			appliedRules: appendPolicyRules(evaluation.AppliedRules, "input.secret.policy_missing"),
			obligations: []types.Obligation{
				auditObligation("critical", map[string]interface{}{"finding_count": len(facts.findings)}),
				abortTaskObligation(),
			},
		}
	}
	if evaluation.Effect != types.EffectAllow && evaluation.Effect != types.EffectAllowWithAudit {
		return nil
	}

	handles := make([]types.SecretHandle, 0, len(facts.findings))
	summaries := make([]types.SecretFindingSummary, 0, len(facts.findings))
	rewritten := scanner.RewriteSecrets(facts.text, facts.findings, func(index int, finding scanner.SecretFinding) string {
		placeholder := fmt.Sprintf("[SECRET_HANDLE:%d]", index+1)
		hash := scanner.HashSecret(finding.Value)
		handle := types.SecretHandle{
			HandleID:    newID("sech"),
			SessionID:   req.Session.SessionID,
			TaskID:      req.Session.TaskID,
			Kind:        finding.Kind,
			Placeholder: placeholder,
			SecretHash:  hash,
			CreatedAt:   now,
		}
		handles = append(handles, handle)
		summaries = append(summaries, types.SecretFindingSummary{
			Kind:        finding.Kind,
			Placeholder: placeholder,
			HandleID:    handle.HandleID,
			Hash:        hash,
			Offset:      finding.Start,
			Length:      finding.End - finding.Start,
		})
		return placeholder
	})

	if e.stateStore != nil {
		for index, handle := range handles {
			if err := e.stateStore.SaveSecretHandle(handle, facts.findings[index].Value); err != nil {
				return &decisionPatch{
					effect:       types.EffectDeny,
					reason:       "secret_handle_store_failed",
					appliedRules: []string{"secret.handle.persist.fail_closed"},
					obligations:  []types.Obligation{abortTaskObligation()},
				}
			}
		}
	}
	e.mu.Lock()
	for _, handle := range handles {
		e.secretHandles[handle.HandleID] = handle
	}
	for index, handle := range handles {
		e.secretValues[handle.HandleID] = facts.findings[index].Value
	}
	e.mu.Unlock()

	return &decisionPatch{
		effect:       types.EffectAllowWithAudit,
		reason:       evaluation.ReasonCode,
		appliedRules: appendPolicyRules(evaluation.AppliedRules, "input.secret.detect", "secret.handle.create", "input.rewrite.secret_placeholders"),
		obligations: []types.Obligation{
			{
				Type: "rewrite_input",
				Params: map[string]interface{}{
					"text":             rewritten,
					"bodyForAgent":     rewritten,
					"secret_findings":  summaries,
					"secret_handles":   handles,
					"redaction_policy": "placeholder_only",
				},
			},
			{
				Type: "audit_event",
				Params: map[string]interface{}{
					"severity":        "warning",
					"finding_count":   len(facts.findings),
					"secret_findings": summaries,
				},
			},
		},
	}
}

func (e *Engine) evaluateSecretHandleAccess(req types.PolicyRequest, evaluation policy.Evaluation) *decisionPatch {
	if req.Target.Kind != "secret_handle" || req.Target.Identifier == "" {
		return &decisionPatch{
			effect:       types.EffectDeny,
			reason:       "resource_access_unsupported_target",
			appliedRules: []string{"resource.secret_handle.required"},
			obligations:  []types.Obligation{abortTaskObligation()},
		}
	}
	if evaluation.Defaulted {
		return &decisionPatch{
			effect:       types.EffectDeny,
			reason:       "resource_secret_policy_missing",
			appliedRules: appendPolicyRules(evaluation.AppliedRules, "resource.secret_handle.policy_missing"),
			obligations: []types.Obligation{
				auditObligation("critical", map[string]interface{}{"handle_id": req.Target.Identifier}),
				abortTaskObligation(),
			},
		}
	}
	if evaluation.Effect != types.EffectAllow && evaluation.Effect != types.EffectAllowWithAudit {
		return nil
	}

	e.mu.RLock()
	handle, ok := e.secretHandles[req.Target.Identifier]
	value := e.secretValues[req.Target.Identifier]
	e.mu.RUnlock()
	if !ok && e.stateStore != nil {
		storedHandle, storedValue, found, err := e.stateStore.GetSecretHandle(req.Target.Identifier)
		if err != nil {
			return &decisionPatch{
				effect:       types.EffectDeny,
				reason:       "secret_handle_store_unavailable",
				appliedRules: []string{"resource.secret_handle.lookup.fail_closed"},
				obligations:  []types.Obligation{abortTaskObligation()},
			}
		}
		if found {
			handle = storedHandle
			value = storedValue
			ok = true
			e.mu.Lock()
			e.secretHandles[handle.HandleID] = handle
			e.secretValues[handle.HandleID] = value
			e.mu.Unlock()
		}
	}

	if !ok {
		return &decisionPatch{
			effect:       types.EffectDeny,
			reason:       "secret_handle_not_found",
			appliedRules: []string{"resource.secret_handle.lookup"},
			obligations: []types.Obligation{
				auditObligation("critical", map[string]interface{}{"handle_id": req.Target.Identifier}),
				abortTaskObligation(),
			},
		}
	}

	if handle.SessionID != req.Session.SessionID || (handle.TaskID != "" && handle.TaskID != req.Session.TaskID) {
		return &decisionPatch{
			effect:       types.EffectDeny,
			reason:       "secret_handle_scope_mismatch",
			appliedRules: []string{"resource.secret_handle.scope"},
			obligations: []types.Obligation{
				auditObligation("critical", map[string]interface{}{"handle_id": handle.HandleID, "secret_hash": handle.SecretHash}),
				abortTaskObligation(),
			},
		}
	}

	return &decisionPatch{
		effect:       types.EffectAllowWithAudit,
		reason:       evaluation.ReasonCode,
		appliedRules: appendPolicyRules(evaluation.AppliedRules, "resource.secret_handle.lookup", "resource.secret_handle.scope"),
		obligations: []types.Obligation{
			{
				Type: "resolve_secret_handle",
				Params: map[string]interface{}{
					"handle_id":    handle.HandleID,
					"placeholder":  handle.Placeholder,
					"kind":         handle.Kind,
					"secret_value": value,
				},
			},
			auditObligation("warning", map[string]interface{}{"handle_id": handle.HandleID, "secret_hash": handle.SecretHash}),
		},
	}
}

func (e *Engine) evaluateToolAttempt(req types.PolicyRequest, now time.Time, evaluation policy.Evaluation) *decisionPatch {
	if evaluation.Effect != types.EffectApprovalRequired {
		return nil
	}

	key := attemptKey(req.Session.SessionID, req.Session.TaskID, req.Session.AttemptID)
	e.mu.RLock()
	grant, granted := e.attemptGrants[key]
	e.mu.RUnlock()
	if !granted && e.stateStore != nil {
		storedGrant, found, err := e.stateStore.GetAttemptGrant(req.Session.SessionID, req.Session.TaskID, req.Session.AttemptID)
		if err != nil {
			return &decisionPatch{
				effect:       types.EffectDeny,
				reason:       "attempt_grant_store_unavailable",
				appliedRules: []string{"runtime.grant.lookup.fail_closed"},
				obligations:  []types.Obligation{abortTaskObligation()},
			}
		}
		if found {
			grant = storedGrant
			granted = true
			e.mu.Lock()
			e.attemptGrants[key] = storedGrant
			e.mu.Unlock()
		}
	}
	if granted && grant.ExpiresAt.After(now) {
		return &decisionPatch{
			effect:       types.EffectAllowWithAudit,
			reason:       "user_allow_once_valid",
			appliedRules: []string{"runtime.high_risk.allow_once_grant"},
			obligations:  []types.Obligation{auditObligation("info", map[string]interface{}{"approval_id": grant.ApprovalID})},
		}
	}

	approvalID := newID("appr")
	expiresAt := now.Add(10 * time.Minute)
	approvalChannel := e.approvalChannelForRequest(req)
	approval := approvalState{
		ApprovalID: approvalID,
		RequestID:  req.RequestID,
		SessionID:  req.Session.SessionID,
		TaskID:     req.Session.TaskID,
		AttemptID:  req.Session.AttemptID,
		Status:     types.ApprovalPending,
		Reason:     "High-risk runtime attempt paused by AgentGate policy.",
		Channel:    approvalChannel,
		CreatedAt:  now,
		ExpiresAt:  expiresAt,
	}

	if e.stateStore != nil {
		if err := e.stateStore.SaveApproval(approvalStateToRecord(approval)); err != nil {
			return &decisionPatch{
				effect:       types.EffectDeny,
				reason:       "approval_store_failed",
				appliedRules: []string{"runtime.approval.persist.fail_closed"},
				obligations:  []types.Obligation{abortTaskObligation()},
			}
		}
	}
	e.mu.Lock()
	e.approvals[approvalID] = approval
	e.mu.Unlock()

	return &decisionPatch{
		effect:       types.EffectApprovalRequired,
		reason:       evaluation.ReasonCode,
		appliedRules: evaluation.AppliedRules,
		obligations: []types.Obligation{
			{
				Type: "approval_request",
				Params: map[string]interface{}{
					"approval_id": approvalID,
					"scope":       "attempt",
					"channel":     approvalChannel,
					"session_id":  req.Session.SessionID,
					"task_id":     req.Session.TaskID,
					"attempt_id":  req.Session.AttemptID,
					"reason":      approval.Reason,
					"expires_at":  expiresAt,
				},
			},
			{
				Type: "task_control",
				Params: map[string]interface{}{
					"action": "pause_for_approval",
				},
			},
		},
	}
}

func (e *Engine) approvalChannelForRequest(req types.PolicyRequest) string {
	integrationID := strings.TrimSpace(mapStringValue(req.Policy, "integration_id"))
	if integrationID == "" {
		integrationID = strings.TrimSpace(mapStringValue(req.Context.Raw, "integration_id"))
	}
	if integrationID == "" {
		return ""
	}
	definition, found, err := e.integrationDefinition(integrationID)
	if err != nil || !found || !definition.Enabled {
		return ""
	}
	return definition.ApprovalChannel
}

func (e *Engine) hasCoverage(surface types.Surface) bool {
	if e.stateStore != nil {
		adapters, err := e.stateStore.ListAdapterRegistrations()
		if err == nil {
			for _, adapter := range adapters {
				for _, registeredSurface := range adapter.Surfaces {
					if registeredSurface == surface {
						return true
					}
				}
			}
			return false
		}
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, state := range e.registrations {
		for _, registeredSurface := range state.registration.Surfaces {
			if registeredSurface == surface {
				return true
			}
		}
	}
	return false
}

func (e *Engine) sessionFactsForDecision(sessionID string) types.SessionFacts {
	if sessionID == "" || e.stateStore == nil {
		return types.SessionFacts{}
	}
	record, found, err := e.stateStore.GetSessionFacts(sessionID)
	if err != nil || !found {
		return types.SessionFacts{}
	}
	return normalizeSessionFacts(record.Facts)
}

func (e *Engine) updateSessionFactsFromReport(report types.ReportRequest, reportedAt time.Time) {
	if e.stateStore == nil || report.DecisionID == "" {
		return
	}
	decisionEvent, found, err := e.lookupDecisionEvent(report.DecisionID)
	if err != nil || !found || decisionEvent.SessionID == "" {
		return
	}
	_ = e.stateStore.UpdateSessionFacts(decisionEvent.SessionID, func(record types.SessionFactsRecord, found bool) (types.SessionFactsRecord, error) {
		if !found {
			record = types.SessionFactsRecord{
				SessionID: decisionEvent.SessionID,
				Facts: types.SessionFacts{
					DistinctTargets:     []string{},
					DistinctTools:       []string{},
					DistinctReasonCodes: []string{},
					SideEffectSequence:  []string{},
				},
			}
		}
		record.AdapterID = firstNonEmpty(record.AdapterID, report.AdapterID, decisionEvent.AdapterID, stringValue(decisionEvent.Metadata["host_id"]))
		record.UpdatedAt = reportedAt
		record.Facts = updateSessionFacts(record.Facts, decisionEvent, reportedAt)
		return record, nil
	})
}

func (e *Engine) lookupDecisionEvent(decisionID string) (types.EventEnvelope, bool, error) {
	if e.eventStore != nil {
		event, found, err := e.eventStore.GetEventByDecisionID(decisionID)
		if err != nil || found {
			return event, found, err
		}
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for index := len(e.events) - 1; index >= 0; index-- {
		event := e.events[index]
		if event.DecisionID == decisionID && event.EventType == "policy_decision" {
			return event, true, nil
		}
	}
	return types.EventEnvelope{}, false, nil
}

func updateSessionFacts(facts types.SessionFacts, event types.EventEnvelope, reportedAt time.Time) types.SessionFacts {
	facts = normalizeSessionFacts(facts)
	facts.RequestCount++
	switch event.Effect {
	case types.EffectDeny, types.EffectExclusion:
		facts.DenyCount++
	case types.EffectApprovalRequired:
		facts.ApprovalCount++
	case types.EffectAllow, types.EffectAllowWithAudit:
		facts.AllowCount++
	}
	facts.LastEffect = string(event.Effect)
	if facts.FirstRequestAt == nil || facts.FirstRequestAt.IsZero() {
		first := reportedAt
		if !event.OccurredAt.IsZero() {
			first = event.OccurredAt
		}
		facts.FirstRequestAt = &first
	}
	last := reportedAt
	facts.LastRequestAt = &last
	facts.DistinctTargets = addDistinct(facts.DistinctTargets, stringValue(event.Metadata["target_identifier"]))
	facts.DistinctTools = addDistinct(facts.DistinctTools, stringValue(event.Metadata["tool"]))
	facts.DistinctReasonCodes = addDistinct(facts.DistinctReasonCodes, event.Summary)
	facts.SideEffectSequence = appendCapped(facts.SideEffectSequence, stringSliceValue(event.Metadata["side_effects"]), 20)
	return facts
}

func normalizeSessionFacts(facts types.SessionFacts) types.SessionFacts {
	if facts.DistinctTargets == nil {
		facts.DistinctTargets = []string{}
	}
	if facts.DistinctTools == nil {
		facts.DistinctTools = []string{}
	}
	if facts.DistinctReasonCodes == nil {
		facts.DistinctReasonCodes = []string{}
	}
	if facts.SideEffectSequence == nil {
		facts.SideEffectSequence = []string{}
	}
	return facts
}

func addDistinct(values []string, candidate string) []string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return values
	}
	for _, value := range values {
		if value == candidate {
			return values
		}
	}
	return append(values, candidate)
}

func appendCapped(values []string, additions []string, cap int) []string {
	for _, addition := range additions {
		if strings.TrimSpace(addition) != "" {
			values = append(values, addition)
		}
	}
	if cap > 0 && len(values) > cap {
		values = values[len(values)-cap:]
	}
	return values
}

func stringValue(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return ""
	}
}

func stringSliceValue(value interface{}) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []interface{}:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok {
				result = append(result, text)
			}
		}
		return result
	default:
		return nil
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func (e *Engine) appendEvent(event types.EventEnvelope) error {
	if e.eventStore != nil {
		if err := e.eventStore.AppendEvent(event); err != nil {
			return err
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	e.events = append(e.events, event)
	if len(e.events) > e.maxEvents {
		e.events = e.events[len(e.events)-e.maxEvents:]
	}
	return nil
}

func errBadRequest(code string, message string) error {
	return errStatus(http.StatusBadRequest, code, message)
}

func errStatus(status int, code string, message string) error {
	return &Error{Status: status, Code: code, Message: message}
}

func validateRegistration(req types.AdapterRegistration) error {
	if req.IntegrationID != "" && !isCompactToken(req.IntegrationID) {
		return fmt.Errorf("integration_id must be a compact token")
	}
	seenSurfaces := make(map[types.Surface]struct{}, len(req.Surfaces))
	for _, surface := range req.Surfaces {
		if !isValidSurface(surface) {
			return fmt.Errorf("unsupported surface %q", surface)
		}
		if _, exists := seenSurfaces[surface]; exists {
			return fmt.Errorf("duplicate surface %q", surface)
		}
		seenSurfaces[surface] = struct{}{}
	}
	seenChannels := make(map[string]struct{}, len(req.SupportingChannels))
	for _, channel := range req.SupportingChannels {
		if strings.TrimSpace(channel) == "" || strings.TrimSpace(channel) != channel {
			return fmt.Errorf("supporting channel must be a compact non-empty token")
		}
		if strings.ContainsAny(channel, " \t\n\r") {
			return fmt.Errorf("supporting channel %q must be a compact token", channel)
		}
		normalized := strings.ToLower(channel)
		if _, exists := seenChannels[normalized]; exists {
			return fmt.Errorf("duplicate supporting channel %q", channel)
		}
		seenChannels[normalized] = struct{}{}
	}
	capabilities := req.Capabilities
	if _, ok := seenSurfaces[types.SurfaceInput]; ok {
		if !capabilities.CanBlock {
			return fmt.Errorf("input surface requires can_block capability")
		}
		if !capabilities.CanRewriteInput {
			return fmt.Errorf("input surface requires can_rewrite_input capability")
		}
	}
	if _, ok := seenSurfaces[types.SurfaceRuntime]; ok {
		if !capabilities.CanBlock {
			return fmt.Errorf("runtime surface requires can_block capability")
		}
		if !capabilities.CanPauseForApproval {
			return fmt.Errorf("runtime surface requires can_pause_for_approval capability")
		}
	}
	if _, ok := seenSurfaces[types.SurfaceResource]; ok && !capabilities.CanBlock {
		return fmt.Errorf("resource surface requires can_block capability")
	}
	return nil
}

func isCompactToken(value string) bool {
	return value != "" &&
		strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, " \t\n\r")
}

func isValidSurface(surface types.Surface) bool {
	switch surface {
	case types.SurfaceInput, types.SurfaceRuntime, types.SurfaceResource:
		return true
	default:
		return false
	}
}

func isValidRequestKind(kind types.RequestKind) bool {
	switch kind {
	case types.RequestKindInput,
		types.RequestKindToolAttempt,
		types.RequestKindResourceEgress,
		types.RequestKindResourceAccess,
		types.RequestKindInitialEnvelope,
		types.RequestKindEnvelopeAmendment:
		return true
	default:
		return false
	}
}

func validateDecisionRequest(req types.PolicyRequest, surface types.Surface) *decisionPatch {
	if !isValidRequestKind(req.RequestKind) {
		return requestValidationPatch("unsupported_request_kind")
	}
	if !isValidSurface(surface) {
		return requestValidationPatch("unsupported_surface")
	}
	if strings.TrimSpace(req.Session.SessionID) == "" {
		return requestValidationPatch("missing_session_id")
	}
	if strings.TrimSpace(req.Session.TaskID) == "" {
		return requestValidationPatch("missing_task_id")
	}
	if req.RequestKind == types.RequestKindToolAttempt && strings.TrimSpace(req.Session.AttemptID) == "" {
		return requestValidationPatch("missing_attempt_id")
	}
	return nil
}

func requestValidationPatch(reason string) *decisionPatch {
	return &decisionPatch{
		effect:       types.EffectDeny,
		reason:       reason,
		appliedRules: []string{"core.request.validation"},
		obligations: []types.Obligation{
			auditObligation("critical", map[string]interface{}{"reason": reason}),
			abortTaskObligation(),
		},
	}
}

func requestValidationEvaluation(patch *decisionPatch) policy.Evaluation {
	return policy.Evaluation{
		Effect:       patch.effect,
		ReasonCode:   patch.reason,
		AppliedRules: append([]string(nil), patch.appliedRules...),
		SelectedRule: "core.request.validation",
		Defaulted:    true,
	}
}

func (e *Engine) enrichPolicyFacts(req *types.PolicyRequest) inputSecretFacts {
	if req.RequestKind != types.RequestKindInput || req.Context.Surface != types.SurfaceInput {
		return inputSecretFacts{}
	}
	text, ok := rawString(req.Context.Raw, "text")
	if !ok {
		text, ok = rawString(req.Context.Raw, "body")
	}
	if !ok {
		return inputSecretFacts{}
	}
	findings, err := e.detector.DetectSecrets(text)
	if err != nil {
		log.Printf("secret detection error: %v", err)
		return inputSecretFacts{text: text}
	}
	if len(findings) == 0 {
		return inputSecretFacts{text: text}
	}
	req.Content.DataClasses = appendDataClassOnce(req.Content.DataClasses, types.DataClassSecret)
	req.Content.DataClasses = appendDataClassOnce(req.Content.DataClasses, types.DataClassCredential)
	req.Context.Taints = appendTaintOnce(req.Context.Taints, types.TaintSecretBearing)
	return inputSecretFacts{text: text, findings: findings}
}

func appendDataClassOnce(values []types.DataClass, value types.DataClass) []types.DataClass {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendTaintOnce(values []types.Taint, value types.Taint) []types.Taint {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func rawString(raw map[string]interface{}, key string) (string, bool) {
	if raw == nil {
		return "", false
	}
	value, ok := raw[key]
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	if !ok || text == "" {
		return "", false
	}
	return text, true
}

func attemptKey(sessionID string, taskID string, attemptID string) string {
	return sessionID + "\x00" + taskID + "\x00" + attemptID
}

func approvalStateToRecord(approval approvalState) types.ApprovalRecord {
	return types.ApprovalRecord{
		ApprovalID: approval.ApprovalID,
		RequestID:  approval.RequestID,
		SessionID:  approval.SessionID,
		TaskID:     approval.TaskID,
		AttemptID:  approval.AttemptID,
		Status:     approval.Status,
		Reason:     approval.Reason,
		OperatorID: approval.OperatorID,
		Channel:    approval.Channel,
		CreatedAt:  approval.CreatedAt,
		ExpiresAt:  approval.ExpiresAt,
		ResolvedAt: approval.ResolvedAt,
	}
}

func approvalRecordToState(approval types.ApprovalRecord) approvalState {
	return approvalState{
		ApprovalID: approval.ApprovalID,
		RequestID:  approval.RequestID,
		SessionID:  approval.SessionID,
		TaskID:     approval.TaskID,
		AttemptID:  approval.AttemptID,
		Status:     approval.Status,
		Reason:     approval.Reason,
		CreatedAt:  approval.CreatedAt,
		ExpiresAt:  approval.ExpiresAt,
		ResolvedAt: approval.ResolvedAt,
		OperatorID: approval.OperatorID,
		Channel:    approval.Channel,
	}
}

func expireApprovalIfNeeded(approval types.ApprovalRecord, now time.Time) (types.ApprovalRecord, bool) {
	if approval.Status != types.ApprovalPending || approval.ExpiresAt.After(now) {
		return approval, false
	}
	approval.Status = types.ApprovalExpired
	approval.ResolvedAt = &now
	return approval, true
}

func auditObligation(severity string, params map[string]interface{}) types.Obligation {
	copied := map[string]interface{}{"severity": severity}
	for key, value := range params {
		copied[key] = value
	}
	return types.Obligation{Type: "audit_event", Params: copied}
}

func abortTaskObligation() types.Obligation {
	return types.Obligation{
		Type: "task_control",
		Params: map[string]interface{}{
			"action": "abort_task",
		},
	}
}

func appendPolicyRules(base []string, extra ...string) []string {
	result := make([]string, 0, len(base)+len(extra))
	result = append(result, base...)
	result = append(result, extra...)
	return result
}

func obligationTypes(obligations []types.Obligation) []string {
	result := make([]string, 0, len(obligations))
	for _, obligation := range obligations {
		result = append(result, obligation.Type)
	}
	return result
}

func policyRuleTraceIDs(rules []types.PolicyRuleTrace) []string {
	result := make([]string, 0, len(rules))
	for _, rule := range rules {
		if rule.BundleID != "" {
			result = append(result, rule.BundleID+"/"+rule.RuleID)
			continue
		}
		result = append(result, rule.RuleID)
	}
	return result
}

func approvalIDFromObligations(obligations []types.Obligation) string {
	for _, obligation := range obligations {
		if obligation.Type != "approval_request" {
			continue
		}
		value, ok := obligation.Params["approval_id"].(string)
		if ok {
			return value
		}
	}
	return ""
}

func approvalScopeFromObligations(obligations []types.Obligation) string {
	for _, obligation := range obligations {
		if obligation.Type != "approval_request" {
			continue
		}
		value, ok := obligation.Params["scope"].(string)
		if ok {
			return value
		}
	}
	return ""
}

func approvalExpiresAtFromObligations(obligations []types.Obligation) string {
	for _, obligation := range obligations {
		if obligation.Type != "approval_request" {
			continue
		}
		switch value := obligation.Params["expires_at"].(type) {
		case time.Time:
			return value.Format(time.RFC3339Nano)
		case string:
			return value
		}
	}
	return ""
}

func approvalChannelFromObligations(obligations []types.Obligation) string {
	for _, obligation := range obligations {
		if obligation.Type != "approval_request" {
			continue
		}
		value, ok := obligation.Params["channel"].(string)
		if ok && value != "" {
			return value
		}
	}
	return ""
}

func mapStringValue(values map[string]interface{}, key string) string {
	if values == nil {
		return ""
	}
	value, ok := values[key].(string)
	if !ok {
		return ""
	}
	return value
}

func redactAuditValue(value interface{}, det scanner.Detector) (interface{}, bool) {
	switch typed := value.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{}, len(typed))
		redacted := false
		for key, item := range typed {
			if isSensitiveAuditKey(key) {
				result[key] = "[REDACTED]"
				redacted = true
				continue
			}
			next, changed := redactAuditValue(item, det)
			result[key] = next
			redacted = redacted || changed
		}
		return result, redacted
	case []interface{}:
		result := make([]interface{}, 0, len(typed))
		redacted := false
		for _, item := range typed {
			next, changed := redactAuditValue(item, det)
			result = append(result, next)
			redacted = redacted || changed
		}
		return result, redacted
	case string:
		next := redactAuditString(typed, det)
		return next, next != typed
	default:
		return value, false
	}
}

func redactAuditString(value string, det scanner.Detector) string {
	if value == "" {
		return value
	}
	findings, err := det.DetectSecrets(value)
	if err != nil {
		log.Printf("secret detection error in redact: %v", err)
		return value
	}
	if len(findings) == 0 {
		return value
	}
	return scanner.RewriteSecrets(value, findings, func(index int, finding scanner.SecretFinding) string {
		return "[REDACTED]"
	})
}

func isSensitiveAuditKey(key string) bool {
	switch strings.ToLower(strings.ReplaceAll(key, "-", "_")) {
	case "secret", "secret_value", "value", "token", "api_key", "apikey", "password", "authorization", "access_token", "refresh_token":
		return true
	default:
		return false
	}
}

func decisionSummary(reason string) string {
	switch reason {
	case "input_secret_rewritten_to_handles":
		return "Input contained secret-like material; model-visible text was rewritten to SecretHandle placeholders."
	case "policy_allow_with_audit":
		return "Policy allowed the request with audit."
	case "secret_handle_resolve_allowed":
		return "SecretHandle scope matched the resource request; secret material was released to the authorized resource surface."
	case "secret_handle_not_found":
		return "SecretHandle was not found."
	case "secret_handle_scope_mismatch":
		return "SecretHandle exists but is outside the current session or task scope."
	case "missing_task_id":
		return "Request denied because task_id is required for AgentGate decision scope."
	case "resource_access_unsupported_target":
		return "Resource access denied because the target is not a supported resource kind."
	case "runtime_high_risk_requires_approval":
		return "Runtime attempt has high-risk side effects and requires an attempt-scoped approval."
	case "user_allow_once_valid":
		return "Attempt-scoped approval grant matched this runtime request."
	default:
		return reason
	}
}

func policyTrace(bundle policy.Bundle, evaluation policy.Evaluation) types.PolicyTrace {
	matched := make([]types.PolicyRuleTrace, 0, len(evaluation.MatchedRules))
	for _, match := range evaluation.MatchedRules {
		matched = append(matched, types.PolicyRuleTrace{
			BundleID:       match.BundleID,
			BundlePriority: match.BundlePriority,
			RuleID:         match.Rule.ID,
			Priority:       match.Rule.Priority,
			Effect:         match.Rule.Effect,
			ReasonCode:     match.Rule.ReasonCode,
		})
	}
	return types.PolicyTrace{
		PolicyVersion:  bundle.Version,
		PolicyStatus:   bundle.StatusValue(),
		SelectedBundle: evaluation.SelectedBundle,
		BundlePriority: evaluation.BundlePriority,
		SelectedRule:   evaluation.SelectedRule,
		TopPriority:    evaluation.TopPriority,
		Defaulted:      evaluation.Defaulted,
		MatchedRules:   matched,
	}
}

func inferSurface(kind types.RequestKind) types.Surface {
	switch kind {
	case types.RequestKindInput, types.RequestKindInitialEnvelope:
		return types.SurfaceInput
	case types.RequestKindToolAttempt, types.RequestKindEnvelopeAmendment:
		return types.SurfaceRuntime
	case types.RequestKindResourceEgress, types.RequestKindResourceAccess:
		return types.SurfaceResource
	default:
		return ""
	}
}

func newID(prefix string) string {
	return fmt.Sprintf("%s_%d_%d", prefix, time.Now().UTC().UnixNano(), idCounter.Add(1))
}
