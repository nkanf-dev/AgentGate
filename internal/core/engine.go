package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agentgate/agentgate/internal/authz"
	"github.com/agentgate/agentgate/internal/policy"
	"github.com/agentgate/agentgate/internal/scanner"
	"github.com/agentgate/agentgate/internal/types"
)

type Engine struct {
	startedAt time.Time

	// Subsystems
	approvals ApprovalStore
	vault     SecretVault
	policy    *PolicyManager
	runtimes  *RuntimeSupervisor

	// Registrations (Memory-first, DB-confirmed)
	regMu         sync.RWMutex
	registrations map[string]adapterState

	// Infrastructure
	eventStore EventStore
	stateStore StateStore

	// Temporary config for initialization
	init struct {
		detector          scanner.Detector
		injectionDetector scanner.InjectionDetector
		policyBundle      policy.Bundle
		policyBundles     []policy.Bundle
	}

	eventMu            sync.RWMutex
	events             []types.EventEnvelope
	maxEvents          int
	eventRetentionDays int
	eventStopCh        chan struct{}
}

type EventStore interface {
	AppendEvent(ctx context.Context, event types.EventEnvelope) error
	ListEvents(ctx context.Context, limit int) ([]types.EventEnvelope, error)
	GetEventByDecisionID(ctx context.Context, decisionID string) (types.EventEnvelope, bool, error)
	PruneEvents(ctx context.Context, before time.Time) (int64, error)
}

type StateStore interface {
	UpsertAdapterRegistration(ctx context.Context, registration types.AdapterRegistration, registeredAt time.Time, lastSeenAt time.Time) error
	ListAdapterRegistrations(ctx context.Context) ([]types.AdapterCoverage, error)
	SaveIntegrationDefinition(ctx context.Context, definition types.IntegrationDefinition, now time.Time) error
	GetIntegrationDefinition(ctx context.Context, integrationID string) (types.IntegrationDefinition, bool, error)
	ListIntegrationDefinitions(ctx context.Context) ([]types.IntegrationDefinition, error)
	DeleteIntegrationDefinition(ctx context.Context, integrationID string) error
	SaveApproval(ctx context.Context, approval types.ApprovalRecord) error
	ResolveApprovalAtomic(ctx context.Context, command types.ApprovalResolveCommand, event types.EventEnvelope) (types.ApprovalResolveResult, error)
	GetApproval(ctx context.Context, approvalID string) (types.ApprovalRecord, bool, error)
	ListApprovals(ctx context.Context, limit int) ([]types.ApprovalRecord, error)
	SaveAttemptGrant(ctx context.Context, sessionID string, taskID string, attemptID string, approvalID string, expiresAt time.Time) error
	GetAttemptGrant(ctx context.Context, sessionID string, taskID string, attemptID string) (types.AttemptGrant, bool, error)
	SaveSecretHandle(ctx context.Context, handle types.SecretHandle, value string) error
	GetSecretHandle(ctx context.Context, handleID string) (types.SecretHandle, string, bool, error)
	SavePolicyVersion(ctx context.Context, bundle policy.Bundle, publishedBy string, message string, sourceVersion int, publishedAt time.Time) (policy.VersionRecord, error)
	SavePolicyVersionAtomic(ctx context.Context, bundle policy.Bundle, publishedBy string, message string, sourceVersion int, publishedAt time.Time, event types.EventEnvelope) (policy.VersionRecord, error)
	GetActivePolicyBundle(ctx context.Context) (policy.Bundle, policy.VersionRecord, bool, error)
	GetPolicyBundleVersion(ctx context.Context, version int) (policy.Bundle, policy.VersionRecord, bool, error)
	ListPolicyVersions(ctx context.Context, limit int) ([]policy.VersionRecord, error)
	SavePolicyBundle(ctx context.Context, bundle policy.Bundle) error
	GetPolicyBundle(ctx context.Context, bundleID string) (policy.Bundle, bool, error)
	ListPolicyBundles(ctx context.Context, includeArchived bool) ([]policy.Bundle, error)
	ArchivePolicyBundle(ctx context.Context, bundleID string, updatedAt time.Time) error
	GetSessionFacts(ctx context.Context, sessionID string) (types.SessionFactsRecord, bool, error)
	UpsertSessionFacts(ctx context.Context, record types.SessionFactsRecord) error
	UpdateSessionFacts(ctx context.Context, sessionID string, update func(ctx context.Context, record types.SessionFactsRecord, found bool) (types.SessionFactsRecord, error)) error
	ListSecretHandles(ctx context.Context) ([]types.SecretHandleHydration, error)
	ListAttemptGrants(ctx context.Context) ([]types.AttemptGrantHydration, error)
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
const secretHandleTTL = 1 * time.Hour

var idCounter atomic.Uint64

func NewEngine(options ...Option) *Engine {
	engine := &Engine{
		startedAt:          time.Now().UTC(),
		registrations:      make(map[string]adapterState),
		events:             make([]types.EventEnvelope, 0, 128),
		maxEvents:          10000,
		eventRetentionDays: 30,
	}
	// Defaults
	engine.init.detector = scanner.RegexDetector{}
	engine.init.injectionDetector = scanner.RegexInjectionDetector{}
	engine.init.policyBundle = policy.DefaultBundle()
	engine.init.policyBundles = []policy.Bundle{policy.CorePolicyBundle(), defaultPolicyBundle(policy.DefaultBundle())}

	for _, option := range options {
		option(engine)
	}

	// Initialize subsystems
	engine.approvals = newApprovalStore(engine.stateStore)
	engine.vault = newSecretVault(engine.stateStore, engine.init.detector, engine.init.injectionDetector)
	engine.policy = newPolicyManager(engine.stateStore, engine.init.policyBundle, engine.init.policyBundles)
	engine.runtimes = newRuntimeSupervisor()

	engine.hydrateFromStore()
	engine.bootstrapManagedRuntimes(context.Background())
	engine.startEventCleanup()
	return engine
}

func (e *Engine) hydrateFromStore() {
	if e.stateStore == nil {
		return
	}

	ctx := context.Background()
	if err := e.approvals.Hydrate(ctx); err != nil {
		log.Printf("hydrate approvals: %v", err)
	}
	if err := e.vault.Hydrate(ctx); err != nil {
		log.Printf("hydrate secret handles: %v", err)
	}
	if err := e.policy.Hydrate(ctx); err != nil {
		log.Printf("hydrate policy: %v", err)
	}
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
		bundles := ensureCorePolicy([]policy.Bundle{bundle})
		engine.init.policyBundles = bundles
		engine.init.policyBundle = aggregateBundles(bundles)
	}
}

func WithPolicyBundles(bundles []policy.Bundle) Option {
	return func(engine *Engine) {
		engine.init.policyBundles = ensureCorePolicy(clonePolicyBundles(bundles))
		if len(engine.init.policyBundles) > 0 {
			engine.init.policyBundle = aggregateBundles(engine.init.policyBundles)
		}
	}
}

func WithDetector(d scanner.Detector) Option {
	return func(engine *Engine) {
		engine.init.detector = d
	}
}

func WithInjectionDetector(d scanner.InjectionDetector) Option {
	return func(engine *Engine) {
		engine.init.injectionDetector = d
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
	e.eventMu.Lock()
	e.eventStopCh = make(chan struct{})
	e.eventMu.Unlock()
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
			case <-e.stopCh():
				return
			}
		}
	}()
}

func (e *Engine) stopCh() <-chan struct{} {
	e.eventMu.RLock()
	defer e.eventMu.RUnlock()
	return e.eventStopCh
}

func (e *Engine) pruneOldEvents() {
	before := time.Now().UTC().Add(-time.Duration(e.eventRetentionDays) * 24 * time.Hour)
	ctx := context.Background()
	if e.eventStore != nil {
		n, err := e.eventStore.PruneEvents(ctx, before)
		if err != nil {
			log.Printf("prune events: %v", err)
			return
		}
		if n > 0 {
			log.Printf("prune events: deleted %d events older than %d days", n, e.eventRetentionDays)
		}
		return
	}
	e.eventMu.Lock()
	defer e.eventMu.Unlock()
	cutoff := 0
	for i, event := range e.events {
		if event.OccurredAt.After(before) {
			cutoff = i
			break
		}
	}
	if cutoff > 0 {
		e.events = append([]types.EventEnvelope(nil), e.events[cutoff:]...)
	}
}

func (e *Engine) Close() {
	e.eventMu.Lock()
	defer e.eventMu.Unlock()
	if e.eventStopCh != nil {
		close(e.eventStopCh)
		e.eventStopCh = nil
	}
}

func (e *Engine) StartedAt() time.Time {
	return e.startedAt
}

func (e *Engine) PolicyStatus(ctx context.Context) map[string]interface{} {
	bundle := e.policy.Active(context.Background()).bundle
	return map[string]interface{}{
		"version":   bundle.Version,
		"status":    bundle.StatusValue(),
		"issued_at": bundle.IssuedAt,
	}
}

func (e *Engine) bootstrapManagedRuntimes(ctx context.Context) {
	if e.stateStore == nil {
		return
	}
	definitions, err := e.stateStore.ListIntegrationDefinitions(ctx)
	if err != nil {
		log.Printf("bootstrap managed runtimes: %v", err)
		return
	}
	for _, definition := range definitions {
		if err := e.reconcileManagedRuntime(ctx, definition); err != nil {
			e.runtimes.setError(ctx, definition.ID, "bootstrap_failed", err)
		}
	}
}

func (e *Engine) reconcileManagedRuntime(ctx context.Context, definition types.IntegrationDefinition) error {
	return e.runtimes.Ensure(ctx, definition)
}

func (e *Engine) CurrentPolicy(ctx context.Context) PolicyCurrentResponse {
	active := e.policy.Active(ctx)
	return PolicyCurrentResponse{
		Bundle: active.bundle,
		Record: active.record,
	}
}

func (e *Engine) PolicyBundles(ctx context.Context, includeArchived bool) (PolicyBundlesResponse, error) {
	if e.stateStore != nil {
		bundles, err := e.stateStore.ListPolicyBundles(ctx, includeArchived)
		if err != nil {
			return PolicyBundlesResponse{}, errStatus(http.StatusInternalServerError, "state_store_read_failed", err.Error())
		}
		return PolicyBundlesResponse{Bundles: bundles}, nil
	}
	active := e.policy.Active(ctx)
	bundles := active.bundles
	if !includeArchived {
		filtered := bundles[:0]
		for _, bundle := range bundles {
			if bundle.Status != policy.BundleStatusArchived {
				filtered = append(filtered, bundle)
			}
		}
		bundles = filtered
	}
	return PolicyBundlesResponse{Bundles: bundles}, nil
}

func (e *Engine) GetPolicyBundle(ctx context.Context, bundleID string) (policy.Bundle, error) {
	if bundleID == "" {
		return policy.Bundle{}, errBadRequest("missing_bundle_id", "bundle_id is required")
	}
	if e.stateStore != nil {
		bundle, found, err := e.stateStore.GetPolicyBundle(ctx, bundleID)
		if err != nil {
			return policy.Bundle{}, errStatus(http.StatusInternalServerError, "state_store_read_failed", err.Error())
		}
		if !found {
			return policy.Bundle{}, errStatus(http.StatusNotFound, "policy_bundle_not_found", "policy bundle was not found")
		}
		return bundle, nil
	}
	active := e.policy.Active(ctx)
	for _, bundle := range active.bundles {
		if bundle.BundleID == bundleID {
			return bundle, nil
		}
	}
	return policy.Bundle{}, errStatus(http.StatusNotFound, "policy_bundle_not_found", "policy bundle was not found")
}

func (e *Engine) CreatePolicyBundle(ctx context.Context, bundle policy.Bundle) (policy.Bundle, error) {
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
	if e.stateStore != nil {
		if err := e.stateStore.SavePolicyBundle(ctx, bundle); err != nil {
			return policy.Bundle{}, errStatus(http.StatusInternalServerError, "state_store_write_failed", err.Error())
		}
	}
	return bundle, nil
}

func (e *Engine) UpdatePolicyBundle(ctx context.Context, bundleID string, bundle policy.Bundle) (policy.Bundle, error) {
	current, err := e.GetPolicyBundle(ctx, bundleID)
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
	if e.stateStore != nil {
		if err := e.stateStore.SavePolicyBundle(ctx, bundle); err != nil {
			return policy.Bundle{}, errStatus(http.StatusInternalServerError, "state_store_write_failed", err.Error())
		}
	}
	return bundle, nil
}

func (e *Engine) DeletePolicyBundle(ctx context.Context, bundleID string) error {
	if bundleID == "" {
		return errBadRequest("missing_bundle_id", "bundle_id is required")
	}
	now := time.Now().UTC()
	if e.stateStore != nil {
		if err := e.stateStore.ArchivePolicyBundle(ctx, bundleID, now); err != nil {
			return errStatus(http.StatusInternalServerError, "state_store_write_failed", err.Error())
		}
	}
	return nil
}

func (e *Engine) ValidatePolicyBundle(ctx context.Context, bundleID string) (PolicyValidationResponse, error) {
	bundle, err := e.GetPolicyBundle(ctx, bundleID)
	if err != nil {
		return PolicyValidationResponse{}, err
	}
	return e.ValidatePolicy(ctx, bundle), nil
}

func (e *Engine) PublishPolicyBundle(ctx context.Context, bundleID string) (policy.Bundle, error) {
	bundle, err := e.GetPolicyBundle(ctx, bundleID)
	if err != nil {
		return policy.Bundle{}, err
	}
	bundle.Status = policy.BundleStatusActive
	bundle.UpdatedAt = time.Now().UTC()
	if err := validateManagedBundle(bundle); err != nil {
		return policy.Bundle{}, err
	}
	if e.stateStore != nil {
		if err := e.stateStore.SavePolicyBundle(ctx, bundle); err != nil {
			return policy.Bundle{}, errStatus(http.StatusInternalServerError, "state_store_write_failed", err.Error())
		}
	}
	return bundle, nil
}

func (e *Engine) ValidatePolicy(ctx context.Context, bundle policy.Bundle) PolicyValidationResponse {
	if err := bundle.Validate(); err != nil {
		return PolicyValidationResponse{
			Valid:  false,
			Errors: []string{err.Error()},
		}
	}
	return policyValidationSuccess(bundle)
}

func (e *Engine) PolicyVersions(ctx context.Context, limit int) (PolicyVersionsResponse, error) {
	if e.stateStore != nil {
		records, err := e.stateStore.ListPolicyVersions(ctx, limit)
		if err != nil {
			return PolicyVersionsResponse{}, errStatus(http.StatusInternalServerError, "state_store_read_failed", err.Error())
		}
		return PolicyVersionsResponse{Versions: records}, nil
	}
	return PolicyVersionsResponse{Versions: []policy.VersionRecord{e.policy.Active(context.Background()).record}}, nil
}

func (e *Engine) PublishPolicy(ctx context.Context, req PolicyPublishRequest) (PolicyCurrentResponse, error) {
	if err := req.Bundle.Validate(); err != nil {
		return PolicyCurrentResponse{}, errBadRequest("invalid_policy_bundle", err.Error())
	}

	now := time.Now().UTC()
	event := types.EventEnvelope{
		EventID:   newID("evt_policy"),
		EventType: "policy_published",
		Summary:   "policy published",
		Metadata: map[string]interface{}{
			"operator_id":    req.OperatorID,
			"message":        req.Message,
			"published_at":   now.Format(time.RFC3339Nano),
		},
		OccurredAt: now,
	}
	return e.policy.Publish(ctx, req.Bundle, req.OperatorID, req.Message, 0, now, event)
}

func (e *Engine) RollbackPolicy(ctx context.Context, req PolicyRollbackRequest) (PolicyCurrentResponse, error) {
	if req.Version <= 0 {
		return PolicyCurrentResponse{}, errBadRequest("invalid_policy_version", "version must be positive")
	}

	now := time.Now().UTC()
	event := types.EventEnvelope{
		EventID:   newID("evt_policy"),
		EventType: "policy_rolled_back",
		Summary:   fmt.Sprintf("rolled back to version %d", req.Version),
		Metadata: map[string]interface{}{
			"operator_id":    req.OperatorID,
			"message":        req.Message,
			"source_version": req.Version,
			"published_at":   now.Format(time.RFC3339Nano),
		},
		OccurredAt: now,
	}
	return e.policy.Rollback(ctx, req.Version, req.OperatorID, req.Message, now, event)
}

func (e *Engine) Integrations(ctx context.Context) (types.IntegrationsResponse, error) {
	definitions, err := e.integrationDefinitions(ctx)
	if err != nil {
		return types.IntegrationsResponse{}, err
	}
	if definitions == nil {
		definitions = []types.IntegrationDefinition{}
	}
	adapters, err := e.adapterCoverages(ctx)
	if err != nil {
		return types.IntegrationsResponse{}, err
	}
	now := time.Now().UTC()
	for index := range definitions {
		definitions[index] = e.hydrateIntegrationHealth(ctx, definitions[index], adapters, now)
	}
	sort.SliceStable(definitions, func(i, j int) bool {
		if definitions[i].Enabled == definitions[j].Enabled {
			return definitions[i].ID < definitions[j].ID
		}
		return definitions[i].Enabled
	})
	return types.IntegrationsResponse{Integrations: definitions}, nil
}

func (e *Engine) GetIntegration(ctx context.Context, integrationID string) (types.IntegrationDefinition, error) {
	if integrationID == "" {
		return types.IntegrationDefinition{}, errBadRequest("missing_integration_id", "integration id is required")
	}
	definition, found, err := e.integrationDefinition(ctx, integrationID)
	if err != nil {
		return types.IntegrationDefinition{}, err
	}
	if !found {
		return types.IntegrationDefinition{}, errStatus(http.StatusNotFound, "integration_not_found", "integration definition was not found")
	}
	adapters, err := e.adapterCoverages(ctx)
	if err != nil {
		return types.IntegrationDefinition{}, err
	}
	return e.hydrateIntegrationHealth(ctx, definition, adapters, time.Now().UTC()), nil
}

func (e *Engine) SaveIntegration(ctx context.Context, definition types.IntegrationDefinition) (types.IntegrationDefinition, error) {
	normalized, err := normalizeIntegrationDefinition(definition)
	if err != nil {
		return types.IntegrationDefinition{}, errBadRequest("invalid_integration_definition", err.Error())
	}
	now := time.Now().UTC()
	if e.stateStore != nil {
		if err := e.stateStore.SaveIntegrationDefinition(ctx, normalized, now); err != nil {
			return types.IntegrationDefinition{}, errStatus(http.StatusInternalServerError, "state_store_write_failed", err.Error())
		}
	}
	adapters, err := e.adapterCoverages(ctx)
	if err != nil {
		return types.IntegrationDefinition{}, err
	}
	if err := e.reconcileManagedRuntime(ctx, normalized); err != nil {
		return types.IntegrationDefinition{}, errStatus(http.StatusInternalServerError, "managed_runtime_reconcile_failed", err.Error())
	}
	return e.hydrateIntegrationHealth(ctx, normalized, adapters, now), nil
}

func (e *Engine) DeleteIntegration(ctx context.Context, integrationID string) error {
	if integrationID == "" {
		return errBadRequest("missing_integration_id", "integration id is required")
	}
	e.runtimes.Stop(ctx, integrationID)
	if e.stateStore != nil {
		if err := e.stateStore.DeleteIntegrationDefinition(ctx, integrationID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errStatus(http.StatusNotFound, "integration_not_found", "integration definition was not found")
			}
			return errStatus(http.StatusInternalServerError, "state_store_write_failed", err.Error())
		}
		return nil
	}
	return errStatus(http.StatusNotFound, "integration_not_found", "integration definition was not found")
}

func (e *Engine) integrationDefinitions(ctx context.Context) ([]types.IntegrationDefinition, error) {
	if e.stateStore != nil {
		definitions, err := e.stateStore.ListIntegrationDefinitions(ctx)
		if err != nil {
			return nil, errStatus(http.StatusInternalServerError, "state_store_read_failed", err.Error())
		}
		return definitions, nil
	}
	return []types.IntegrationDefinition{}, nil
}

func (e *Engine) integrationDefinition(ctx context.Context, integrationID string) (types.IntegrationDefinition, bool, error) {
	if e.stateStore != nil {
		definition, found, err := e.stateStore.GetIntegrationDefinition(ctx, integrationID)
		if err != nil {
			return types.IntegrationDefinition{}, false, errStatus(http.StatusInternalServerError, "state_store_read_failed", err.Error())
		}
		return definition, found, nil
	}
	return types.IntegrationDefinition{}, false, nil
}

func (e *Engine) adapterCoverages(ctx context.Context) ([]types.AdapterCoverage, error) {
	if e.stateStore != nil {
		adapters, err := e.stateStore.ListAdapterRegistrations(ctx)
		if err != nil {
			return nil, errStatus(http.StatusInternalServerError, "state_store_read_failed", err.Error())
		}
		return adapters, nil
	}
	e.regMu.RLock()
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
	e.regMu.RUnlock()
	return adapters, nil
}

func (e *Engine) hydrateIntegrationHealth(ctx context.Context, definition types.IntegrationDefinition, adapters []types.AdapterCoverage, now time.Time) types.IntegrationDefinition {
	definition.Health = types.IntegrationHealth{ComputedAt: now}
	definition.MatchedAdapters = nil
	definition.Health.Runtime = e.runtimes.View(ctx, definition.ID)
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

func (e *Engine) RegisterAdapter(ctx context.Context, req types.AdapterRegistration) (types.RegistrationResult, error) {
	if req.AdapterID == "" {
		return types.RegistrationResult{}, errBadRequest("missing_adapter_id", "adapter_id is required")
	}
	if err := validateRegistration(req); err != nil {
		return types.RegistrationResult{}, errBadRequest("invalid_registration", err.Error())
	}

	// Enforce identity binding if configured.
	if principal, ok := authz.PrincipalFromContext(ctx); ok && principal.Bound {
		if req.AdapterID != principal.ID && req.IntegrationID != principal.ID {
			return types.RegistrationResult{}, errStatus(http.StatusForbidden, "identity_binding_violation",
				fmt.Sprintf("token is bound to identity %q, but request uses adapter %q / integration %q",
					principal.ID, req.AdapterID, req.IntegrationID))
		}
	}

	if len(req.Surfaces) == 0 && len(req.SupportingChannels) == 0 {
		return types.RegistrationResult{}, errBadRequest("missing_coverage", "at least one surface or supporting channel is required")
	}

	now := time.Now().UTC()
	if e.stateStore != nil {
		if err := e.stateStore.UpsertAdapterRegistration(ctx, req, now, now); err != nil {
			return types.RegistrationResult{}, errStatus(http.StatusInternalServerError, "state_store_write_failed", err.Error())
		}
	}
	e.regMu.Lock()
	e.registrations[req.AdapterID] = adapterState{
		registration: req,
		registeredAt: now,
		lastSeenAt:   now,
	}
	e.regMu.Unlock()

	metadata := map[string]interface{}{"adapter_kind": req.AdapterKind, "host_kind": req.Host.Kind}
	if req.IntegrationID != "" {
		metadata["integration_id"] = req.IntegrationID
	}
	if err := e.appendEvent(ctx, types.EventEnvelope{
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

func (e *Engine) Coverage(ctx context.Context) types.CoverageResponse {
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
		adapters, err := e.stateStore.ListAdapterRegistrations(ctx)
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

	e.regMu.RLock()
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
	e.regMu.RUnlock()

	for _, surface := range []types.Surface{types.SurfaceInput, types.SurfaceRuntime, types.SurfaceResource} {
		if response.Surfaces[surface] == 0 {
			response.Warnings = append(response.Warnings, fmt.Sprintf("no adapter registered for %s surface", surface))
		}
	}

	return response
}

func (e *Engine) Approvals(ctx context.Context, limit int) (types.ApprovalsResponse, error) {
	approvals, err := e.approvals.List(ctx, limit)
	if err != nil {
		return types.ApprovalsResponse{}, errStatus(http.StatusInternalServerError, "state_store_read_failed", err.Error())
	}
	return types.ApprovalsResponse{Approvals: approvals}, nil
}

func (e *Engine) Decide(ctx context.Context, req types.PolicyRequest) (types.PolicyDecision, error) {
	if req.RequestID == "" {
		req.RequestID = newID("req")
	}
	if req.RequestKind == types.RequestKindToolAttempt && req.Session.AttemptID == "" {
		req.Session.AttemptID = req.RequestID
	}

	// Enforce identity binding if configured.
	if principal, ok := authz.PrincipalFromContext(ctx); ok && principal.Bound && principal.Role == authz.RoleAdapter {
		integrationID := strings.TrimSpace(mapStringValue(req.Policy, "integration_id"))
		if integrationID == "" {
			integrationID = strings.TrimSpace(mapStringValue(req.Context.Raw, "integration_id"))
		}
		if integrationID != principal.ID {
			return types.PolicyDecision{}, errStatus(http.StatusForbidden, "identity_binding_violation",
				fmt.Sprintf("token is bound to integration %q, but request uses %q", principal.ID, integrationID))
		}
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
	var newTaints []types.Taint

	activePolicy := e.policy.Active(ctx)

	decisionReady := false
	if patch := validateDecisionRequest(req, surface); patch != nil {
		policyEvaluation = requestValidationEvaluation(patch)
		effect = patch.effect
		reason = patch.reason
		appliedRules = patch.appliedRules
		obligations = append([]types.Obligation(nil), patch.obligations...)
		decisionReady = true
	}

	var inputFacts inputSecretFacts
	var sessionFacts types.SessionFacts
	if !decisionReady {
		var enrichErr error
		inputFacts, enrichErr = e.enrichPolicyFacts(ctx, &req)
		if enrichErr != nil {
			policyEvaluation = requestValidationEvaluation(&decisionPatch{
				effect:       types.EffectDeny,
				reason:       "secret_detection_failed",
				appliedRules: []string{"core.secret_detection.fail_closed"},
				obligations:  []types.Obligation{abortTaskObligation()},
			})
			effect = types.EffectDeny
			reason = "secret_detection_failed"
			appliedRules = []string{"core.secret_detection.fail_closed"}
			obligations = []types.Obligation{abortTaskObligation()}
			decisionReady = true
		}

		if surface == types.SurfaceRuntime {
			if req.Action.OpenWorld || containsSideEffect(req.Action.SideEffects, types.SideEffectNetworkEgress) {
				req.Context.Taints = appendTaintOnce(req.Context.Taints, types.TaintUntrustedExternal)
			}
		}

		newTaints = append([]types.Taint(nil), req.Context.Taints...)

		var err error
		sessionFacts, err = e.sessionFactsForDecision(ctx, req.Session.SessionID)
		if err != nil {
			log.Printf("session facts read failed, proceeding with empty facts: %v", err)
			sessionFacts = types.SessionFacts{}
		}

		req.Context.Taints = mergeTaints(req.Context.Taints, sessionFacts.Taints)
		if len(inputFacts.findings) > 0 {
			if req.Context.Raw == nil {
				req.Context.Raw = make(map[string]interface{})
			}
			req.Context.Raw["has_secret_findings"] = true
		}
	}

	if !decisionReady && req.RequestKind == types.RequestKindToolAttempt && surface == types.SurfaceRuntime {
		if grant, ok, err := e.approvals.ValidGrant(ctx, req.Session, now); err == nil && ok {
			effect = types.EffectAllowWithAudit
			reason = "user_allow_once_valid"
			appliedRules = []string{"runtime.high_risk.allow_once_grant"}
			obligations = []types.Obligation{auditObligation("info", map[string]interface{}{"approval_id": grant.ApprovalID})}
			policyEvaluation = policy.Evaluation{Effect: effect, ReasonCode: reason, AppliedRules: appliedRules}
			decisionReady = true
		}
	}

	if !decisionReady {
		policyEvaluation = policy.EvaluateBundles(activePolicy.bundles, req, sessionFacts)
		effect = policyEvaluation.Effect
		reason = policyEvaluation.ReasonCode
		appliedRules = append([]string(nil), policyEvaluation.AppliedRules...)
		obligations = append([]types.Obligation(nil), policyEvaluation.Obligations...)

		// Safety check: EffectApprovalRequired must have an approval_request obligation.
		if effect == types.EffectApprovalRequired && !hasObligation(obligations, types.ObligationApprovalRequest) {
			effect = types.EffectDeny
			reason = "broken_approval_rule"
			appliedRules = append(appliedRules, "core.safety.missing_obligation")
			obligations = []types.Obligation{abortTaskObligation()}
		}
	}

	if enriched, patch := e.executeObligations(ctx, obligations, req, inputFacts, reason, now); patch != nil {
		effect = patch.effect
		reason = patch.reason
		appliedRules = patch.appliedRules
		obligations = patch.obligations
	} else {
		obligations = enriched
	}

	if isValidSurface(surface) && !e.hasCoverage(ctx, surface) {
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
			PolicyTrace: policyTrace(activePolicy.bundle, policyEvaluation),
		},
		DecidedAt: now,
	}
	traceMetadata := decision.Explanation.PolicyTrace

	metadata := map[string]interface{}{
		"request_kind":        req.RequestKind,
		"actor_user":          req.Actor.UserID,
		"host_id":             req.Actor.HostID,
		"integration_id":      mapStringValue(req.Policy, "integration_id"),
		"operation":           req.Action.Operation,
		"tool":                req.Action.Tool,
		"content_summary":     req.Content.Summary,
		"side_effects":        append([]types.SideEffect(nil), req.Action.SideEffects...),
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
	}

	if effect == types.EffectAllowWithAudit {
		metadata["audit_trigger"] = auditTrigger(obligations, reason)
		metadata["matched_rule_count"] = len(traceMetadata.MatchedRules)
	}

	if err := e.appendEvent(ctx, types.EventEnvelope{
		EventID:    newID("evt_decide"),
		EventType:  "policy_decision",
		RequestID:  req.RequestID,
		DecisionID: decision.DecisionID,
		SessionID:  req.Session.SessionID,
		Surface:    surface,
		Effect:     effect,
		Summary:    reason,
		Metadata:   metadata,
		OccurredAt: now,
	}); err != nil {
		return types.PolicyDecision{}, errStatus(http.StatusInternalServerError, "event_store_write_failed", err.Error())
	}

	if err := e.updateSessionFactsFromDecision(ctx, req, decision, newTaints, now); err != nil {
		log.Printf("session facts update failed: %v", err)
	}

	return decision, nil
}

func (e *Engine) Report(ctx context.Context, req types.ReportRequest) (types.ReportResponse, error) {
	if req.RequestID == "" && req.DecisionID == "" {
		return types.ReportResponse{}, errBadRequest("missing_correlation", "request_id or decision_id is required")
	}

	now := time.Now().UTC()
	redactedMetadata, _, err := e.vault.RedactValue(ctx, req.Metadata)
	if err != nil {
		return types.ReportResponse{}, errStatus(http.StatusInternalServerError, "audit_redaction_failed", err.Error())
	}
	redactedError, err := e.vault.RedactString(ctx, req.ErrorMessage)
	if err != nil {
		return types.ReportResponse{}, errStatus(http.StatusInternalServerError, "audit_redaction_failed", err.Error())
	}
	if err := e.appendEvent(ctx, types.EventEnvelope{
		EventID:    newID("evt_report"),
		EventType:  "adapter_report",
		RequestID:  req.RequestID,
		DecisionID: req.DecisionID,
		AdapterID:  req.AdapterID,
		Surface:    req.Surface,
		Summary:    req.Outcome,
		Metadata: map[string]interface{}{
			"error_message": redactedError,
			"metadata":      redactedMetadata,
			"obligations":   obligationTypes(req.Obligations),
		},
		OccurredAt: now,
	}); err != nil {
		return types.ReportResponse{}, errStatus(http.StatusInternalServerError, "event_store_write_failed", err.Error())
	}

	return types.ReportResponse{Accepted: true, RecordedAt: now}, nil
}

func (e *Engine) ResolveApproval(ctx context.Context, approvalID string, req types.ApprovalResolveRequest) (types.ApprovalResolveResponse, error) {
	if approvalID == "" {
		return types.ApprovalResolveResponse{}, errBadRequest("missing_approval_id", "approval_id is required")
	}

	now := time.Now().UTC()
	command := types.ApprovalResolveCommand{
		ApprovalID: approvalID,
		Decision:   req.Decision,
		OperatorID: req.OperatorID,
		Channel:    req.Channel,
		ResolvedAt: now,
	}
	eventType := "approval_denied"
	if strings.Contains(strings.ToLower(strings.TrimSpace(req.Decision)), "allow") || strings.Contains(strings.ToLower(strings.TrimSpace(req.Decision)), "approve") {
		eventType = "approval_granted"
	}
	event := types.EventEnvelope{
		EventID:   newID("evt_approval"),
		EventType: eventType,
		Surface:   types.SurfaceRuntime,
		Summary:   strings.ToLower(strings.TrimSpace(req.Decision)),
		Metadata: map[string]interface{}{
			"approval_id": approvalID,
			"operator_id": req.OperatorID,
			"channel":     req.Channel,
		},
		OccurredAt: now,
	}
	result, err := e.approvals.Resolve(ctx, command, event)
	if err != nil {
		var coreErr *Error
		if errors.As(err, &coreErr) {
			return types.ApprovalResolveResponse{}, err
		}
		if errors.Is(err, sql.ErrNoRows) {
			return types.ApprovalResolveResponse{}, errStatus(http.StatusNotFound, "approval_not_found", "approval was not found")
		}
		return types.ApprovalResolveResponse{}, errStatus(http.StatusInternalServerError, "state_store_write_failed", err.Error())
	}
	return types.ApprovalResolveResponse{
		ApprovalID: approvalID,
		Status:     result.Approval.Status,
		ResolvedAt: now,
	}, nil
}

func (e *Engine) Events(ctx context.Context, limit int) ([]types.EventEnvelope, error) {
	if e.eventStore != nil {
		return e.eventStore.ListEvents(ctx, limit)
	}
	e.eventMu.RLock()
	events := append([]types.EventEnvelope(nil), e.events...)
	e.eventMu.RUnlock()
	if limit > 0 && len(events) > limit {
		events = events[len(events)-limit:]
	}
	return events, nil
}

func (e *Engine) executeObligations(ctx context.Context, obligations []types.Obligation, req types.PolicyRequest, facts inputSecretFacts, reason string, now time.Time) ([]types.Obligation, *decisionPatch) {
	capabilities, adapterFound := e.capabilitiesForRequest(ctx, req)
	enriched := make([]types.Obligation, 0, len(obligations))
	executed := make(map[types.ObligationType]bool)
	for _, ob := range obligations {
		switch ob.Type {
		case types.ObligationRewriteInput:
			if executed[ob.Type] {
				continue
			}
			if adapterFound && !capabilities.CanRewriteInput {
				return nil, capabilityDenialPatch("adapter_cannot_rewrite_input")
			}
			executed[ob.Type] = true
			result, patch := e.executeRewriteInput(ctx, req, facts, now)
			if patch != nil {
				return nil, patch
			}
			enriched = append(enriched, result)
			enriched = append(enriched, types.Obligation{
				Type: types.ObligationAuditEvent,
				Params: map[string]interface{}{
					"severity":        "warning",
					"finding_count":   len(facts.findings),
					"secret_findings": result.Params["secret_findings"],
				},
			})
		case types.ObligationResolveSecretHandle:
			if executed[ob.Type] {
				continue
			}
			executed[ob.Type] = true
			result, patch := e.executeResolveSecretHandle(ctx, req, now)
			if patch != nil {
				return nil, patch
			}
			enriched = append(enriched, result)
		case types.ObligationApprovalRequest:
			if executed[ob.Type] {
				continue
			}
			if adapterFound && !capabilities.CanPauseForApproval {
				return nil, capabilityDenialPatch("adapter_cannot_pause_for_approval")
			}
			executed[ob.Type] = true
			result, patch := e.executeApprovalRequest(ctx, req, reason, now)
			if patch != nil {
				return nil, patch
			}
			enriched = append(enriched, result)
		default:
			enriched = append(enriched, ob)
		}
	}
	return enriched, nil
}

func (e *Engine) executeRewriteInput(ctx context.Context, req types.PolicyRequest, facts inputSecretFacts, now time.Time) (types.Obligation, *decisionPatch) {
	if len(facts.findings) == 0 {
		return types.Obligation{Type: types.ObligationRewriteInput}, nil
	}

	rewritten, handles, summaries, err := e.vault.Rewrite(ctx, facts.text, req.Session.SessionID, req.Session.TaskID, now)
	if err != nil {
		return types.Obligation{}, &decisionPatch{
			effect:       types.EffectDeny,
			reason:       "secret_handle_store_failed",
			appliedRules: []string{"secret.handle.persist.fail_closed"},
			obligations:  []types.Obligation{abortTaskObligation()},
		}
	}

	return types.Obligation{
		Type: types.ObligationRewriteInput,
		Params: map[string]interface{}{
			"text":             rewritten,
			"bodyForAgent":     rewritten,
			"secret_findings":  summaries,
			"secret_handles":   handles,
			"redaction_policy": "placeholder_only",
		},
	}, nil
}

func (e *Engine) executeResolveSecretHandle(ctx context.Context, req types.PolicyRequest, now time.Time) (types.Obligation, *decisionPatch) {
	handle, value, err := e.vault.Resolve(ctx, req.Target.Identifier, req.Session.SessionID, req.Session.TaskID, now)
	if err != nil {
		var coreErr *Error
		if errors.As(err, &coreErr) && coreErr.Code == "secret_handle_scope_mismatch" {
			return types.Obligation{}, &decisionPatch{
				effect:       types.EffectDeny,
				reason:       "secret_handle_scope_mismatch",
				appliedRules: []string{"resource.secret_handle.scope"},
				obligations: []types.Obligation{
					auditObligation("critical", map[string]interface{}{"handle_id": req.Target.Identifier}),
					abortTaskObligation(),
				},
			}
		}
		if errors.As(err, &coreErr) && coreErr.Code == "secret_handle_expired" {
			return types.Obligation{}, &decisionPatch{
				effect:       types.EffectDeny,
				reason:       "secret_handle_expired",
				appliedRules: []string{"resource.secret_handle.expiry"},
				obligations: []types.Obligation{
					auditObligation("warning", map[string]interface{}{"handle_id": req.Target.Identifier}),
					abortTaskObligation(),
				},
			}
		}
		return types.Obligation{}, &decisionPatch{
			effect:       types.EffectDeny,
			reason:       "secret_handle_not_found",
			appliedRules: []string{"resource.secret_handle.lookup"},
			obligations: []types.Obligation{
				auditObligation("critical", map[string]interface{}{"handle_id": req.Target.Identifier}),
				abortTaskObligation(),
			},
		}
	}
	return types.Obligation{
		Type: types.ObligationResolveSecretHandle,
		Params: map[string]interface{}{
			"handle_id":    handle.HandleID,
			"placeholder":  handle.Placeholder,
			"kind":         handle.Kind,
			"secret_value": value,
		},
	}, nil
}

func (e *Engine) executeApprovalRequest(ctx context.Context, req types.PolicyRequest, reason string, now time.Time) (types.Obligation, *decisionPatch) {
	// Check for existing pending approval on the same attempt.
	if existing, _ := e.approvals.FindPending(ctx, req.Session.SessionID, req.Session.TaskID, req.Session.AttemptID, now); existing != nil {
		return types.Obligation{
			Type: types.ObligationApprovalRequest,
			Params: map[string]interface{}{
				"approval_id": existing.ApprovalID,
				"scope":       fmt.Sprintf("session:%s task:%s attempt:%s", existing.SessionID, existing.TaskID, existing.AttemptID),
				"channel":     existing.Channel,
				"expires_at":  existing.ExpiresAt,
				"reason":      existing.Reason,
			},
		}, nil
	}

	timeout := 10 * time.Minute
	active := e.policy.Active(context.Background())
	if active.bundle.RuntimePolicy.ApprovalTimeout.Duration > 0 {
		timeout = active.bundle.RuntimePolicy.ApprovalTimeout.Duration
	}

	approvalReason := reason
	if approvalReason == "" {
		approvalReason = "High-risk runtime attempt paused by AgentGate policy."
	}

	channel := e.approvalChannelForRequest(ctx, req)
	approval := types.ApprovalRecord{
		ApprovalID: newID("appr"),
		RequestID:  req.RequestID,
		SessionID:  req.Session.SessionID,
		TaskID:     req.Session.TaskID,
		AttemptID:  req.Session.AttemptID,
		Status:     types.ApprovalPending,
		Reason:     approvalReason,
		CreatedAt:  now,
		ExpiresAt:  now.Add(timeout),
		Channel:    channel,
	}

	if err := e.approvals.Create(ctx, approval); err != nil {
		return types.Obligation{}, &decisionPatch{
			effect:       types.EffectDeny,
			reason:       "approval_store_failed",
			appliedRules: []string{"core.approval.create.fail_closed"},
			obligations:  []types.Obligation{abortTaskObligation()},
		}
	}

	return types.Obligation{
		Type: types.ObligationApprovalRequest,
		Params: map[string]interface{}{
			"approval_id": approval.ApprovalID,
			"scope":       fmt.Sprintf("session:%s task:%s attempt:%s", approval.SessionID, approval.TaskID, approval.AttemptID),
			"expires_at":  approval.ExpiresAt,
			"channel":     approval.Channel,
			"reason":      approval.Reason,
		},
	}, nil
}

func (e *Engine) approvalChannelForRequest(ctx context.Context, req types.PolicyRequest) string {
	integrationID := strings.TrimSpace(mapStringValue(req.Policy, "integration_id"))
	if integrationID == "" {
		integrationID = strings.TrimSpace(mapStringValue(req.Context.Raw, "integration_id"))
	}
	if integrationID == "" {
		return ""
	}
	definition, found, err := e.integrationDefinition(ctx, integrationID)
	if err != nil || !found || !definition.Enabled {
		return ""
	}
	if definition.ApprovalChannel != "" {
		return definition.ApprovalChannel
	}
	return "default"
}

func (e *Engine) capabilitiesForRequest(ctx context.Context, req types.PolicyRequest) (types.AdapterCapabilities, bool) {
	integrationID := strings.TrimSpace(mapStringValue(req.Policy, "integration_id"))
	if integrationID == "" {
		integrationID = strings.TrimSpace(mapStringValue(req.Context.Raw, "integration_id"))
	}
	if integrationID == "" {
		return types.AdapterCapabilities{}, false
	}
	e.regMu.RLock()
	defer e.regMu.RUnlock()
	for _, state := range e.registrations {
		if state.registration.IntegrationID == integrationID {
			return state.registration.Capabilities, true
		}
	}
	return types.AdapterCapabilities{}, false
}

func (e *Engine) hasCoverage(ctx context.Context, surface types.Surface) bool {
	if e.stateStore != nil {
		adapters, err := e.stateStore.ListAdapterRegistrations(ctx)
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

	e.regMu.RLock()
	defer e.regMu.RUnlock()

	for _, state := range e.registrations {
		for _, registeredSurface := range state.registration.Surfaces {
			if registeredSurface == surface {
				return true
			}
		}
	}
	return false
}

func (e *Engine) sessionFactsForDecision(ctx context.Context, sessionID string) (types.SessionFacts, error) {
	if sessionID == "" || e.stateStore == nil {
		return types.SessionFacts{}, nil
	}
	record, found, err := e.stateStore.GetSessionFacts(ctx, sessionID)
	if err != nil {
		return types.SessionFacts{}, err
	}
	if !found {
		return types.SessionFacts{}, nil
	}
	return normalizeSessionFacts(record.Facts), nil
}

func (e *Engine) updateSessionFactsFromDecision(ctx context.Context, req types.PolicyRequest, decision types.PolicyDecision, newTaints []types.Taint, now time.Time) error {
	if e.stateStore == nil || req.Session.SessionID == "" {
		return nil
	}
	return e.stateStore.UpdateSessionFacts(ctx, req.Session.SessionID, func(ctx context.Context, record types.SessionFactsRecord, found bool) (types.SessionFactsRecord, error) {
		if !found {
			record = types.SessionFactsRecord{
				SessionID: req.Session.SessionID,
				Facts: types.SessionFacts{
					DistinctTargets:     []string{},
					DistinctTools:       []string{},
					DistinctReasonCodes: []string{},
					SideEffectSequence:  []types.SideEffect{},
					Taints:              []types.Taint{},
				},
			}
		}
		record.AdapterID = firstNonEmpty(record.AdapterID, stringValue(req.Policy["integration_id"]))
		record.UpdatedAt = now
		record.Facts = updateSessionFacts(record.Facts, req, decision, newTaints, now)
		return record, nil
	})
}

func updateSessionFacts(facts types.SessionFacts, req types.PolicyRequest, decision types.PolicyDecision, newTaints []types.Taint, now time.Time) types.SessionFacts {
	facts = normalizeSessionFacts(facts)
	facts.RequestCount++
	switch decision.Effect {
	case types.EffectDeny, types.EffectExclusion:
		facts.DenyCount++
	case types.EffectApprovalRequired:
		facts.ApprovalCount++
	case types.EffectAllow:
		facts.AllowCount++
	case types.EffectAllowWithAudit:
		facts.AllowCount++
		facts.AllowWithAuditCount++
	}
	facts.LastEffect = string(decision.Effect)
	if facts.FirstRequestAt == nil || facts.FirstRequestAt.IsZero() {
		first := now
		facts.FirstRequestAt = &first
	}
	facts.LastRequestAt = &now
	facts.DistinctTargets = addDistinct(facts.DistinctTargets, req.Target.Identifier)
	facts.DistinctTools = addDistinct(facts.DistinctTools, req.Action.Tool)
	facts.DistinctReasonCodes = addDistinct(facts.DistinctReasonCodes, decision.ReasonCode)
	facts.SideEffectSequence = append(facts.SideEffectSequence, req.Action.SideEffects...)
	if len(facts.SideEffectSequence) > 20 {
		facts.SideEffectSequence = facts.SideEffectSequence[len(facts.SideEffectSequence)-20:]
	}
	facts.Taints = mergeTaints(facts.Taints, newTaints)
	return facts
}

func mergeTaints(existing []types.Taint, additions []types.Taint) []types.Taint {
	for _, t := range additions {
		existing = appendTaintOnce(existing, t)
	}
	return existing
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
		facts.SideEffectSequence = []types.SideEffect{}
	}
	if facts.Taints == nil {
		facts.Taints = []types.Taint{}
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

func containsSideEffect(haystack []types.SideEffect, needle types.SideEffect) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func (e *Engine) appendEvent(ctx context.Context, event types.EventEnvelope) error {
	if e.eventStore != nil {
		return e.eventStore.AppendEvent(ctx, event)
	}
	e.eventMu.Lock()
	defer e.eventMu.Unlock()
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

func capabilityDenialPatch(reason string) *decisionPatch {
	return &decisionPatch{
		effect:       types.EffectDeny,
		reason:       reason,
		appliedRules: []string{"core.adapter.capability_check"},
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

func (e *Engine) enrichPolicyFacts(ctx context.Context, req *types.PolicyRequest) (inputSecretFacts, error) {
	text := extractScannableText(req)
	if text == "" {
		return inputSecretFacts{}, nil
	}

	findings, injFindings, err := e.vault.Detect(ctx, text)
	if err != nil {
		return inputSecretFacts{}, err
	}

	// Map findings to taints via the mapping layer.
	taints := scanner.FindingsToTaints(findings, injFindings)
	for _, t := range taints {
		req.Context.Taints = appendTaintOnce(req.Context.Taints, t)
	}

	// Set data classes for secret findings.
	if len(findings) > 0 {
		req.Content.DataClasses = appendDataClassOnce(req.Content.DataClasses, types.DataClassSecret)
		req.Content.DataClasses = appendDataClassOnce(req.Content.DataClasses, types.DataClassCredential)
	}

	return inputSecretFacts{text: text, findings: findings}, nil
}

func extractScannableText(req *types.PolicyRequest) string {
	switch req.Context.Surface {
	case types.SurfaceInput:
		text, ok := rawString(req.Context.Raw, "text")
		if !ok {
			text, _ = rawString(req.Context.Raw, "body")
		}
		return text
	case types.SurfaceRuntime:
		if text, ok := rawString(req.Context.Raw, "text"); ok {
			return text
		}
		return req.Content.Summary
	default:
		return ""
	}
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

func hasObligation(obligations []types.Obligation, obligationType types.ObligationType) bool {
	for _, ob := range obligations {
		if ob.Type == obligationType {
			return true
		}
	}
	return false
}

func auditObligation(severity string, params map[string]interface{}) types.Obligation {
	copied := map[string]interface{}{"severity": severity}
	for key, value := range params {
		copied[key] = value
	}
	return types.Obligation{Type: types.ObligationAuditEvent, Params: copied}
}

func auditTrigger(obligations []types.Obligation, reason string) string {
	triggers := make([]string, 0, len(obligations))
	for _, ob := range obligations {
		switch ob.Type {
		case types.ObligationRewriteInput:
			triggers = append(triggers, "secret_rewrite")
		case types.ObligationResolveSecretHandle:
			triggers = append(triggers, "secret_handle_access")
		case types.ObligationApprovalRequest:
			triggers = append(triggers, "approval_required")
		case types.ObligationTaskControl:
			triggers = append(triggers, "task_control")
		}
	}
	if len(triggers) == 0 {
		return reason
	}
	return strings.Join(triggers, ",")
}

func abortTaskObligation() types.Obligation {
	return types.Obligation{
		Type: types.ObligationTaskControl,
		Params: map[string]interface{}{
			"action": "abort_task",
		},
	}
}

func obligationTypes(obligations []types.Obligation) []types.ObligationType {
	result := make([]types.ObligationType, 0, len(obligations))
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
		if obligation.Type != types.ObligationApprovalRequest {
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
		if obligation.Type != types.ObligationApprovalRequest {
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
		if obligation.Type != types.ObligationApprovalRequest {
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
		if obligation.Type != types.ObligationApprovalRequest {
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

func mapString(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprint(value)
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
	if spec.Managed && len(spec.Command) == 0 {
		return fmt.Errorf("runtime.command is required")
	}
	for _, part := range spec.Command {
		if strings.TrimSpace(part) == "" {
			return fmt.Errorf("runtime.command entries must be non-empty")
		}
	}
	if spec.Restart.MaxAttempts < 0 {
		return fmt.Errorf("runtime.restart.max_attempts must be >= 0")
	}
	if spec.Restart.BackoffMs < 0 {
		return fmt.Errorf("runtime.restart.backoff_ms must be >= 0")
	}
	return nil
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
