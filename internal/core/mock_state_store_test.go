package core

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/agentgate/agentgate/internal/policy"
	"github.com/agentgate/agentgate/internal/types"
)

type memoryStateStore struct {
	mu            sync.RWMutex
	integrations  map[string]types.IntegrationDefinition
	policyHistory map[int]policy.Bundle
	policyRecords []policy.VersionRecord
	registrations map[string]types.AdapterCoverage
	approvals     map[string]types.ApprovalRecord
	grants        map[string]types.AttemptGrant
	secrets       map[string]types.SecretHandle
	secretValues  map[string]string
	sessionFacts  map[string]types.SessionFactsRecord
}

func newMemoryStateStore() *memoryStateStore {
	return &memoryStateStore{
		integrations:  make(map[string]types.IntegrationDefinition),
		policyHistory: make(map[int]policy.Bundle),
		registrations: make(map[string]types.AdapterCoverage),
		approvals:     make(map[string]types.ApprovalRecord),
		grants:        make(map[string]types.AttemptGrant),
		secrets:       make(map[string]types.SecretHandle),
		secretValues:  make(map[string]string),
		sessionFacts:  make(map[string]types.SessionFactsRecord),
	}
}

func (m *memoryStateStore) SaveIntegrationDefinition(definition types.IntegrationDefinition, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.integrations[definition.ID] = definition
	return nil
}

func (m *memoryStateStore) GetIntegrationDefinition(integrationID string) (types.IntegrationDefinition, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	def, ok := m.integrations[integrationID]
	return def, ok, nil
}

func (m *memoryStateStore) ListIntegrationDefinitions() ([]types.IntegrationDefinition, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var defs []types.IntegrationDefinition
	for _, def := range m.integrations {
		defs = append(defs, def)
	}
	return defs, nil
}

func (m *memoryStateStore) DeleteIntegrationDefinition(integrationID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.integrations[integrationID]; !ok {
		return sql.ErrNoRows
	}
	delete(m.integrations, integrationID)
	return nil
}

func (m *memoryStateStore) SavePolicyVersionAtomic(bundle policy.Bundle, publishedBy string, message string, sourceVersion int, publishedAt time.Time, event types.EventEnvelope) (policy.VersionRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.policyRecords {
		m.policyRecords[i].Active = false
	}
	record := policy.VersionRecord{
		Version:       bundle.Version,
		Status:        bundle.StatusValue(),
		Active:        true,
		RuleCount:     len(bundle.Rules),
		PublishedAt:   publishedAt,
		PublishedBy:   publishedBy,
		Message:       message,
		SourceVersion: sourceVersion,
	}
	m.policyRecords = append(m.policyRecords, record)
	m.policyHistory[bundle.Version] = bundle
	return record, nil
}

func (m *memoryStateStore) GetPolicyBundleVersion(version int) (policy.Bundle, policy.VersionRecord, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	bundle, ok := m.policyHistory[version]
	if !ok {
		return policy.Bundle{}, policy.VersionRecord{}, false, nil
	}
	for _, rec := range m.policyRecords {
		if rec.Version == version {
			return bundle, rec, true, nil
		}
	}
	return bundle, policy.VersionRecord{}, true, nil
}

func (m *memoryStateStore) ListPolicyVersions(limit int) ([]policy.VersionRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]policy.VersionRecord, len(m.policyRecords))
	copy(result, m.policyRecords)
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (m *memoryStateStore) UpsertAdapterRegistration(registration types.AdapterRegistration, registeredAt time.Time, lastSeenAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registrations[registration.AdapterID] = types.AdapterCoverage{
		AdapterID:          registration.AdapterID,
		IntegrationID:      registration.IntegrationID,
		AdapterKind:        registration.AdapterKind,
		Host:               registration.Host,
		Surfaces:           registration.Surfaces,
		SupportingChannels: registration.SupportingChannels,
		RegisteredAt:       registeredAt,
		LastSeenAt:         lastSeenAt,
	}
	return nil
}

func (m *memoryStateStore) ListAdapterRegistrations() ([]types.AdapterCoverage, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []types.AdapterCoverage
	for _, reg := range m.registrations {
		result = append(result, reg)
	}
	return result, nil
}

func (m *memoryStateStore) SaveApproval(approval types.ApprovalRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.approvals[approval.ApprovalID] = approval
	return nil
}

func (m *memoryStateStore) ResolveApprovalAtomic(command types.ApprovalResolveCommand, event types.EventEnvelope) (types.ApprovalResolveResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	record, ok := m.approvals[command.ApprovalID]
	if !ok {
		return types.ApprovalResolveResult{}, sql.ErrNoRows
	}
	if record.Status != types.ApprovalPending {
		return types.ApprovalResolveResult{}, fmt.Errorf("already resolved")
	}

	record.Status = types.ApprovalStatus(command.Decision)
	if !record.ExpiresAt.After(command.ResolvedAt) {
		record.Status = types.ApprovalExpired
	}
	record.ResolvedAt = &command.ResolvedAt
	record.OperatorID = command.OperatorID
	record.Channel = command.Channel
	m.approvals[record.ApprovalID] = record

	var grant *types.AttemptGrant
	if record.Status == "approve" || record.Status == "approved" || record.Status == "allow_once" {
		record.Status = types.ApprovalApproved
		g := types.AttemptGrant{
			ApprovalID: record.ApprovalID,
			ExpiresAt:  record.ExpiresAt,
		}
		grant = &g
		key := fmt.Sprintf("%s:%s:%s", record.SessionID, record.TaskID, record.AttemptID)
		m.grants[key] = g
	}

	return types.ApprovalResolveResult{Approval: record, Grant: grant}, nil
}

func (m *memoryStateStore) GetApproval(approvalID string) (types.ApprovalRecord, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.approvals[approvalID]
	return a, ok, nil
}

func (m *memoryStateStore) ListApprovals(limit int) ([]types.ApprovalRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []types.ApprovalRecord
	for _, a := range m.approvals {
		result = append(result, a)
	}
	return result, nil
}

func (m *memoryStateStore) SaveAttemptGrant(sessionID string, taskID string, attemptID string, approvalID string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s:%s:%s", sessionID, taskID, attemptID)
	m.grants[key] = types.AttemptGrant{ApprovalID: approvalID, ExpiresAt: expiresAt}
	return nil
}

func (m *memoryStateStore) GetAttemptGrant(sessionID string, taskID string, attemptID string) (types.AttemptGrant, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := fmt.Sprintf("%s:%s:%s", sessionID, taskID, attemptID)
	g, ok := m.grants[key]
	return g, ok, nil
}

func (m *memoryStateStore) SaveSecretHandle(handle types.SecretHandle, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secrets[handle.HandleID] = handle
	m.secretValues[handle.HandleID] = value
	return nil
}

func (m *memoryStateStore) GetSecretHandle(handleID string) (types.SecretHandle, string, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	h, ok := m.secrets[handleID]
	v := m.secretValues[handleID]
	return h, v, ok, nil
}

func (m *memoryStateStore) ListSecretHandles() ([]types.SecretHandleHydration, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []types.SecretHandleHydration
	for id, h := range m.secrets {
		result = append(result, types.SecretHandleHydration{Handle: h, Value: m.secretValues[id]})
	}
	return result, nil
}

func (m *memoryStateStore) ListAttemptGrants() ([]types.AttemptGrantHydration, error) {
	return nil, nil
}

func (m *memoryStateStore) SavePolicyVersion(bundle policy.Bundle, publishedBy string, message string, sourceVersion int, publishedAt time.Time) (policy.VersionRecord, error) {
	return m.SavePolicyVersionAtomic(bundle, publishedBy, message, sourceVersion, publishedAt, types.EventEnvelope{})
}

func (m *memoryStateStore) GetActivePolicyBundle() (policy.Bundle, policy.VersionRecord, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, rec := range m.policyRecords {
		if rec.Active {
			return m.policyHistory[rec.Version], rec, true, nil
		}
	}
	return policy.Bundle{}, policy.VersionRecord{}, false, nil
}

func (m *memoryStateStore) SavePolicyBundle(bundle policy.Bundle) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Mock: we'll just store it in history for simplicity or another map if needed.
	return nil
}

func (m *memoryStateStore) GetPolicyBundle(bundleID string) (policy.Bundle, bool, error) {
	// Mock
	return policy.Bundle{}, false, nil
}

func (m *memoryStateStore) ListPolicyBundles(includeArchived bool) ([]policy.Bundle, error) {
	return nil, nil
}

func (m *memoryStateStore) ArchivePolicyBundle(bundleID string, updatedAt time.Time) error { return nil }

func (m *memoryStateStore) GetSessionFacts(sessionID string) (types.SessionFactsRecord, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	f, ok := m.sessionFacts[sessionID]
	return f, ok, nil
}

func (m *memoryStateStore) UpsertSessionFacts(record types.SessionFactsRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessionFacts[record.SessionID] = record
	return nil
}

func (m *memoryStateStore) UpdateSessionFacts(sessionID string, update func(types.SessionFactsRecord, bool) (types.SessionFactsRecord, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	record, ok := m.sessionFacts[sessionID]
	newRecord, err := update(record, ok)
	if err != nil {
		return err
	}
	m.sessionFacts[sessionID] = newRecord
	return nil
}
