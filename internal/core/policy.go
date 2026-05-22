package core

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agentgate/agentgate/internal/policy"
	"github.com/agentgate/agentgate/internal/types"
)

type policySnapshot struct {
	bundle  policy.Bundle
	bundles []policy.Bundle
	record  policy.VersionRecord
}

type PolicyManager struct {
	active atomic.Value
	mu     sync.Mutex // Serializes write operations

	stateStore StateStore
}

func newPolicyManager(stateStore StateStore, bundle policy.Bundle, bundles []policy.Bundle) *PolicyManager {
	manager := &PolicyManager{stateStore: stateStore}
	record := policy.VersionRecord{
		Version:     bundle.Version,
		Status:      bundle.StatusValue(),
		Active:      true,
		RuleCount:   len(bundle.Rules),
		PublishedAt: bundle.IssuedAt,
		Message:     "initial policy",
	}
	manager.active.Store(&policySnapshot{
		bundle:  clonePolicyBundle(bundle),
		bundles: clonePolicyBundles(bundles),
		record:  record,
	})
	return manager
}

func (m *PolicyManager) Active(ctx context.Context) policySnapshot {
	return *(m.active.Load().(*policySnapshot))
}

func (m *PolicyManager) Publish(ctx context.Context, bundle policy.Bundle, operatorID string, message string, sourceVersion int, now time.Time, event types.EventEnvelope) (PolicyCurrentResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	current := m.Active(ctx)
	nextBundle := clonePolicyBundle(bundle)
	nextBundle.Version = max(current.bundle.Version+1, nextBundle.Version)
	nextBundle.Status = "active"
	nextBundle.IssuedAt = now

	var record policy.VersionRecord
	var err error
	if m.stateStore != nil {
		record, err = m.stateStore.SavePolicyVersionAtomic(ctx, nextBundle, operatorID, message, sourceVersion, now, event)
		if err != nil {
			return PolicyCurrentResponse{}, err
		}
	} else {
		record = policy.VersionRecord{
			Version:       nextBundle.Version,
			Status:        nextBundle.StatusValue(),
			Active:        true,
			RuleCount:     len(nextBundle.Rules),
			PublishedAt:   now,
			PublishedBy:   operatorID,
			Message:       message,
			SourceVersion: sourceVersion,
		}
	}

	nextBundles := ensureCorePolicy([]policy.Bundle{defaultPolicyBundle(nextBundle)})
	activeBundle := aggregateBundles(nextBundles)
	m.active.Store(&policySnapshot{
		bundle:  activeBundle,
		bundles: nextBundles,
		record:  record,
	})
	return PolicyCurrentResponse{Bundle: clonePolicyBundle(activeBundle), Record: record}, nil
}

func (m *PolicyManager) Rollback(ctx context.Context, version int, operatorID string, message string, now time.Time, event types.EventEnvelope) (PolicyCurrentResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sourceBundle, found, err := m.bundleForVersion(ctx, version)
	if err != nil {
		return PolicyCurrentResponse{}, err
	}
	if !found {
		return PolicyCurrentResponse{}, errStatus(404, "policy_version_not_found", "policy version was not found")
	}

	current := m.Active(ctx)
	nextBundle := clonePolicyBundle(sourceBundle)
	nextBundle.Version = max(current.bundle.Version+1, nextBundle.Version)
	nextBundle.Status = "active"
	nextBundle.IssuedAt = now

	var record policy.VersionRecord
	if m.stateStore != nil {
		record, err = m.stateStore.SavePolicyVersionAtomic(ctx, nextBundle, operatorID, message, version, now, event)
		if err != nil {
			return PolicyCurrentResponse{}, err
		}
	} else {
		record = policy.VersionRecord{
			Version:       nextBundle.Version,
			Status:        nextBundle.StatusValue(),
			Active:        true,
			RuleCount:     len(nextBundle.Rules),
			PublishedAt:   now,
			PublishedBy:   operatorID,
			Message:       message,
			SourceVersion: version,
		}
	}

	nextBundles := ensureCorePolicy([]policy.Bundle{defaultPolicyBundle(nextBundle)})
	activeBundle := aggregateBundles(nextBundles)
	m.active.Store(&policySnapshot{
		bundle:  activeBundle,
		bundles: nextBundles,
		record:  record,
	})
	return PolicyCurrentResponse{Bundle: clonePolicyBundle(activeBundle), Record: record}, nil
}

func (m *PolicyManager) BundleForVersion(ctx context.Context, version int) (policy.Bundle, bool, error) {
	return m.bundleForVersion(ctx, version)
}

func (m *PolicyManager) bundleForVersion(ctx context.Context, version int) (policy.Bundle, bool, error) {
	if m.stateStore == nil {
		// In-memory fallback
		current := m.Active(ctx)
		if current.bundle.Version == version {
			return clonePolicyBundle(current.bundle), true, nil
		}
		return policy.Bundle{}, false, nil
	}
	bundle, _, found, err := m.stateStore.GetPolicyBundleVersion(ctx, version)
	if err != nil {
		return policy.Bundle{}, false, err
	}
	return bundle, found, nil
}

func (m *PolicyManager) Hydrate(ctx context.Context) error {
	if m.stateStore == nil {
		return nil
	}
	bundle, record, found, err := m.stateStore.GetActivePolicyBundle(ctx)
	if err != nil {
		return err
	}
	if found {
		bundles := ensureCorePolicy([]policy.Bundle{defaultPolicyBundle(bundle)})
		activeBundle := aggregateBundles(bundles)
		m.active.Store(&policySnapshot{
			bundle:  activeBundle,
			bundles: bundles,
			record:  record,
		})
	}
	return nil
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

func clonePolicyBundles(bundles []policy.Bundle) []policy.Bundle {
	result := make([]policy.Bundle, 0, len(bundles))
	for _, bundle := range bundles {
		result = append(result, clonePolicyBundle(bundle))
	}
	return result
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

func ensureCorePolicy(bundles []policy.Bundle) []policy.Bundle {
	hasCore := false
	for i := range bundles {
		if bundles[i].BundleID == "core" {
			if len(bundles[i].Rules) < 2 {
				bundles[i] = policy.CorePolicyBundle()
			}
			hasCore = true
		}
		if bundles[i].Status == "active_default" {
			bundles[i].Status = policy.BundleStatusActive
		}
	}
	if hasCore {
		return bundles
	}
	return append([]policy.Bundle{policy.CorePolicyBundle()}, bundles...)
}

func aggregateBundles(bundles []policy.Bundle) policy.Bundle {
	bundle := policy.DefaultBundle()
	bundle.Status = "bundles_active"
	bundle.IssuedAt = time.Now().UTC()
	bundle.Rules = nil

	corePolicy := policy.CorePolicyBundle()
	bundle.Rules = append(bundle.Rules, corePolicy.Rules...)

	maxVersion := 0
	mergedTools := append([]string(nil), bundle.RuntimePolicy.RequireApprovalTools...)
	mergedSideEffects := append([]types.SideEffect(nil), bundle.RuntimePolicy.RequireApprovalSideEffects...)
	mergedOpenWorld := bundle.RuntimePolicy.RequireApprovalOpenWorld
	mergedTimeout := bundle.RuntimePolicy.ApprovalTimeout

	for _, managedBundle := range bundles {
		if managedBundle.BundleID == "core" {
			continue
		}
		if managedBundle.Status != policy.BundleStatusActive {
			continue
		}
		if managedBundle.Version > maxVersion {
			maxVersion = managedBundle.Version
		}
		bundle.Rules = append(bundle.Rules, managedBundle.Rules...)

		rp := managedBundle.RuntimePolicy
		mergedTools = appendUnique(mergedTools, rp.RequireApprovalTools)
		mergedSideEffects = appendUnique(mergedSideEffects, rp.RequireApprovalSideEffects)
		if rp.RequireApprovalOpenWorld {
			mergedOpenWorld = true
		}
		if mergedTimeout.Duration == 0 && rp.ApprovalTimeout.Duration > 0 {
			mergedTimeout = rp.ApprovalTimeout
		}
	}
	bundle.Version = maxVersion
	bundle.RuntimePolicy = policy.RuntimePolicy{
		RequireApprovalTools:       mergedTools,
		RequireApprovalSideEffects: mergedSideEffects,
		RequireApprovalOpenWorld:   mergedOpenWorld,
		ApprovalTimeout:            mergedTimeout,
	}

	if len(bundle.Rules) == len(corePolicy.Rules) {
		bundle.Rules = append(bundle.Rules, policy.DefaultBundle().Rules...)
	}
	return bundle
}

func appendUnique[T comparable](base, additions []T) []T {
	seen := make(map[T]bool, len(base))
	for _, s := range base {
		seen[s] = true
	}
	for _, s := range additions {
		if !seen[s] {
			base = append(base, s)
			seen[s] = true
		}
	}
	return base
}
