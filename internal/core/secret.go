package core

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/agentgate/agentgate/internal/scanner"
	"github.com/agentgate/agentgate/internal/types"
)

type SecretVault interface {
	Rewrite(ctx context.Context, text, sessionID, taskID string, now time.Time) (string, []types.SecretHandle, []types.SecretFindingSummary, error)
	Resolve(ctx context.Context, handleID, sessionID, taskID string, now time.Time) (types.SecretHandle, string, error)
	RedactValue(ctx context.Context, value interface{}) (interface{}, bool, error)
	RedactString(ctx context.Context, text string) (string, error)
	Detect(ctx context.Context, text string) ([]scanner.SecretFinding, []scanner.InjectionFinding, error)
	Hydrate(ctx context.Context) error
}

type secretVault struct {
	stateStore        StateStore
	detector          scanner.Detector
	injectionDetector scanner.InjectionDetector

	mu      sync.RWMutex
	handles map[string]types.SecretHandle
	values  map[string]string
}

func newSecretVault(stateStore StateStore, detector scanner.Detector, injectionDetector scanner.InjectionDetector) SecretVault {
	return &secretVault{
		stateStore:        stateStore,
		detector:          detector,
		injectionDetector: injectionDetector,
		handles:           make(map[string]types.SecretHandle),
		values:            make(map[string]string),
	}
}

func (v *secretVault) Hydrate(ctx context.Context) error {
	if v.stateStore == nil {
		return nil
	}
	handles, err := v.stateStore.ListSecretHandles(ctx)
	if err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, hydrated := range handles {
		v.handles[hydrated.Handle.HandleID] = hydrated.Handle
		v.values[hydrated.Handle.HandleID] = hydrated.Value
	}
	return nil
}

func (v *secretVault) Detect(ctx context.Context, text string) ([]scanner.SecretFinding, []scanner.InjectionFinding, error) {
	if text == "" {
		return nil, nil, nil
	}
	findings, err := v.detector.DetectSecrets(ctx, text)
	if err != nil {
		return nil, nil, err
	}
	var injFindings []scanner.InjectionFinding
	if v.injectionDetector != nil {
		var err error
		injFindings, err = v.injectionDetector.DetectInjections(ctx, text)
		if err != nil {
			return nil, nil, err
		}
	}
	return findings, injFindings, nil
}

func (v *secretVault) Rewrite(ctx context.Context, text, sessionID, taskID string, now time.Time) (string, []types.SecretHandle, []types.SecretFindingSummary, error) {
	if strings.TrimSpace(text) == "" {
		return text, nil, nil, nil
	}
	findings, err := v.detector.DetectSecrets(ctx, text)
	if err != nil {
		return "", nil, nil, err // Fail-closed (C1)
	}
	rewritten := text
	if len(findings) == 0 {
		return rewritten, nil, nil, nil
	}
	handles := make([]types.SecretHandle, 0, len(findings))
	summaries := make([]types.SecretFindingSummary, 0, len(findings))
	rewritten = scanner.RewriteSecrets(text, findings, func(index int, finding scanner.SecretFinding) string {
		placeholder := fmt.Sprintf("[SECRET_HANDLE:%d]", index+1)
		handle := types.SecretHandle{
			HandleID:    newID("sech"),
			SessionID:   sessionID,
			TaskID:      taskID,
			Kind:        finding.Kind,
			Placeholder: placeholder,
			SecretHash:  scanner.HashSecret(finding.Value),
			CreatedAt:   now,
			ExpiresAt:   now.Add(secretHandleTTL),
		}
		handles = append(handles, handle)
		summaries = append(summaries, types.SecretFindingSummary{
			Kind:        finding.Kind,
			Placeholder: placeholder,
			HandleID:    handle.HandleID,
			Hash:        handle.SecretHash,
			Offset:      finding.Start,
			Length:      finding.End - finding.Start,
		})
		return placeholder
	})
	for index, handle := range handles {
		if v.stateStore != nil {
			if err := v.stateStore.SaveSecretHandle(ctx, handle, findings[index].Value); err != nil {
				return "", nil, nil, err // Fail-closed
			}
		}
	}
	v.mu.Lock()
	for index, handle := range handles {
		v.handles[handle.HandleID] = handle
		v.values[handle.HandleID] = findings[index].Value
	}
	v.mu.Unlock()
	return rewritten, handles, summaries, nil
}

func (v *secretVault) Resolve(ctx context.Context, handleID, sessionID, taskID string, now time.Time) (types.SecretHandle, string, error) {
	v.mu.RLock()
	handle, ok := v.handles[handleID]
	value := v.values[handleID]
	v.mu.RUnlock()
	if !ok && v.stateStore != nil {
		storedHandle, storedValue, found, err := v.stateStore.GetSecretHandle(ctx, handleID)
		if err != nil {
			return types.SecretHandle{}, "", err
		}
		if found {
			handle = storedHandle
			value = storedValue
			ok = true
			v.mu.Lock()
			v.handles[handleID] = handle
			v.values[handleID] = value
			v.mu.Unlock()
		}
	}
	if !ok {
		return types.SecretHandle{}, "", errStatus(http.StatusNotFound, "secret_handle_not_found", "secret handle was not found")
	}
	if handle.ExpiresAt.IsZero() || !now.Before(handle.ExpiresAt) {
		return types.SecretHandle{}, "", errStatus(http.StatusConflict, "secret_handle_expired", "secret handle has expired")
	}
	if handle.SessionID != sessionID || (handle.TaskID != "" && handle.TaskID != taskID) {
		return types.SecretHandle{}, "", errStatus(http.StatusForbidden, "secret_handle_scope_mismatch", "secret handle scope mismatch")
	}
	return handle, value, nil
}

func (v *secretVault) RedactValue(ctx context.Context, value interface{}) (interface{}, bool, error) {
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
			next, changed, err := v.RedactValue(ctx, item)
			if err != nil {
				return nil, false, err
			}
			result[key] = next
			redacted = redacted || changed
		}
		return result, redacted, nil
	case []interface{}:
		result := make([]interface{}, 0, len(typed))
		redacted := false
		for _, item := range typed {
			next, changed, err := v.RedactValue(ctx, item)
			if err != nil {
				return nil, false, err
			}
			result = append(result, next)
			redacted = redacted || changed
		}
		return result, redacted, nil
	case string:
		next, err := v.RedactString(ctx, typed)
		return next, next != typed, err
	default:
		return value, false, nil
	}
}

func (v *secretVault) RedactString(ctx context.Context, text string) (string, error) {
	if text == "" {
		return text, nil
	}
	findings, err := v.detector.DetectSecrets(ctx, text)
	if err != nil {
		return "[REDACTED:error]", err // Fail-closed (C2)
	}
	if len(findings) == 0 {
		return text, nil
	}
	return scanner.RewriteSecrets(text, findings, func(index int, finding scanner.SecretFinding) string {
		return "[REDACTED]"
	}), nil
}

func (v *secretVault) Snapshot(ctx context.Context) (map[string]types.SecretHandle, map[string]string) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	handles := make(map[string]types.SecretHandle, len(v.handles))
	for k, v := range v.handles {
		handles[k] = v
	}
	values := make(map[string]string, len(v.values))
	for k, v := range v.values {
		values[k] = v
	}
	return handles, values
}

func (v *secretVault) OverrideHandle(ctx context.Context, handle types.SecretHandle, value string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.handles[handle.HandleID] = handle
	v.values[handle.HandleID] = value
}

func isSensitiveAuditKey(key string) bool {
	key = strings.ToLower(key)
	return strings.Contains(key, "token") ||
		strings.Contains(key, "secret") ||
		strings.Contains(key, "password") ||
		strings.Contains(key, "key") ||
		strings.Contains(key, "auth") ||
		strings.Contains(key, "credential")
}
