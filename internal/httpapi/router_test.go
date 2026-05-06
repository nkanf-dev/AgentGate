package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentgate/agentgate/internal/authz"
	"github.com/agentgate/agentgate/internal/core"
)

func TestRouterRejectsUnknownJSONFields(t *testing.T) {
	router := testRouter()
	request := httptest.NewRequest(http.MethodPost, "/v1/register", strings.NewReader(`{
		"adapter_id": "openclaw-test",
		"adapter_kind": "host_plugin",
		"host": {"kind": "openclaw"},
		"surfaces": ["input"],
		"capabilities": {
			"can_block": true,
			"can_rewrite_input": true,
			"can_rewrite_tool_args": true,
			"can_pause_for_approval": true
		},
		"unexpected": true
	}`))
	request.Header.Set("Authorization", "Bearer adapter-token")
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "unknown field") {
		t.Fatalf("expected unknown field error, got %s", recorder.Body.String())
	}
}

func TestRouterRejectsTrailingJSONValues(t *testing.T) {
	router := testRouter()
	request := httptest.NewRequest(http.MethodPost, "/v1/report", strings.NewReader(`{
		"request_id": "req_1",
		"outcome": "ok"
	} {"extra": true}`))
	request.Header.Set("Authorization", "Bearer adapter-token")
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "single JSON object") {
		t.Fatalf("expected single JSON object error, got %s", recorder.Body.String())
	}
}

func TestRouterDoesNotAllowOperatorOnAdapterEndpoints(t *testing.T) {
	router := testRouter()
	request := httptest.NewRequest(http.MethodPost, "/v1/report", strings.NewReader(`{
		"request_id": "req_1",
		"outcome": "ok"
	}`))
	request.Header.Set("Authorization", "Bearer operator-token")
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestPolicyPublishRequiresAdmin(t *testing.T) {
	router := testRouter()
	request := httptest.NewRequest(http.MethodPost, "/internal/policy/publish", strings.NewReader(`{}`))
	request.Header.Set("Authorization", "Bearer operator-token")
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestIntegrationsRequireAdmin(t *testing.T) {
	router := testRouter()
	request := httptest.NewRequest(http.MethodGet, "/internal/integrations", nil)
	request.Header.Set("Authorization", "Bearer operator-token")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestIntegrationDefinitionMatchesRegisteredAdapterByIntegrationID(t *testing.T) {
	router := testRouter()
	create := httptest.NewRequest(http.MethodPost, "/internal/integrations", strings.NewReader(`{
		"id": "openclaw-main",
		"name": "OpenClaw main adapter",
		"kind": "adapter",
		"enabled": true,
		"expected_surfaces": ["input", "runtime"]
	}`))
	create.Header.Set("Authorization", "Bearer admin-token")
	create.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, create)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"status":"missing"`) {
		t.Fatalf("new integration should start missing, got %s", recorder.Body.String())
	}

	register := httptest.NewRequest(http.MethodPost, "/v1/register", strings.NewReader(`{
		"adapter_id": "openclaw-main-01",
		"integration_id": "openclaw-main",
		"adapter_kind": "host_plugin",
		"host": {"kind": "openclaw"},
		"surfaces": ["input", "runtime"],
		"capabilities": {
			"can_block": true,
			"can_rewrite_input": true,
			"can_rewrite_tool_args": true,
			"can_pause_for_approval": true
		}
	}`))
	register.Header.Set("Authorization", "Bearer adapter-token")
	register.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()

	router.ServeHTTP(recorder, register)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", recorder.Code, recorder.Body.String())
	}

	list := httptest.NewRequest(http.MethodGet, "/internal/integrations", nil)
	list.Header.Set("Authorization", "Bearer admin-token")
	recorder = httptest.NewRecorder()

	router.ServeHTTP(recorder, list)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, `"status":"connected"`) {
		t.Fatalf("expected connected integration, got %s", body)
	}
	if !strings.Contains(body, `"matched_adapter_id":"openclaw-main-01"`) {
		t.Fatalf("expected exact matched adapter, got %s", body)
	}
}

func TestPolicyValidateAndPublish(t *testing.T) {
	router := testRouter()
	validate := httptest.NewRequest(http.MethodPost, "/internal/policy/validate", strings.NewReader(`{
		"bundle": {
			"version": 1,
			"status": "draft",
			"issued_at": "2026-04-29T00:00:00Z",
			"rules": [{
				"id": "runtime.bash.deny",
				"priority": 100,
				"surface": "runtime",
				"request_kinds": ["tool_attempt"],
				"effect": "deny",
				"reason_code": "runtime_bash_denied",
					"when": {"language": "cel", "expression": "action.tool == \"bash\""}
			}],
			"input_policy": {"secret_mode": "secret_handle"},
			"resource_policy": {"secret_handle_scope": "session_task"},
			"runtime_policy": {},
			"egress_policy": {"host_allowlist": [], "block_sensitive_query_params": [], "require_purpose_declaration": true},
			"path_policy": {"workspace_root": ".", "allow_worktree_siblings": false, "blocked_prefixes": []}
		}
	}`))
	validate.Header.Set("Authorization", "Bearer admin-token")
	validate.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, validate)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var validation struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &validation); err != nil {
		t.Fatalf("decode validation: %v", err)
	}
	if !validation.Valid {
		t.Fatalf("expected valid policy, got %s", recorder.Body.String())
	}

	publish := httptest.NewRequest(http.MethodPost, "/internal/policy/publish", strings.NewReader(`{
		"operator_id": "admin-test",
		"message": "deny bash",
		"bundle": {
			"version": 1,
			"status": "draft",
			"issued_at": "2026-04-29T00:00:00Z",
			"rules": [{
				"id": "runtime.bash.deny",
				"priority": 100,
				"surface": "runtime",
				"request_kinds": ["tool_attempt"],
				"effect": "deny",
				"reason_code": "runtime_bash_denied",
					"when": {"language": "cel", "expression": "action.tool == \"bash\""}
			}],
			"input_policy": {"secret_mode": "secret_handle"},
			"resource_policy": {"secret_handle_scope": "session_task"},
			"runtime_policy": {},
			"egress_policy": {"host_allowlist": [], "block_sensitive_query_params": [], "require_purpose_declaration": true},
			"path_policy": {"workspace_root": ".", "allow_worktree_siblings": false, "blocked_prefixes": []}
		}
	}`))
	publish.Header.Set("Authorization", "Bearer admin-token")
	publish.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()

	router.ServeHTTP(recorder, publish)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"version":2`) {
		t.Fatalf("publish should assign next version, got %s", recorder.Body.String())
	}
}

func TestCORSAllowsLocalDevPorts(t *testing.T) {
	tests := []string{
		"http://localhost:5174",
		"http://127.0.0.1:61234",
		"http://[::1]:5174",
	}
	for _, origin := range tests {
		t.Run(origin, func(t *testing.T) {
			if !isAllowedOrigin(origin) {
				t.Fatalf("expected local origin %q to be allowed", origin)
			}
		})
	}
}

func TestCORSRejectsNonLocalOrigin(t *testing.T) {
	if isAllowedOrigin("https://example.com") {
		t.Fatal("non-local origin should not be allowed")
	}
}

func testRouter() http.Handler {
	return NewServer(core.NewEngine(), authz.New(authz.Config{
		AdapterTokens:  []string{"adapter-token"},
		OperatorTokens: []string{"operator-token"},
		AdminTokens:    []string{"admin-token"},
	})).Router()
}
