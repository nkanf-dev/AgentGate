package authz

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthorizerRequiresBearerToken(t *testing.T) {
	authorizer := New(Config{AdapterTokens: []string{"adapter-token"}})
	called := false
	handler := authorizer.Middleware(RoleAdapter)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/decide", nil))

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}
	if called {
		t.Fatal("handler should not be called without token")
	}
}

func TestAuthorizerAllowsAdminForAnyRole(t *testing.T) {
	authorizer := New(Config{AdminTokens: []string{"admin-token"}})
	called := false
	handler := authorizer.Middleware(RoleAdapter)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))

	request := httptest.NewRequest(http.MethodPost, "/v1/decide", nil)
	request.Header.Set("Authorization", "Bearer admin-token")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	if !called {
		t.Fatal("handler should be called for admin token")
	}
}

func TestAuthorizerKeepsAdapterAndOperatorRolesSeparate(t *testing.T) {
	authorizer := New(Config{
		AdapterTokens:  []string{"adapter-token"},
		OperatorTokens: []string{"operator-token"},
	})
	called := false
	handler := authorizer.Middleware(RoleAdapter)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))

	request := httptest.NewRequest(http.MethodPost, "/v1/decide", nil)
	request.Header.Set("Authorization", "Bearer operator-token")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}
	if called {
		t.Fatal("operator token should not access adapter endpoints")
	}
}
