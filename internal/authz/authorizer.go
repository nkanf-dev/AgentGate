package authz

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

type Role string

const (
	RoleAdapter  Role = "adapter"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

type Config struct {
	AdapterTokens  []string
	OperatorTokens []string
	AdminTokens    []string
}

type Principal struct {
	Role Role
}

type Authorizer struct {
	adapterTokens  []string
	operatorTokens []string
	adminTokens    []string
}

func New(config Config) *Authorizer {
	return &Authorizer{
		adapterTokens:  compact(config.AdapterTokens),
		operatorTokens: compact(config.OperatorTokens),
		adminTokens:    compact(config.AdminTokens),
	}
}

func (a *Authorizer) Middleware(required ...Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			if _, ok := a.authorize(r, required); !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":{"code":"unauthorized","message":"valid bearer token required"}}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (a *Authorizer) authorize(r *http.Request, required []Role) (Principal, bool) {
	token := bearerToken(r.Header.Get("Authorization"))
	if token == "" {
		return Principal{}, false
	}
	role, ok := a.roleForToken(token)
	if !ok {
		return Principal{}, false
	}
	for _, candidate := range required {
		if roleAllowed(role, candidate) {
			return Principal{Role: role}, true
		}
	}
	return Principal{}, false
}

func (a *Authorizer) roleForToken(token string) (Role, bool) {
	if containsToken(a.adminTokens, token) {
		return RoleAdmin, true
	}
	if containsToken(a.operatorTokens, token) {
		return RoleOperator, true
	}
	if containsToken(a.adapterTokens, token) {
		return RoleAdapter, true
	}
	return "", false
}

func roleAllowed(actual Role, required Role) bool {
	if actual == RoleAdmin {
		return true
	}
	return actual == required
}

func bearerToken(header string) string {
	prefix := "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}

func containsToken(tokens []string, token string) bool {
	for _, candidate := range tokens {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(token)) == 1 {
			return true
		}
	}
	return false
}

func compact(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}
