package authz

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
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
	Role  Role
	ID    string
	Bound bool // True if the ID was explicitly provided in the token config
}

type tokenEntry struct {
	token     string
	principal Principal
}

type Authorizer struct {
	entries []tokenEntry
}

func New(config Config) *Authorizer {
	a := &Authorizer{}

	// Order matters: admin -> operator -> adapter (highest privilege first)
	for _, t := range compact(config.AdminTokens) {
		a.entries = append(a.entries, parseToken(t, RoleAdmin))
	}
	for _, t := range compact(config.OperatorTokens) {
		a.entries = append(a.entries, parseToken(t, RoleOperator))
	}
	for _, t := range compact(config.AdapterTokens) {
		a.entries = append(a.entries, parseToken(t, RoleAdapter))
	}

	return a
}

func parseToken(s string, role Role) tokenEntry {
	parts := strings.SplitN(s, ":", 2)
	token := parts[0]
	if len(parts) > 1 {
		return tokenEntry{
			token: token,
			principal: Principal{
				Role:  role,
				ID:    parts[1],
				Bound: true,
			},
		}
	}
	return tokenEntry{
		token: token,
		principal: Principal{
			Role:  role,
			ID:    autoPrincipalID(role, token),
			Bound: false,
		},
	}
}

func (a *Authorizer) Middleware(required ...Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			principal, ok := a.authorize(r, required)
			if !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":{"code":"unauthorized","message":"valid bearer token required"}}`))
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalContextKey{}, principal)))
		})
	}
}

func (a *Authorizer) authorize(r *http.Request, required []Role) (Principal, bool) {
	token := bearerToken(r.Header.Get("Authorization"))
	if token == "" {
		return Principal{}, false
	}

	for _, entry := range a.entries {
		if subtle.ConstantTimeCompare([]byte(entry.token), []byte(token)) == 1 {
			// Found a matching token. Now check if the role is allowed.
			for _, candidate := range required {
				if roleAllowed(entry.principal.Role, candidate) {
					return entry.principal, true
				}
			}
			// Token matches but role is not authorized for this endpoint.
			return Principal{}, false
		}
	}
	return Principal{}, false
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

type principalContextKey struct{}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok
}

func autoPrincipalID(role Role, token string) string {
	sum := sha256.Sum256([]byte(token))
	return string(role) + "_" + hex.EncodeToString(sum[:8])
}
