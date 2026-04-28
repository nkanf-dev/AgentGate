package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/agentgate/agentgate/internal/authz"
	"github.com/agentgate/agentgate/internal/core"
	"github.com/agentgate/agentgate/internal/policy"
	"github.com/agentgate/agentgate/internal/types"
	"github.com/go-chi/chi/v5"
)

type Server struct {
	engine     *core.Engine
	authorizer *authz.Authorizer
}

func NewServer(engine *core.Engine, authorizer *authz.Authorizer) *Server {
	return &Server{engine: engine, authorizer: authorizer}
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(corsMiddleware)

	r.Get("/healthz", s.healthz)
	r.Route("/v1", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(s.authorizer.Middleware(authz.RoleAdapter))
			r.Post("/register", s.registerAdapter)
			r.Post("/decide", s.decide)
			r.Post("/report", s.report)
		})
		r.Group(func(r chi.Router) {
			r.Use(s.authorizer.Middleware(authz.RoleOperator))
			r.Post("/approvals/{approval_id}/resolve", s.resolveApproval)
			r.Get("/approvals", s.approvalsList)
			r.Get("/coverage", s.coverage)
			r.Get("/events", s.eventsList)
		})
	})
	r.Route("/internal", func(r chi.Router) {
		r.Use(s.authorizer.Middleware(authz.RoleAdmin))
		r.Get("/policy/current", s.currentPolicy)
		r.Get("/policy/versions", s.policyVersions)
		r.Post("/policy/validate", s.validatePolicy)
		r.Post("/policy/publish", s.publishPolicy)
		r.Post("/policy/rollback", s.rollbackPolicy)
		r.Get("/policy/bundles", s.policyBundles)
		r.Post("/policy/bundles", s.createPolicyBundle)
		r.Get("/policy/bundles/{bundle_id}", s.getPolicyBundle)
		r.Patch("/policy/bundles/{bundle_id}", s.updatePolicyBundle)
		r.Delete("/policy/bundles/{bundle_id}", s.deletePolicyBundle)
		r.Post("/policy/bundles/{bundle_id}/validate", s.validatePolicyBundle)
		r.Post("/policy/bundles/{bundle_id}/publish", s.publishPolicyBundle)
		r.Get("/integrations", s.integrationDefinitions)
		r.Post("/integrations", s.createIntegrationDefinition)
		r.Get("/integrations/{integration_id}", s.getIntegrationDefinition)
		r.Patch("/integrations/{integration_id}", s.updateIntegrationDefinition)
		r.Delete("/integrations/{integration_id}", s.deleteIntegrationDefinition)
	})

	return r
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if isAllowedOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "ok",
		"service":    "agentgate",
		"started_at": s.engine.StartedAt(),
	})
}

func (s *Server) currentPolicy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.engine.CurrentPolicy())
}

func (s *Server) policyVersions(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if value := r.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 1000 {
			writeError(w, http.StatusBadRequest, "invalid_limit", "limit must be between 1 and 1000")
			return
		}
		limit = parsed
	}

	versions, err := s.engine.PolicyVersions(limit)
	if err != nil {
		writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, versions)
}

func (s *Server) validatePolicy(w http.ResponseWriter, r *http.Request) {
	var req core.PolicyValidateRequest
	if !decodeOrError(w, r, &req) {
		return
	}
	writeJSON(w, http.StatusOK, s.engine.ValidatePolicy(req.Bundle))
}

func (s *Server) publishPolicy(w http.ResponseWriter, r *http.Request) {
	var req core.PolicyPublishRequest
	if !decodeOrError(w, r, &req) {
		return
	}
	result, err := s.engine.PublishPolicy(req)
	if err != nil {
		writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (s *Server) rollbackPolicy(w http.ResponseWriter, r *http.Request) {
	var req core.PolicyRollbackRequest
	if !decodeOrError(w, r, &req) {
		return
	}
	result, err := s.engine.RollbackPolicy(req)
	if err != nil {
		writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (s *Server) policyBundles(w http.ResponseWriter, r *http.Request) {
	includeArchived := r.URL.Query().Get("include_archived") == "true"
	result, err := s.engine.PolicyBundles(includeArchived)
	if err != nil {
		writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) createPolicyBundle(w http.ResponseWriter, r *http.Request) {
	var req policy.Bundle
	if !decodeOrError(w, r, &req) {
		return
	}
	result, err := s.engine.CreatePolicyBundle(req)
	if err != nil {
		writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (s *Server) getPolicyBundle(w http.ResponseWriter, r *http.Request) {
	result, err := s.engine.GetPolicyBundle(chi.URLParam(r, "bundle_id"))
	if err != nil {
		writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) updatePolicyBundle(w http.ResponseWriter, r *http.Request) {
	var req policy.Bundle
	if !decodeOrError(w, r, &req) {
		return
	}
	result, err := s.engine.UpdatePolicyBundle(chi.URLParam(r, "bundle_id"), req)
	if err != nil {
		writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) deletePolicyBundle(w http.ResponseWriter, r *http.Request) {
	if err := s.engine.DeletePolicyBundle(chi.URLParam(r, "bundle_id")); err != nil {
		writeCoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) validatePolicyBundle(w http.ResponseWriter, r *http.Request) {
	result, err := s.engine.ValidatePolicyBundle(chi.URLParam(r, "bundle_id"))
	if err != nil {
		writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) publishPolicyBundle(w http.ResponseWriter, r *http.Request) {
	result, err := s.engine.PublishPolicyBundle(chi.URLParam(r, "bundle_id"))
	if err != nil {
		writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) integrationDefinitions(w http.ResponseWriter, r *http.Request) {
	result, err := s.engine.Integrations()
	if err != nil {
		writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) createIntegrationDefinition(w http.ResponseWriter, r *http.Request) {
	var req types.IntegrationDefinition
	if !decodeOrError(w, r, &req) {
		return
	}
	result, err := s.engine.SaveIntegration(req)
	if err != nil {
		writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (s *Server) getIntegrationDefinition(w http.ResponseWriter, r *http.Request) {
	result, err := s.engine.GetIntegration(chi.URLParam(r, "integration_id"))
	if err != nil {
		writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) updateIntegrationDefinition(w http.ResponseWriter, r *http.Request) {
	var req types.IntegrationDefinition
	if !decodeOrError(w, r, &req) {
		return
	}
	req.ID = chi.URLParam(r, "integration_id")
	result, err := s.engine.SaveIntegration(req)
	if err != nil {
		writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) deleteIntegrationDefinition(w http.ResponseWriter, r *http.Request) {
	if err := s.engine.DeleteIntegration(chi.URLParam(r, "integration_id")); err != nil {
		writeCoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) registerAdapter(w http.ResponseWriter, r *http.Request) {
	var req types.AdapterRegistration
	if !decodeOrError(w, r, &req) {
		return
	}
	result, err := s.engine.RegisterAdapter(req)
	if err != nil {
		writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (s *Server) coverage(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.engine.Coverage())
}

func (s *Server) decide(w http.ResponseWriter, r *http.Request) {
	var req types.PolicyRequest
	if !decodeOrError(w, r, &req) {
		return
	}
	decision, err := s.engine.Decide(req)
	if err != nil {
		writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, decision)
}

func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	var req types.ReportRequest
	if !decodeOrError(w, r, &req) {
		return
	}
	result, err := s.engine.Report(req)
	if err != nil {
		writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, result)
}

func (s *Server) resolveApproval(w http.ResponseWriter, r *http.Request) {
	var req types.ApprovalResolveRequest
	if !decodeOrError(w, r, &req) {
		return
	}
	result, err := s.engine.ResolveApproval(chi.URLParam(r, "approval_id"), req)
	if err != nil {
		writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) approvalsList(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if value := r.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 1000 {
			writeError(w, http.StatusBadRequest, "invalid_limit", "limit must be between 1 and 1000")
			return
		}
		limit = parsed
	}

	approvals, err := s.engine.Approvals(limit)
	if err != nil {
		writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, approvals)
}

func (s *Server) eventsList(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if value := r.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 1000 {
			writeError(w, http.StatusBadRequest, "invalid_limit", "limit must be between 1 and 1000")
			return
		}
		limit = parsed
	}

	events, err := s.engine.Events(limit)
	if err != nil {
		writeCoreError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"events": events})
}

func decodeOrError(w http.ResponseWriter, r *http.Request, value interface{}) bool {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(value); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return false
	}
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must contain a single JSON object")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeCoreError(w http.ResponseWriter, err error) {
	var coreErr *core.Error
	if errors.As(err, &coreErr) {
		writeError(w, coreErr.Status, coreErr.Code, coreErr.Message)
		return
	}
	writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
}

func writeError(w http.ResponseWriter, status int, code string, message string) {
	writeJSON(w, status, map[string]interface{}{
		"error": map[string]interface{}{
			"code":    code,
			"message": message,
		},
	})
}

func isAllowedOrigin(origin string) bool {
	parsed, err := url.Parse(origin)
	if err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") {
		switch parsed.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			return true
		}
	}
	return false
}
