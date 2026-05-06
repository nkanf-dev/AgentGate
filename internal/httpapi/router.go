// Package httpapi provides the HTTP API for the AgentGate control plane.
//
// @title           AgentGate API
// @version         1.0.0
// @description     Policy decision and control plane for agentic systems.
// @host            localhost:8080
// @BasePath        /
// @securityDefinitions.apikey BearerAuth
// @in              header
// @name            Authorization
// @description     Bearer token authentication. Roles: adapter, operator, admin.

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
	httpSwagger "github.com/swaggo/http-swagger/v2"
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

	// Health
	r.Get("/healthz", s.healthz)

	// Swagger
	r.Get("/swagger/*", s.swaggerUI)
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

func (s *Server) swaggerUI(w http.ResponseWriter, r *http.Request) {
	httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	).ServeHTTP(w, r)
}

// @Summary      Health check
// @Description  Returns the service status and start time.
// @Tags         health
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Router       /healthz [get]
func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "ok",
		"service":    "agentgate",
		"started_at": s.engine.StartedAt(),
	})
}

// @Summary      Get active policy
// @Description  Returns the currently active policy bundle with all rules.
// @Tags         policy
// @Security     BearerAuth
// @Produce      json
// @Success      200  {object}  policy.Bundle
// @Router       /internal/policy/current [get]
func (s *Server) currentPolicy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.engine.CurrentPolicy())
}

// @Summary      List policy versions
// @Description  Returns paginated policy version history.
// @Tags         policy
// @Security     BearerAuth
// @Produce      json
// @Param        limit  query     int  false  "max results (1-1000)"
// @Success      200    {array}   map[string]interface{}
// @Failure      400    {object}  map[string]interface{}
// @Router       /internal/policy/versions [get]
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

// @Summary      Validate a policy bundle
// @Description  Validates a policy bundle without publishing it.
// @Tags         policy
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body      core.PolicyValidateRequest  true  "Policy bundle to validate"
// @Success      200   {object}  map[string]interface{}
// @Failure      400   {object}  map[string]interface{}
// @Router       /internal/policy/validate [post]
func (s *Server) validatePolicy(w http.ResponseWriter, r *http.Request) {
	var req core.PolicyValidateRequest
	if !decodeOrError(w, r, &req) {
		return
	}
	writeJSON(w, http.StatusOK, s.engine.ValidatePolicy(req.Bundle))
}

// @Summary      Publish a new policy version
// @Description  Validates and publishes a new policy version, making it active.
// @Tags         policy
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body      core.PolicyPublishRequest  true  "Policy to publish"
// @Success      201   {object}  map[string]interface{}
// @Failure      400   {object}  map[string]interface{}
// @Router       /internal/policy/publish [post]
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

// @Summary      Rollback to a previous policy version
// @Description  Rolls back the active policy to a specified version.
// @Tags         policy
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body      core.PolicyRollbackRequest  true  "Rollback parameters"
// @Success      201   {object}  map[string]interface{}
// @Failure      400   {object}  map[string]interface{}
// @Router       /internal/policy/rollback [post]
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

// @Summary      List policy bundles
// @Description  Returns all policy bundles, optionally including archived ones.
// @Tags         policy
// @Security     BearerAuth
// @Produce      json
// @Param        include_archived  query     bool  false  "include archived bundles"
// @Success      200               {array}   policy.Bundle
// @Router       /internal/policy/bundles [get]
func (s *Server) policyBundles(w http.ResponseWriter, r *http.Request) {
	includeArchived := r.URL.Query().Get("include_archived") == "true"
	result, err := s.engine.PolicyBundles(includeArchived)
	if err != nil {
		writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// @Summary      Create a policy bundle
// @Description  Creates a new policy bundle.
// @Tags         policy
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body      policy.Bundle  true  "Bundle definition"
// @Success      201   {object}  policy.Bundle
// @Failure      400   {object}  map[string]interface{}
// @Router       /internal/policy/bundles [post]
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

// @Summary      Get a policy bundle
// @Description  Returns a single policy bundle by ID.
// @Tags         policy
// @Security     BearerAuth
// @Produce      json
// @Param        bundle_id  path      string  true  "Bundle ID"
// @Success      200        {object}  policy.Bundle
// @Router       /internal/policy/bundles/{bundle_id} [get]
func (s *Server) getPolicyBundle(w http.ResponseWriter, r *http.Request) {
	result, err := s.engine.GetPolicyBundle(chi.URLParam(r, "bundle_id"))
	if err != nil {
		writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// @Summary      Update a policy bundle
// @Description  Updates an existing policy bundle.
// @Tags         policy
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        bundle_id  path      string        true  "Bundle ID"
// @Param        body       body      policy.Bundle true  "Updated bundle"
// @Success      200        {object}  policy.Bundle
// @Failure      400        {object}  map[string]interface{}
// @Router       /internal/policy/bundles/{bundle_id} [patch]
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

// @Summary      Delete a policy bundle
// @Description  Archives (soft-deletes) a policy bundle.
// @Tags         policy
// @Security     BearerAuth
// @Produce      json
// @Param        bundle_id  path  string  true  "Bundle ID"
// @Success      204
// @Router       /internal/policy/bundles/{bundle_id} [delete]
func (s *Server) deletePolicyBundle(w http.ResponseWriter, r *http.Request) {
	if err := s.engine.DeletePolicyBundle(chi.URLParam(r, "bundle_id")); err != nil {
		writeCoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// @Summary      Validate a policy bundle by ID
// @Description  Validates a stored policy bundle.
// @Tags         policy
// @Security     BearerAuth
// @Produce      json
// @Param        bundle_id  path      string  true  "Bundle ID"
// @Success      200        {object}  map[string]interface{}
// @Router       /internal/policy/bundles/{bundle_id}/validate [post]
func (s *Server) validatePolicyBundle(w http.ResponseWriter, r *http.Request) {
	result, err := s.engine.ValidatePolicyBundle(chi.URLParam(r, "bundle_id"))
	if err != nil {
		writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// @Summary      Publish a policy bundle by ID
// @Description  Publishes a stored policy bundle, making it active.
// @Tags         policy
// @Security     BearerAuth
// @Produce      json
// @Param        bundle_id  path      string  true  "Bundle ID"
// @Success      200        {object}  map[string]interface{}
// @Router       /internal/policy/bundles/{bundle_id}/publish [post]
func (s *Server) publishPolicyBundle(w http.ResponseWriter, r *http.Request) {
	result, err := s.engine.PublishPolicyBundle(chi.URLParam(r, "bundle_id"))
	if err != nil {
		writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// @Summary      List integration definitions
// @Description  Returns all registered integration definitions.
// @Tags         integrations
// @Security     BearerAuth
// @Produce      json
// @Success      200  {array}  types.IntegrationDefinition
// @Router       /internal/integrations [get]
func (s *Server) integrationDefinitions(w http.ResponseWriter, r *http.Request) {
	result, err := s.engine.Integrations()
	if err != nil {
		writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// @Summary      Create an integration definition
// @Description  Registers a new integration (adapter, resource, etc.).
// @Tags         integrations
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body      types.IntegrationDefinition  true  "Integration definition"
// @Success      201   {object}  types.IntegrationDefinition
// @Failure      400   {object}  map[string]interface{}
// @Router       /internal/integrations [post]
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

// @Summary      Get an integration definition
// @Description  Returns a single integration definition by ID.
// @Tags         integrations
// @Security     BearerAuth
// @Produce      json
// @Param        integration_id  path      string  true  "Integration ID"
// @Success      200             {object}  types.IntegrationDefinition
// @Router       /internal/integrations/{integration_id} [get]
func (s *Server) getIntegrationDefinition(w http.ResponseWriter, r *http.Request) {
	result, err := s.engine.GetIntegration(chi.URLParam(r, "integration_id"))
	if err != nil {
		writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// @Summary      Update an integration definition
// @Description  Updates an existing integration definition.
// @Tags         integrations
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        integration_id  path      string                       true  "Integration ID"
// @Param        body            body      types.IntegrationDefinition  true  "Updated definition"
// @Success      200             {object}  types.IntegrationDefinition
// @Failure      400             {object}  map[string]interface{}
// @Router       /internal/integrations/{integration_id} [patch]
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

// @Summary      Delete an integration definition
// @Description  Removes an integration definition.
// @Tags         integrations
// @Security     BearerAuth
// @Produce      json
// @Param        integration_id  path  string  true  "Integration ID"
// @Success      204
// @Router       /internal/integrations/{integration_id} [delete]
func (s *Server) deleteIntegrationDefinition(w http.ResponseWriter, r *http.Request) {
	if err := s.engine.DeleteIntegration(chi.URLParam(r, "integration_id")); err != nil {
		writeCoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// @Summary      Register an adapter
// @Description  Registers an adapter with its capabilities, surfaces, and host info.
// @Tags         adapter
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body      types.AdapterRegistration  true  "Adapter registration"
// @Success      201   {object}  map[string]interface{}
// @Failure      400   {object}  map[string]interface{}
// @Router       /v1/register [post]
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

// @Summary      Get adapter coverage
// @Description  Returns coverage information for registered adapters and their surfaces.
// @Tags         adapter
// @Security     BearerAuth
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Router       /v1/coverage [get]
func (s *Server) coverage(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.engine.Coverage())
}

// @Summary      Make a policy decision
// @Description  Evaluates a policy request against all active rules and returns a decision.
// @Tags         decision
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body      types.PolicyRequest  true  "Policy decision request"
// @Success      200   {object}  types.PolicyDecision
// @Failure      400   {object}  map[string]interface{}
// @Router       /v1/decide [post]
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

// @Summary      Report an adapter event
// @Description  Submits a post-decision report from an adapter (e.g., side-effect observations).
// @Tags         decision
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body      types.ReportRequest  true  "Adapter report"
// @Success      202   {object}  map[string]interface{}
// @Failure      400   {object}  map[string]interface{}
// @Router       /v1/report [post]
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

// @Summary      Resolve an approval
// @Description  Approves or denies a pending approval request.
// @Tags         approvals
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        approval_id  path      string                       true  "Approval ID"
// @Param        body         body      types.ApprovalResolveRequest true  "Resolution (approved/denied)"
// @Success      200          {object}  map[string]interface{}
// @Failure      400          {object}  map[string]interface{}
// @Router       /v1/approvals/{approval_id}/resolve [post]
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

// @Summary      List approvals
// @Description  Returns paginated list of approval records.
// @Tags         approvals
// @Security     BearerAuth
// @Produce      json
// @Param        limit  query     int  false  "max results (1-1000)"
// @Success      200    {array}   types.ApprovalRecord
// @Failure      400    {object}  map[string]interface{}
// @Router       /v1/approvals [get]
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

// @Summary      List events
// @Description  Returns paginated event log.
// @Tags         events
// @Security     BearerAuth
// @Produce      json
// @Param        limit  query     int  false  "max results (1-1000)"
// @Success      200    {object}  map[string]interface{}
// @Failure      400    {object}  map[string]interface{}
// @Router       /v1/events [get]
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
