package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

type Server struct {
	startedAt time.Time
}

func NewServer() *Server {
	return &Server{startedAt: time.Now().UTC()}
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()

	r.Get("/healthz", s.healthz)
	r.Route("/internal", func(r chi.Router) {
		r.Get("/policy/current", s.currentPolicy)
	})

	return r
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "ok",
		"service":    "agentgate",
		"started_at": s.startedAt,
	})
}

func (s *Server) currentPolicy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"version": 0,
		"status":  "not_loaded",
	})
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
