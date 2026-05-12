package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/agentgate/agentgate/internal/authz"
	"github.com/agentgate/agentgate/internal/core"
	"github.com/agentgate/agentgate/internal/httpapi"
	"github.com/agentgate/agentgate/internal/policy"
	"github.com/agentgate/agentgate/internal/scanner"
	"github.com/agentgate/agentgate/internal/store"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("agentgate: %v", err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sqliteDSN := getenv("AGENTGATE_SQLITE_DSN", "file:agentgate.db?_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)")
	db, err := store.OpenSQLite(ctx, sqliteDSN)
	if err != nil {
		return err
	}
	defer db.Close()

	policyPath := getenv("AGENTGATE_POLICY_PATH", "config/default_policy.json")
	policyBundle, err := policy.LoadFile(policyPath)
	if err != nil {
		return err
	}
	if activeBundle, _, found, err := db.GetActivePolicyBundle(); err != nil {
		return err
	} else if found {
		policyBundle = activeBundle
	} else {
		if _, err := db.SavePolicyVersion(policyBundle, "bootstrap", "initial policy from AGENTGATE_POLICY_PATH", 0, policyBundle.IssuedAt); err != nil {
			return err
		}
	}
	bundles, err := db.ListPolicyBundles(false)
	if err != nil {
		return err
	}
	if len(bundles) == 0 {
		bootstrap := policyBundle
		bootstrap.BundleID = "default"
		bootstrap.Name = "Default bundle"
		bootstrap.Description = "Bootstrap policy bundle"
		bootstrap.Priority = 100
		bootstrap.Status = policy.BundleStatusActive
		bootstrap.CreatedAt = policyBundle.IssuedAt
		bootstrap.UpdatedAt = policyBundle.IssuedAt
		if err := db.SavePolicyBundle(bootstrap); err != nil {
			return err
		}
		bundles = []policy.Bundle{bootstrap}
	}

	addr := getenv("AGENTGATE_ADDR", ":8080")

	// Secret detector: ML (openai/privacy-filter) if enabled, else regex.
	detector := buildDetector()

	srv := &http.Server{
		Addr: addr,
		Handler: httpapi.NewServer(core.NewEngine(core.WithEventStore(db), core.WithStateStore(db), core.WithPolicyBundle(policyBundle), core.WithPolicyBundles(bundles), core.WithDetector(detector)), authz.New(authz.Config{
			AdapterTokens:  splitCSV(getenv("AGENTGATE_ADAPTER_TOKENS", "adapter-local-token")),
			OperatorTokens: splitCSV(getenv("AGENTGATE_OPERATOR_TOKENS", "operator-local-token")),
			AdminTokens:    splitCSV(getenv("AGENTGATE_ADMIN_TOKENS", "admin-local-token")),
		})).Router(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("agentgate listening on %s", addr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func splitCSV(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func buildDetector() scanner.Detector {
	mlPath := os.Getenv("AGENTGATE_ML_SCANNER")
	if mlPath == "" {
		return scanner.RegexDetector{}
	}

	absPath, err := filepath.Abs(mlPath)
	if err != nil {
		log.Printf("ml scanner: invalid path %q, falling back to regex: %v", mlPath, err)
		return scanner.RegexDetector{}
	}

	timeout := 30 * time.Second
	if t := os.Getenv("AGENTGATE_ML_SCANNER_TIMEOUT"); t != "" {
		if d, err := time.ParseDuration(t); err == nil {
			timeout = d
		}
	}

	ml := scanner.NewMLScanner(absPath, timeout)
	regex := scanner.RegexDetector{}
	log.Printf("ml scanner: enabled (script=%s, timeout=%s)", absPath, timeout)
	return &scanner.CompositeDetector{ML: ml, Regex: regex}
}
