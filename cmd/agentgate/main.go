package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/agentgate/agentgate/internal/authz"
	"github.com/agentgate/agentgate/internal/core"
	"github.com/agentgate/agentgate/internal/httpapi"
	"github.com/agentgate/agentgate/internal/policy"
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
	srv := &http.Server{
		Addr: addr,
		Handler: httpapi.NewServer(core.NewEngine(core.WithEventStore(db), core.WithStateStore(db), core.WithPolicyBundle(policyBundle), core.WithPolicyBundles(bundles)), authz.New(authz.Config{
			AdapterTokens:  splitCSV(os.Getenv("AGENTGATE_ADAPTER_TOKENS")),
			OperatorTokens: splitCSV(os.Getenv("AGENTGATE_OPERATOR_TOKENS")),
			AdminTokens:    splitCSV(os.Getenv("AGENTGATE_ADMIN_TOKENS")),
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
