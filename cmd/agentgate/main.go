package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/agentgate/agentgate/internal/authz"
	"github.com/agentgate/agentgate/internal/config"
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

	// Load configuration.
	cfg, err := config.Load(config.GetConfigPath())
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	db, err := store.OpenSQLite(ctx, cfg.Database.DSN)
	if err != nil {
		return err
	}
	defer db.Close()

	policyBundle, err := policy.LoadFile(cfg.Policy.Path)
	if err != nil {
		return err
	}
	if activeBundle, _, found, err := db.GetActivePolicyBundle(); err != nil {
		return err
	} else if found {
		policyBundle = activeBundle
	} else {
		if _, err := db.SavePolicyVersion(policyBundle, "bootstrap", "initial policy from config", 0, policyBundle.IssuedAt); err != nil {
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

	// Secret detector: ML (openai/privacy-filter) if enabled, else regex.
	detector := buildDetector()

	engine := core.NewEngine(
		core.WithEventStore(db),
		core.WithStateStore(db),
		core.WithPolicyBundle(policyBundle),
		core.WithPolicyBundles(bundles),
		core.WithDetector(detector),
	)

	srv := &http.Server{
		Addr: cfg.Server.Addr,
		Handler: httpapi.NewServer(engine, authz.New(authz.Config{
			AdapterTokens:  cfg.Auth.AdapterTokens,
			OperatorTokens: cfg.Auth.OperatorTokens,
			AdminTokens:    cfg.Auth.AdminTokens,
		}), cfg.Server.CORSOrigins).Router(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("agentgate listening on %s", cfg.Server.Addr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		engine.Close()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
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
