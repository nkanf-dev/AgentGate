package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/agentgate/agentgate/internal/httpapi"
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

	addr := getenv("AGENTGATE_ADDR", ":8080")
	srv := &http.Server{
		Addr:              addr,
		Handler:           httpapi.NewServer().Router(),
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
