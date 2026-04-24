package store

import (
	"context"
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	db *sql.DB
}

func OpenSQLite(ctx context.Context, dsn string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}

	store := &SQLiteStore{db: db}
	if err := store.Migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func (s *SQLiteStore) Migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS security_events (
	event_id TEXT PRIMARY KEY,
	session_id TEXT NOT NULL,
	agent_id TEXT NOT NULL,
	event_type TEXT NOT NULL,
	decision TEXT NOT NULL,
	reason TEXT NOT NULL,
	data_classes TEXT NOT NULL DEFAULT '[]',
	taints TEXT NOT NULL DEFAULT '[]',
	summary TEXT NOT NULL,
	evidence_id TEXT,
	evidence_hash TEXT,
	layer TEXT NOT NULL,
	occurred_at TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS approvals (
	approval_id TEXT PRIMARY KEY,
	session_id TEXT NOT NULL,
	status TEXT NOT NULL,
	operator_id TEXT,
	channel TEXT,
	decided_at TEXT,
	expires_at TEXT NOT NULL,
	request_json TEXT NOT NULL,
	preview_json TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS evidence_records (
	evidence_id TEXT PRIMARY KEY,
	event_id TEXT NOT NULL,
	access_class TEXT NOT NULL,
	retention_days INTEGER NOT NULL,
	payload BLOB NOT NULL,
	created_at TEXT NOT NULL,
	FOREIGN KEY(event_id) REFERENCES security_events(event_id)
);`

	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate sqlite: %w", err)
	}
	return nil
}
