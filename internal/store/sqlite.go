package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/agentgate/agentgate/internal/policy"
	"github.com/agentgate/agentgate/internal/types"
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
);

CREATE TABLE IF NOT EXISTS event_envelopes (
	event_id TEXT PRIMARY KEY,
	event_type TEXT NOT NULL,
	request_id TEXT,
	decision_id TEXT,
	session_id TEXT,
	adapter_id TEXT,
	surface TEXT,
	effect TEXT,
	summary TEXT NOT NULL,
	metadata_json TEXT NOT NULL DEFAULT '{}',
	occurred_at TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS adapter_registrations (
	adapter_id TEXT PRIMARY KEY,
	registration_json TEXT NOT NULL,
	registered_at TEXT NOT NULL,
	last_seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS integration_definitions (
	integration_id TEXT PRIMARY KEY,
	definition_json TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approval_states (
	approval_id TEXT PRIMARY KEY,
	request_id TEXT,
	session_id TEXT NOT NULL,
	task_id TEXT,
	attempt_id TEXT,
	status TEXT NOT NULL,
	reason TEXT NOT NULL,
	operator_id TEXT,
	channel TEXT,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	resolved_at TEXT
);

CREATE TABLE IF NOT EXISTS attempt_grants (
	session_id TEXT NOT NULL,
	task_id TEXT NOT NULL DEFAULT '',
	attempt_id TEXT NOT NULL,
	approval_id TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	PRIMARY KEY(session_id, task_id, attempt_id)
);

CREATE TABLE IF NOT EXISTS secret_handles (
	handle_id TEXT PRIMARY KEY,
	session_id TEXT NOT NULL,
	task_id TEXT,
	kind TEXT NOT NULL,
	placeholder TEXT NOT NULL,
	secret_hash TEXT NOT NULL,
	secret_value BLOB NOT NULL,
	created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS session_facts (
	session_id TEXT PRIMARY KEY,
	adapter_id TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	facts JSON NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS policy_versions (
	version INTEGER PRIMARY KEY,
	bundle_json TEXT NOT NULL,
	status TEXT NOT NULL,
	active INTEGER NOT NULL DEFAULT 0,
	rule_count INTEGER NOT NULL,
	published_at TEXT NOT NULL,
	published_by TEXT,
	message TEXT,
	source_version INTEGER
);

CREATE TABLE IF NOT EXISTS policy_bundles (
	bundle_id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	priority INTEGER NOT NULL,
	status TEXT NOT NULL,
	bundle_json TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);`

	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate sqlite: %w", err)
	}
	return nil
}

func (s *SQLiteStore) UpsertAdapterRegistration(registration types.AdapterRegistration, registeredAt time.Time, lastSeenAt time.Time) error {
	registrationJSON, err := json.Marshal(registration)
	if err != nil {
		return fmt.Errorf("marshal adapter registration: %w", err)
	}
	_, err = s.db.ExecContext(context.Background(), `
INSERT INTO adapter_registrations (
	adapter_id,
	registration_json,
	registered_at,
	last_seen_at
) VALUES (?, ?, ?, ?)
ON CONFLICT(adapter_id) DO UPDATE SET
	registration_json = excluded.registration_json,
	last_seen_at = excluded.last_seen_at
`,
		registration.AdapterID,
		string(registrationJSON),
		registeredAt.Format(time.RFC3339Nano),
		lastSeenAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("upsert adapter registration: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ListAdapterRegistrations() ([]types.AdapterCoverage, error) {
	rows, err := s.db.QueryContext(context.Background(), `
SELECT registration_json, registered_at, last_seen_at
FROM adapter_registrations
ORDER BY last_seen_at DESC, adapter_id ASC
`)
	if err != nil {
		return nil, fmt.Errorf("list adapter registrations: %w", err)
	}
	defer rows.Close()

	var adapters []types.AdapterCoverage
	for rows.Next() {
		var registration types.AdapterRegistration
		var registrationJSON string
		var registeredAt string
		var lastSeenAt string
		if err := rows.Scan(&registrationJSON, &registeredAt, &lastSeenAt); err != nil {
			return nil, fmt.Errorf("scan adapter registration: %w", err)
		}
		if err := json.Unmarshal([]byte(registrationJSON), &registration); err != nil {
			return nil, fmt.Errorf("unmarshal adapter registration: %w", err)
		}
		registered, err := time.Parse(time.RFC3339Nano, registeredAt)
		if err != nil {
			return nil, fmt.Errorf("parse adapter registered_at: %w", err)
		}
		lastSeen, err := time.Parse(time.RFC3339Nano, lastSeenAt)
		if err != nil {
			return nil, fmt.Errorf("parse adapter last_seen_at: %w", err)
		}
		adapters = append(adapters, types.AdapterCoverage{
			AdapterID:          registration.AdapterID,
			IntegrationID:      registration.IntegrationID,
			AdapterKind:        registration.AdapterKind,
			Host:               registration.Host,
			Surfaces:           append([]types.Surface(nil), registration.Surfaces...),
			SupportingChannels: append([]string(nil), registration.SupportingChannels...),
			RegisteredAt:       registered,
			LastSeenAt:         lastSeen,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate adapter registrations: %w", err)
	}
	return adapters, nil
}

func (s *SQLiteStore) SaveIntegrationDefinition(definition types.IntegrationDefinition, now time.Time) error {
	definitionJSON, err := json.Marshal(definition)
	if err != nil {
		return fmt.Errorf("marshal integration definition: %w", err)
	}
	_, err = s.db.ExecContext(context.Background(), `
INSERT INTO integration_definitions (
	integration_id,
	definition_json,
	created_at,
	updated_at
) VALUES (?, ?, ?, ?)
ON CONFLICT(integration_id) DO UPDATE SET
	definition_json = excluded.definition_json,
	updated_at = excluded.updated_at
`,
		definition.ID,
		string(definitionJSON),
		now.Format(time.RFC3339Nano),
		now.Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("save integration definition: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetIntegrationDefinition(integrationID string) (types.IntegrationDefinition, bool, error) {
	var definitionJSON string
	err := s.db.QueryRowContext(context.Background(), `
SELECT definition_json
FROM integration_definitions
WHERE integration_id = ?
`, integrationID).Scan(&definitionJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return types.IntegrationDefinition{}, false, nil
	}
	if err != nil {
		return types.IntegrationDefinition{}, false, fmt.Errorf("get integration definition: %w", err)
	}
	var definition types.IntegrationDefinition
	if err := json.Unmarshal([]byte(definitionJSON), &definition); err != nil {
		return types.IntegrationDefinition{}, false, fmt.Errorf("unmarshal integration definition: %w", err)
	}
	return definition, true, nil
}

func (s *SQLiteStore) ListIntegrationDefinitions() ([]types.IntegrationDefinition, error) {
	rows, err := s.db.QueryContext(context.Background(), `
SELECT definition_json
FROM integration_definitions
ORDER BY integration_id ASC
`)
	if err != nil {
		return nil, fmt.Errorf("list integration definitions: %w", err)
	}
	defer rows.Close()

	definitions := []types.IntegrationDefinition{}
	for rows.Next() {
		var definitionJSON string
		if err := rows.Scan(&definitionJSON); err != nil {
			return nil, fmt.Errorf("scan integration definition: %w", err)
		}
		var definition types.IntegrationDefinition
		if err := json.Unmarshal([]byte(definitionJSON), &definition); err != nil {
			return nil, fmt.Errorf("unmarshal integration definition: %w", err)
		}
		definitions = append(definitions, definition)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate integration definitions: %w", err)
	}
	return definitions, nil
}

func (s *SQLiteStore) DeleteIntegrationDefinition(integrationID string) error {
	result, err := s.db.ExecContext(context.Background(), `
DELETE FROM integration_definitions
WHERE integration_id = ?
`, integrationID)
	if err != nil {
		return fmt.Errorf("delete integration definition: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete integration definition rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLiteStore) AppendEvent(event types.EventEnvelope) error {
	metadataJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("marshal event metadata: %w", err)
	}
	_, err = s.db.ExecContext(context.Background(), `
INSERT INTO event_envelopes (
	event_id,
	event_type,
	request_id,
	decision_id,
	session_id,
	adapter_id,
	surface,
	effect,
	summary,
	metadata_json,
	occurred_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(event_id) DO UPDATE SET
	event_type = excluded.event_type,
	request_id = excluded.request_id,
	decision_id = excluded.decision_id,
	session_id = excluded.session_id,
	adapter_id = excluded.adapter_id,
	surface = excluded.surface,
	effect = excluded.effect,
	summary = excluded.summary,
	metadata_json = excluded.metadata_json,
	occurred_at = excluded.occurred_at
`,
		event.EventID,
		event.EventType,
		nullable(event.RequestID),
		nullable(event.DecisionID),
		nullable(event.SessionID),
		nullable(event.AdapterID),
		nullable(string(event.Surface)),
		nullable(string(event.Effect)),
		event.Summary,
		string(metadataJSON),
		event.OccurredAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("append event: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ListEvents(limit int) ([]types.EventEnvelope, error) {
	if limit < 1 {
		limit = 100
	}
	rows, err := s.db.QueryContext(context.Background(), `
SELECT
	event_id,
	event_type,
	COALESCE(request_id, ''),
	COALESCE(decision_id, ''),
	COALESCE(session_id, ''),
	COALESCE(adapter_id, ''),
	COALESCE(surface, ''),
	COALESCE(effect, ''),
	summary,
	metadata_json,
	occurred_at
FROM event_envelopes
ORDER BY occurred_at DESC, created_at DESC
LIMIT ?
`, limit)
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}
	defer rows.Close()

	events := make([]types.EventEnvelope, 0, limit)
	for rows.Next() {
		var event types.EventEnvelope
		var surface string
		var effect string
		var metadataJSON string
		var occurredAt string
		if err := rows.Scan(
			&event.EventID,
			&event.EventType,
			&event.RequestID,
			&event.DecisionID,
			&event.SessionID,
			&event.AdapterID,
			&surface,
			&effect,
			&event.Summary,
			&metadataJSON,
			&occurredAt,
		); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		event.Surface = types.Surface(surface)
		event.Effect = types.Effect(effect)
		if err := json.Unmarshal([]byte(metadataJSON), &event.Metadata); err != nil {
			return nil, fmt.Errorf("unmarshal event metadata: %w", err)
		}
		event.OccurredAt, err = time.Parse(time.RFC3339Nano, occurredAt)
		if err != nil {
			return nil, fmt.Errorf("parse event time: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate events: %w", err)
	}

	for left, right := 0, len(events)-1; left < right; left, right = left+1, right-1 {
		events[left], events[right] = events[right], events[left]
	}
	return events, nil
}

func (s *SQLiteStore) GetEventByDecisionID(decisionID string) (types.EventEnvelope, bool, error) {
	row := s.db.QueryRowContext(context.Background(), `
SELECT
	event_id,
	event_type,
	COALESCE(request_id, ''),
	COALESCE(decision_id, ''),
	COALESCE(session_id, ''),
	COALESCE(adapter_id, ''),
	COALESCE(surface, ''),
	COALESCE(effect, ''),
	summary,
	metadata_json,
	occurred_at
FROM event_envelopes
WHERE decision_id = ? AND event_type = 'policy_decision'
ORDER BY occurred_at DESC, created_at DESC
LIMIT 1
`, decisionID)
	event, err := scanEvent(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return types.EventEnvelope{}, false, nil
		}
		return types.EventEnvelope{}, false, fmt.Errorf("get event by decision id: %w", err)
	}
	return event, true, nil
}

type eventScanner interface {
	Scan(dest ...interface{}) error
}

func scanEvent(scanner eventScanner) (types.EventEnvelope, error) {
	var event types.EventEnvelope
	var surface string
	var effect string
	var metadataJSON string
	var occurredAt string
	if err := scanner.Scan(
		&event.EventID,
		&event.EventType,
		&event.RequestID,
		&event.DecisionID,
		&event.SessionID,
		&event.AdapterID,
		&surface,
		&effect,
		&event.Summary,
		&metadataJSON,
		&occurredAt,
	); err != nil {
		return types.EventEnvelope{}, err
	}
	event.Surface = types.Surface(surface)
	event.Effect = types.Effect(effect)
	if err := json.Unmarshal([]byte(metadataJSON), &event.Metadata); err != nil {
		return types.EventEnvelope{}, fmt.Errorf("unmarshal event metadata: %w", err)
	}
	parsed, err := time.Parse(time.RFC3339Nano, occurredAt)
	if err != nil {
		return types.EventEnvelope{}, fmt.Errorf("parse event time: %w", err)
	}
	event.OccurredAt = parsed
	return event, nil
}

func (s *SQLiteStore) SaveApproval(approval types.ApprovalRecord) error {
	var resolvedAt interface{}
	if approval.ResolvedAt != nil {
		resolvedAt = approval.ResolvedAt.Format(time.RFC3339Nano)
	}
	_, err := s.db.ExecContext(context.Background(), `
INSERT INTO approval_states (
	approval_id,
	request_id,
	session_id,
	task_id,
	attempt_id,
	status,
	reason,
	operator_id,
	channel,
	created_at,
	expires_at,
	resolved_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(approval_id) DO UPDATE SET
	request_id = excluded.request_id,
	session_id = excluded.session_id,
	task_id = excluded.task_id,
	attempt_id = excluded.attempt_id,
	status = excluded.status,
	reason = excluded.reason,
	operator_id = excluded.operator_id,
	channel = excluded.channel,
	expires_at = excluded.expires_at,
	resolved_at = excluded.resolved_at
`,
		approval.ApprovalID,
		nullable(approval.RequestID),
		approval.SessionID,
		nullable(approval.TaskID),
		nullable(approval.AttemptID),
		string(approval.Status),
		approval.Reason,
		nullable(approval.OperatorID),
		nullable(approval.Channel),
		approval.CreatedAt.Format(time.RFC3339Nano),
		approval.ExpiresAt.Format(time.RFC3339Nano),
		resolvedAt,
	)
	if err != nil {
		return fmt.Errorf("save approval: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetApproval(approvalID string) (types.ApprovalRecord, bool, error) {
	row := s.db.QueryRowContext(context.Background(), `
SELECT
	approval_id,
	COALESCE(request_id, ''),
	session_id,
	COALESCE(task_id, ''),
	COALESCE(attempt_id, ''),
	status,
	reason,
	COALESCE(operator_id, ''),
	COALESCE(channel, ''),
	created_at,
	expires_at,
	resolved_at
FROM approval_states
WHERE approval_id = ?
`, approvalID)
	approval, err := scanApproval(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return types.ApprovalRecord{}, false, nil
		}
		return types.ApprovalRecord{}, false, fmt.Errorf("get approval: %w", err)
	}
	return approval, true, nil
}

func (s *SQLiteStore) ListApprovals(limit int) ([]types.ApprovalRecord, error) {
	if limit < 1 {
		limit = 100
	}
	rows, err := s.db.QueryContext(context.Background(), `
SELECT
	approval_id,
	COALESCE(request_id, ''),
	session_id,
	COALESCE(task_id, ''),
	COALESCE(attempt_id, ''),
	status,
	reason,
	COALESCE(operator_id, ''),
	COALESCE(channel, ''),
	created_at,
	expires_at,
	resolved_at
FROM approval_states
ORDER BY created_at DESC
LIMIT ?
`, limit)
	if err != nil {
		return nil, fmt.Errorf("list approvals: %w", err)
	}
	defer rows.Close()

	approvals := make([]types.ApprovalRecord, 0, limit)
	for rows.Next() {
		approval, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		approvals = append(approvals, approval)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate approvals: %w", err)
	}
	return approvals, nil
}

func (s *SQLiteStore) SaveAttemptGrant(sessionID string, taskID string, attemptID string, approvalID string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(context.Background(), `
INSERT INTO attempt_grants (
	session_id,
	task_id,
	attempt_id,
	approval_id,
	expires_at
) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(session_id, task_id, attempt_id) DO UPDATE SET
	approval_id = excluded.approval_id,
	expires_at = excluded.expires_at
`,
		sessionID,
		taskID,
		attemptID,
		approvalID,
		expiresAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("save attempt grant: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetAttemptGrant(sessionID string, taskID string, attemptID string) (types.AttemptGrant, bool, error) {
	row := s.db.QueryRowContext(context.Background(), `
SELECT approval_id, expires_at
FROM attempt_grants
WHERE session_id = ? AND task_id = ? AND attempt_id = ?
`, sessionID, taskID, attemptID)

	var grant types.AttemptGrant
	var expiresAt string
	if err := row.Scan(&grant.ApprovalID, &expiresAt); err != nil {
		if err == sql.ErrNoRows {
			return types.AttemptGrant{}, false, nil
		}
		return types.AttemptGrant{}, false, fmt.Errorf("get attempt grant: %w", err)
	}
	parsed, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return types.AttemptGrant{}, false, fmt.Errorf("parse attempt grant expires_at: %w", err)
	}
	grant.ExpiresAt = parsed
	return grant, true, nil
}

func (s *SQLiteStore) GetSessionFacts(sessionID string) (types.SessionFactsRecord, bool, error) {
	row := s.db.QueryRowContext(context.Background(), `
SELECT
	session_id,
	adapter_id,
	updated_at,
	facts
FROM session_facts
WHERE session_id = ?
`, sessionID)
	var record types.SessionFactsRecord
	var updatedAt string
	var factsJSON string
	if err := row.Scan(&record.SessionID, &record.AdapterID, &updatedAt, &factsJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return types.SessionFactsRecord{}, false, nil
		}
		return types.SessionFactsRecord{}, false, fmt.Errorf("get session facts: %w", err)
	}
	parsed, err := time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return types.SessionFactsRecord{}, false, fmt.Errorf("parse session facts updated_at: %w", err)
	}
	record.UpdatedAt = parsed
	if err := json.Unmarshal([]byte(factsJSON), &record.Facts); err != nil {
		return types.SessionFactsRecord{}, false, fmt.Errorf("unmarshal session facts: %w", err)
	}
	return record, true, nil
}

func (s *SQLiteStore) UpsertSessionFacts(record types.SessionFactsRecord) error {
	factsJSON, err := json.Marshal(record.Facts)
	if err != nil {
		return fmt.Errorf("marshal session facts: %w", err)
	}
	_, err = s.db.ExecContext(context.Background(), `
INSERT INTO session_facts (
	session_id,
	adapter_id,
	updated_at,
	facts
) VALUES (?, ?, ?, ?)
ON CONFLICT(session_id) DO UPDATE SET
	adapter_id = excluded.adapter_id,
	updated_at = excluded.updated_at,
	facts = excluded.facts
`, record.SessionID, record.AdapterID, record.UpdatedAt.Format(time.RFC3339Nano), string(factsJSON))
	if err != nil {
		return fmt.Errorf("upsert session facts: %w", err)
	}
	return nil
}

func (s *SQLiteStore) UpdateSessionFacts(sessionID string, update func(types.SessionFactsRecord, bool) (types.SessionFactsRecord, error)) error {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin session facts update: %w", err)
	}
	defer tx.Rollback()

	record, found, err := getSessionFactsTx(tx, sessionID)
	if err != nil {
		return err
	}
	next, err := update(record, found)
	if err != nil {
		return err
	}
	if next.SessionID == "" {
		next.SessionID = sessionID
	}
	factsJSON, err := json.Marshal(next.Facts)
	if err != nil {
		return fmt.Errorf("marshal session facts: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), `
INSERT INTO session_facts (
	session_id,
	adapter_id,
	updated_at,
	facts
) VALUES (?, ?, ?, ?)
ON CONFLICT(session_id) DO UPDATE SET
	adapter_id = excluded.adapter_id,
	updated_at = excluded.updated_at,
	facts = excluded.facts
`, next.SessionID, next.AdapterID, next.UpdatedAt.Format(time.RFC3339Nano), string(factsJSON)); err != nil {
		return fmt.Errorf("upsert session facts: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit session facts update: %w", err)
	}
	return nil
}

func getSessionFactsTx(tx *sql.Tx, sessionID string) (types.SessionFactsRecord, bool, error) {
	row := tx.QueryRowContext(context.Background(), `
SELECT
	session_id,
	adapter_id,
	updated_at,
	facts
FROM session_facts
WHERE session_id = ?
`, sessionID)
	var record types.SessionFactsRecord
	var updatedAt string
	var factsJSON string
	if err := row.Scan(&record.SessionID, &record.AdapterID, &updatedAt, &factsJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return types.SessionFactsRecord{}, false, nil
		}
		return types.SessionFactsRecord{}, false, fmt.Errorf("get session facts: %w", err)
	}
	parsed, err := time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return types.SessionFactsRecord{}, false, fmt.Errorf("parse session facts updated_at: %w", err)
	}
	record.UpdatedAt = parsed
	if err := json.Unmarshal([]byte(factsJSON), &record.Facts); err != nil {
		return types.SessionFactsRecord{}, false, fmt.Errorf("unmarshal session facts: %w", err)
	}
	return record, true, nil
}

func (s *SQLiteStore) SaveSecretHandle(handle types.SecretHandle, value string) error {
	_, err := s.db.ExecContext(context.Background(), `
INSERT INTO secret_handles (
	handle_id,
	session_id,
	task_id,
	kind,
	placeholder,
	secret_hash,
	secret_value,
	created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(handle_id) DO UPDATE SET
	session_id = excluded.session_id,
	task_id = excluded.task_id,
	kind = excluded.kind,
	placeholder = excluded.placeholder,
	secret_hash = excluded.secret_hash,
	secret_value = excluded.secret_value,
	created_at = excluded.created_at
`,
		handle.HandleID,
		handle.SessionID,
		nullable(handle.TaskID),
		handle.Kind,
		handle.Placeholder,
		handle.SecretHash,
		[]byte(value),
		handle.CreatedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("save secret handle: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetSecretHandle(handleID string) (types.SecretHandle, string, bool, error) {
	row := s.db.QueryRowContext(context.Background(), `
SELECT
	handle_id,
	session_id,
	COALESCE(task_id, ''),
	kind,
	placeholder,
	secret_hash,
	secret_value,
	created_at
FROM secret_handles
WHERE handle_id = ?
`, handleID)

	var handle types.SecretHandle
	var value []byte
	var createdAt string
	if err := row.Scan(
		&handle.HandleID,
		&handle.SessionID,
		&handle.TaskID,
		&handle.Kind,
		&handle.Placeholder,
		&handle.SecretHash,
		&value,
		&createdAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return types.SecretHandle{}, "", false, nil
		}
		return types.SecretHandle{}, "", false, fmt.Errorf("get secret handle: %w", err)
	}
	parsed, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return types.SecretHandle{}, "", false, fmt.Errorf("parse secret handle created_at: %w", err)
	}
	handle.CreatedAt = parsed
	return handle, string(value), true, nil
}

func (s *SQLiteStore) SavePolicyVersion(bundle policy.Bundle, publishedBy string, message string, sourceVersion int, publishedAt time.Time) (policy.VersionRecord, error) {
	if err := bundle.Validate(); err != nil {
		return policy.VersionRecord{}, fmt.Errorf("validate policy bundle: %w", err)
	}
	bundleJSON, err := json.Marshal(bundle)
	if err != nil {
		return policy.VersionRecord{}, fmt.Errorf("marshal policy bundle: %w", err)
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return policy.VersionRecord{}, fmt.Errorf("begin policy version transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(context.Background(), `
UPDATE policy_versions
SET active = 0,
	status = 'superseded'
WHERE active = 1
`); err != nil {
		return policy.VersionRecord{}, fmt.Errorf("deactivate active policy version: %w", err)
	}

	_, err = tx.ExecContext(context.Background(), `
INSERT INTO policy_versions (
	version,
	bundle_json,
	status,
	active,
	rule_count,
	published_at,
	published_by,
	message,
	source_version
) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)
`,
		bundle.Version,
		string(bundleJSON),
		bundle.StatusValue(),
		len(bundle.Rules),
		publishedAt.Format(time.RFC3339Nano),
		nullable(publishedBy),
		nullable(message),
		nullableInt(sourceVersion),
	)
	if err != nil {
		return policy.VersionRecord{}, fmt.Errorf("insert policy version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return policy.VersionRecord{}, fmt.Errorf("commit policy version transaction: %w", err)
	}
	return policy.VersionRecord{
		Version:       bundle.Version,
		Status:        bundle.StatusValue(),
		Active:        true,
		RuleCount:     len(bundle.Rules),
		PublishedAt:   publishedAt,
		PublishedBy:   publishedBy,
		Message:       message,
		SourceVersion: sourceVersion,
	}, nil
}

func (s *SQLiteStore) GetActivePolicyBundle() (policy.Bundle, policy.VersionRecord, bool, error) {
	row := s.db.QueryRowContext(context.Background(), `
SELECT version, bundle_json, status, active, rule_count, published_at, COALESCE(published_by, ''), COALESCE(message, ''), source_version
FROM policy_versions
WHERE active = 1
ORDER BY version DESC
LIMIT 1
`)
	bundle, record, err := scanPolicyVersion(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return policy.Bundle{}, policy.VersionRecord{}, false, nil
		}
		return policy.Bundle{}, policy.VersionRecord{}, false, fmt.Errorf("get active policy bundle: %w", err)
	}
	return bundle, record, true, nil
}

func (s *SQLiteStore) GetPolicyBundleVersion(version int) (policy.Bundle, policy.VersionRecord, bool, error) {
	row := s.db.QueryRowContext(context.Background(), `
SELECT version, bundle_json, status, active, rule_count, published_at, COALESCE(published_by, ''), COALESCE(message, ''), source_version
FROM policy_versions
WHERE version = ?
`, version)
	bundle, record, err := scanPolicyVersion(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return policy.Bundle{}, policy.VersionRecord{}, false, nil
		}
		return policy.Bundle{}, policy.VersionRecord{}, false, fmt.Errorf("get policy bundle version: %w", err)
	}
	return bundle, record, true, nil
}

func (s *SQLiteStore) ListPolicyVersions(limit int) ([]policy.VersionRecord, error) {
	if limit < 1 {
		limit = 100
	}
	rows, err := s.db.QueryContext(context.Background(), `
SELECT version, status, active, rule_count, published_at, COALESCE(published_by, ''), COALESCE(message, ''), source_version
FROM policy_versions
ORDER BY version DESC
LIMIT ?
`, limit)
	if err != nil {
		return nil, fmt.Errorf("list policy versions: %w", err)
	}
	defer rows.Close()

	records := make([]policy.VersionRecord, 0, limit)
	for rows.Next() {
		record, err := scanPolicyRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy versions: %w", err)
	}
	return records, nil
}

func (s *SQLiteStore) SavePolicyBundle(bundle policy.Bundle) error {
	if err := bundle.Validate(); err != nil {
		return fmt.Errorf("validate policy bundle: %w", err)
	}
	bundleJSON, err := json.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("marshal policy bundle: %w", err)
	}
	_, err = s.db.ExecContext(context.Background(), `
INSERT INTO policy_bundles (
	bundle_id,
	name,
	description,
	priority,
	status,
	bundle_json,
	created_at,
	updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(bundle_id) DO UPDATE SET
	name = excluded.name,
	description = excluded.description,
	priority = excluded.priority,
	status = excluded.status,
	bundle_json = excluded.bundle_json,
	updated_at = excluded.updated_at
`,
		bundle.BundleID,
		bundle.Name,
		bundle.Description,
		bundle.Priority,
		bundle.Status,
		string(bundleJSON),
		bundle.CreatedAt.Format(time.RFC3339Nano),
		bundle.UpdatedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("save policy bundle: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetPolicyBundle(bundleID string) (policy.Bundle, bool, error) {
	row := s.db.QueryRowContext(context.Background(), `
SELECT bundle_id, name, description, priority, status, bundle_json, created_at, updated_at
FROM policy_bundles
WHERE bundle_id = ?
`, bundleID)
	bundle, err := scanPolicyBundle(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return policy.Bundle{}, false, nil
		}
		return policy.Bundle{}, false, fmt.Errorf("get policy bundle: %w", err)
	}
	return bundle, true, nil
}

func (s *SQLiteStore) ListPolicyBundles(includeArchived bool) ([]policy.Bundle, error) {
	query := `
SELECT bundle_id, name, description, priority, status, bundle_json, created_at, updated_at
FROM policy_bundles
`
	if !includeArchived {
		query += `WHERE status != 'archived'
`
	}
	query += `ORDER BY priority DESC, updated_at DESC, bundle_id ASC`
	rows, err := s.db.QueryContext(context.Background(), query)
	if err != nil {
		return nil, fmt.Errorf("list policy bundles: %w", err)
	}
	defer rows.Close()

	bundles := make([]policy.Bundle, 0)
	for rows.Next() {
		bundle, err := scanPolicyBundle(rows)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, bundle)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy bundles: %w", err)
	}
	return bundles, nil
}

func (s *SQLiteStore) ArchivePolicyBundle(bundleID string, updatedAt time.Time) error {
	result, err := s.db.ExecContext(context.Background(), `
UPDATE policy_bundles
SET status = 'archived',
	updated_at = ?
WHERE bundle_id = ?
`, updatedAt.Format(time.RFC3339Nano), bundleID)
	if err != nil {
		return fmt.Errorf("archive policy bundle: %w", err)
	}
	if rows, err := result.RowsAffected(); err == nil && rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func nullable(value string) interface{} {
	if value == "" {
		return nil
	}
	return value
}

func nullableInt(value int) interface{} {
	if value == 0 {
		return nil
	}
	return value
}

type approvalScanner interface {
	Scan(dest ...interface{}) error
}

func scanApproval(scanner approvalScanner) (types.ApprovalRecord, error) {
	var approval types.ApprovalRecord
	var status string
	var createdAt string
	var expiresAt string
	var resolvedAt sql.NullString
	if err := scanner.Scan(
		&approval.ApprovalID,
		&approval.RequestID,
		&approval.SessionID,
		&approval.TaskID,
		&approval.AttemptID,
		&status,
		&approval.Reason,
		&approval.OperatorID,
		&approval.Channel,
		&createdAt,
		&expiresAt,
		&resolvedAt,
	); err != nil {
		return types.ApprovalRecord{}, fmt.Errorf("scan approval: %w", err)
	}

	approval.Status = types.ApprovalStatus(status)
	var err error
	approval.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return types.ApprovalRecord{}, fmt.Errorf("parse approval created_at: %w", err)
	}
	approval.ExpiresAt, err = time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return types.ApprovalRecord{}, fmt.Errorf("parse approval expires_at: %w", err)
	}
	if resolvedAt.Valid {
		parsed, err := time.Parse(time.RFC3339Nano, resolvedAt.String)
		if err != nil {
			return types.ApprovalRecord{}, fmt.Errorf("parse approval resolved_at: %w", err)
		}
		approval.ResolvedAt = &parsed
	}
	return approval, nil
}

type policyVersionScanner interface {
	Scan(dest ...interface{}) error
}

func scanPolicyVersion(scanner policyVersionScanner) (policy.Bundle, policy.VersionRecord, error) {
	var bundleJSON string
	record, err := scanPolicyRecordWithBundle(scanner, &bundleJSON)
	if err != nil {
		return policy.Bundle{}, policy.VersionRecord{}, err
	}
	var bundle policy.Bundle
	if err := json.Unmarshal([]byte(bundleJSON), &bundle); err != nil {
		return policy.Bundle{}, policy.VersionRecord{}, fmt.Errorf("unmarshal policy bundle: %w", err)
	}
	if err := bundle.Validate(); err != nil {
		return policy.Bundle{}, policy.VersionRecord{}, fmt.Errorf("validate stored policy bundle: %w", err)
	}
	return bundle, record, nil
}

func scanPolicyRecord(scanner policyVersionScanner) (policy.VersionRecord, error) {
	var record policy.VersionRecord
	var active int
	var publishedAt string
	var sourceVersion sql.NullInt64
	if err := scanner.Scan(
		&record.Version,
		&record.Status,
		&active,
		&record.RuleCount,
		&publishedAt,
		&record.PublishedBy,
		&record.Message,
		&sourceVersion,
	); err != nil {
		return policy.VersionRecord{}, fmt.Errorf("scan policy version: %w", err)
	}
	return finishPolicyRecord(record, active, publishedAt, sourceVersion)
}

func scanPolicyRecordWithBundle(scanner policyVersionScanner, bundleJSON *string) (policy.VersionRecord, error) {
	var record policy.VersionRecord
	var active int
	var publishedAt string
	var sourceVersion sql.NullInt64
	if err := scanner.Scan(
		&record.Version,
		bundleJSON,
		&record.Status,
		&active,
		&record.RuleCount,
		&publishedAt,
		&record.PublishedBy,
		&record.Message,
		&sourceVersion,
	); err != nil {
		return policy.VersionRecord{}, fmt.Errorf("scan policy version: %w", err)
	}
	return finishPolicyRecord(record, active, publishedAt, sourceVersion)
}

func finishPolicyRecord(record policy.VersionRecord, active int, publishedAt string, sourceVersion sql.NullInt64) (policy.VersionRecord, error) {
	record.Active = active == 1
	var err error
	record.PublishedAt, err = time.Parse(time.RFC3339Nano, publishedAt)
	if err != nil {
		return policy.VersionRecord{}, fmt.Errorf("parse policy published_at: %w", err)
	}
	if sourceVersion.Valid {
		record.SourceVersion = int(sourceVersion.Int64)
	}
	return record, nil
}

func scanPolicyBundle(scanner policyVersionScanner) (policy.Bundle, error) {
	var bundle policy.Bundle
	var bundleJSON string
	var createdAt string
	var updatedAt string
	if err := scanner.Scan(
		&bundle.BundleID,
		&bundle.Name,
		&bundle.Description,
		&bundle.Priority,
		&bundle.Status,
		&bundleJSON,
		&createdAt,
		&updatedAt,
	); err != nil {
		return policy.Bundle{}, fmt.Errorf("scan policy bundle: %w", err)
	}
	var stored policy.Bundle
	if err := json.Unmarshal([]byte(bundleJSON), &stored); err != nil {
		return policy.Bundle{}, fmt.Errorf("unmarshal policy bundle: %w", err)
	}
	stored.BundleID = bundle.BundleID
	stored.Name = bundle.Name
	stored.Description = bundle.Description
	stored.Priority = bundle.Priority
	stored.Status = bundle.Status
	bundle = stored
	var err error
	bundle.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return policy.Bundle{}, fmt.Errorf("parse policy bundle created_at: %w", err)
	}
	bundle.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return policy.Bundle{}, fmt.Errorf("parse policy bundle updated_at: %w", err)
	}
	if err := bundle.Validate(); err != nil {
		return policy.Bundle{}, fmt.Errorf("validate policy bundle: %w", err)
	}
	return bundle, nil
}
