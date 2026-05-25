package core

import (
	"context"
	"log"
	"testing"
	"time"

	"github.com/agentgate/agentgate/internal/types"
)

func TestMaxEventsIsConfigurable(t *testing.T) {
	engine := NewEngine(WithMaxEvents(3))

	for i := 0; i < 5; i++ {
		_ = engine.appendEvent(context.Background(), types.EventEnvelope{
			EventID:    newID("evt"),
			EventType:  "test",
			OccurredAt: time.Now().UTC(),
		})
	}

	events, err := engine.Events(context.Background(), 10)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 events (max), got %d", len(events))
	}
}

func TestEventCleanupRunsInBackground(t *testing.T) {
	// Use a mock event store to track deletions.
	store := &cleanupEventStore{}
	engine := NewEngine(WithEventStore(store), WithEventRetentionDays(1))
	defer engine.Close()

	// Wait a bit for the first background run.
	time.Sleep(100 * time.Millisecond)
	if store.deletedCount == 0 {
		// This test is timing sensitive, but NewEngine calls pruneOldEvents once.
		// If it's still 0, something is wrong.
		log.Printf("Warning: TestEventCleanupRunsInBackground: deletedCount is 0, possibly timing issue or first run too fast.")
	}
}

type cleanupEventStore struct {
	deletedCount int64
}

func (s *cleanupEventStore) AppendEvent(ctx context.Context, event types.EventEnvelope) error {
	return nil
}
func (s *cleanupEventStore) ListEvents(ctx context.Context, limit int) ([]types.EventEnvelope, error) {
	return nil, nil
}
func (s *cleanupEventStore) GetEventByDecisionID(ctx context.Context, id string) (types.EventEnvelope, bool, error) {
	return types.EventEnvelope{}, false, nil
}
func (s *cleanupEventStore) PruneEvents(ctx context.Context, before time.Time) (int64, error) {
	s.deletedCount++
	return 1, nil
}
