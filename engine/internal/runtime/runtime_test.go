package runtime

import (
	"testing"
	"time"
)

func TestRuntimeStartsStopped(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.FixedZone("CST", 8*60*60))
	engineRuntime := New(func() time.Time { return now })

	got := engineRuntime.Snapshot()
	if got.State != StateStopped {
		t.Fatalf("initial state = %q, want %q", got.State, StateStopped)
	}
	if got.Sequence != 0 {
		t.Fatalf("initial sequence = %d, want 0", got.Sequence)
	}
	if !got.StateChangedAt.Equal(now.UTC()) {
		t.Fatalf("initial timestamp = %v, want %v", got.StateChangedAt, now.UTC())
	}
}

func TestRuntimeAcceptsExpectedLifecycle(t *testing.T) {
	engineRuntime := New(time.Now)
	path := []State{
		StateStarting,
		StateRunning,
		StateDegraded,
		StateRunning,
		StateStopping,
		StateStopped,
	}

	for index, state := range path {
		change, err := engineRuntime.Transition(state, "test")
		if err != nil {
			t.Fatalf("transition to %q failed: %v", state, err)
		}
		if change.Current.State != state {
			t.Fatalf("transition state = %q, want %q", change.Current.State, state)
		}
		if change.Current.Sequence != uint64(index+1) {
			t.Fatalf("sequence = %d, want %d", change.Current.Sequence, index+1)
		}
	}
}

func TestRuntimeRejectsInvalidTransition(t *testing.T) {
	engineRuntime := New(time.Now)

	if _, err := engineRuntime.Transition(StateRunning, "skip startup"); err == nil {
		t.Fatal("stopped -> running unexpectedly succeeded")
	}
	if got := engineRuntime.Snapshot().State; got != StateStopped {
		t.Fatalf("state changed after rejected transition: %q", got)
	}
}

func TestRuntimeClampsStateChangedAtOnClockRollback(t *testing.T) {
	base := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	current := base
	engineRuntime := New(func() time.Time { return current })

	starting, err := engineRuntime.Transition(StateStarting, "test")
	if err != nil {
		t.Fatalf("transition to starting failed: %v", err)
	}
	if !starting.Current.StateChangedAt.Equal(base) {
		t.Fatalf("starting timestamp = %v, want %v", starting.Current.StateChangedAt, base)
	}

	current = base.Add(-90 * time.Second)
	rolled, err := engineRuntime.Transition(StateRunning, "test")
	if err != nil {
		t.Fatalf("transition to running failed: %v", err)
	}
	if rolled.Current.StateChangedAt.Before(starting.Current.StateChangedAt) {
		t.Fatalf(
			"timestamp regressed to %v after %v",
			rolled.Current.StateChangedAt,
			starting.Current.StateChangedAt,
		)
	}
	if rolled.Current.Sequence != starting.Current.Sequence+1 {
		t.Fatalf("sequence = %d, want %d", rolled.Current.Sequence, starting.Current.Sequence+1)
	}

	current = base.Add(time.Minute)
	forward, err := engineRuntime.Transition(StateDegraded, "test")
	if err != nil {
		t.Fatalf("transition to degraded failed: %v", err)
	}
	if !forward.Current.StateChangedAt.Equal(base.Add(time.Minute)) {
		t.Fatalf("forward timestamp = %v, want %v", forward.Current.StateChangedAt, base.Add(time.Minute))
	}
}
