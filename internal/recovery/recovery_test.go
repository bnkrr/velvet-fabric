package recovery

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
)

func TestFailureEpisodeSurvivesRestart(t *testing.T) {
	t0 := time.Now()
	d := &reconcile.DesiredState{UUID: uuid.New(), FabricTableID: 20000}
	tracker := &Tracker{Path: filepath.Join(t.TempDir(), "state"), Window: 30 * time.Minute, Stable: time.Minute}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(tracker.Begin(d, t0))
	for i := 1; i <= 6; i++ {
		now := t0.Add(time.Duration(i) * 5 * time.Minute)
		must(tracker.Begin(d, now))
		must(tracker.Progress(now, true))
		must(tracker.Failure(now.Add(time.Second)))
	}
	calls := 0
	retire := func(s State) error {
		calls++
		if !s.FailureSince.Equal(t0) || s.Node != d.UUID.String() {
			t.Fatal("restart extended or replaced episode")
		}
		if calls == 1 {
			return errors.New("temporary cleanup failure")
		}
		return nil
	}
	if tracker.Check(t0.Add(31*time.Minute), retire) == nil {
		t.Fatal("cleanup failure swallowed")
	}
	must(tracker.Check(t0.Add(32*time.Minute), retire))
	must(tracker.Check(t0.Add(33*time.Minute), retire))
	if calls != 2 {
		t.Fatalf("cleanup calls = %d", calls)
	}
}

func TestStableRecoveryAndIntentionalStop(t *testing.T) {
	t0 := time.Now()
	d := &reconcile.DesiredState{UUID: uuid.New(), FabricTableID: 20000}
	tracker := &Tracker{Path: filepath.Join(t.TempDir(), "state"), Window: 30 * time.Minute, Stable: time.Minute}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(tracker.Begin(d, t0))
	must(tracker.Progress(t0, true))
	must(tracker.Progress(t0.Add(time.Minute), true))
	// ExecStopPost may never run: the independent checker still has a deadline.
	called := false
	must(tracker.Check(t0.Add(20*time.Minute), func(State) error { called = true; return nil }))
	if called {
		t.Fatal("stable recovery inherited previous failure")
	}
	must(tracker.Stop())
	must(tracker.Check(t0.Add(time.Hour), func(State) error { called = true; return nil }))
	if called {
		t.Fatal("intentional stop triggered retirement")
	}
	must(tracker.Begin(d, t0.Add(2*time.Hour)))
	must(tracker.Check(t0.Add(3*time.Hour), func(State) error { called = true; return nil }))
	if !called {
		t.Fatal("both daemons absent did not reach deadline")
	}
}

func TestOtherNamespaceIsNeverRetired(t *testing.T) {
	tracker := &Tracker{Path: filepath.Join(t.TempDir(), "state")}
	if err := tracker.update(func(s *State) error {
		*s = State{Node: uuid.NewString(), Namespace: "other", Running: true, FailureSince: time.Now().Add(-time.Hour), Window: time.Minute}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := tracker.Check(time.Now(), func(State) error { t.Fatal("foreign namespace cleaned"); return nil }); err != nil {
		t.Fatal(err)
	}
}
