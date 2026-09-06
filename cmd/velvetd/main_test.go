package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
)

func TestCancelAndWaitConfirmsExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		<-ctx.Done()
		done <- nil
	}()
	if err := cancelAndWait(cancel, done, time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestCancelAndWaitRejectsStuckRuntime(t *testing.T) {
	done := make(chan error)
	err := cancelAndWait(func() {}, done, 10*time.Millisecond)
	if !errors.Is(err, errRunnerDidNotStop) {
		t.Fatalf("got %v, want errRunnerDidNotStop", err)
	}
}

func TestReloadGenerationTransaction(t *testing.T) {
	for _, scenario := range []string{"equivalent", "identity-change", "commit", "candidate-fails", "stop-fails", "candidate-stuck", "rollback-fails"} {
		t.Run(scenario, func(t *testing.T) {
			old := &reconcile.DesiredState{UUID: uuid.MustParse("10000000-0000-4000-8000-000000000001"), VFPPort: 58420}
			candidate := *old
			candidate.VFPPort++
			active := &running{desired: old}
			status := daemonStatus{Ready: true, ConfigGeneration: 7}
			var starts []*reconcile.DesiredState
			stopped := false
			stop := func(got *running) error {
				if got != active {
					t.Fatal("stopped wrong runtime")
				}
				stopped = true
				if scenario == "stop-fails" {
					return errRunnerDidNotStop
				}
				return nil
			}
			failure := errors.New("start failed")
			start := func(desired *reconcile.DesiredState) (*running, error) {
				if !stopped || status.Ready {
					t.Fatal("started replacement before stopping old generation")
				}
				starts = append(starts, desired)
				if scenario == "candidate-stuck" {
					return nil, errRunnerDidNotStop
				}
				if scenario == "rollback-fails" || scenario == "candidate-fails" && len(starts) == 1 {
					return nil, failure
				}
				return &running{desired: desired}, nil
			}
			if scenario == "equivalent" {
				candidate = *old
			}
			if scenario == "identity-change" {
				candidate.UUID = uuid.New()
			}
			next, err := reloadCandidate(&candidate, active, start, stop, func(update func(*daemonStatus)) { update(&status) })
			switch scenario {
			case "equivalent", "identity-change":
				if next != active || stopped || len(starts) != 0 || !status.Ready || status.ConfigGeneration != 7 || (err != nil) != (scenario == "identity-change") {
					t.Fatalf("preflight changed runtime: %v %#v", err, status)
				}
			case "commit":
				if err != nil || next == nil || next.desired != &candidate || !status.Ready || status.ConfigGeneration != 8 || len(starts) != 1 || status.LastReloadError != "" {
					t.Fatalf("commit=%v %#v", err, status)
				}
			case "candidate-fails":
				if !errors.Is(err, failure) || next == nil || next.desired != old || !status.Ready || status.ConfigGeneration != 7 || len(starts) != 2 || starts[1] != old || status.LastReloadError == "" {
					t.Fatalf("rollback=%v %#v", err, status)
				}
			default:
				wantStarts := map[string]int{"stop-fails": 0, "candidate-stuck": 1, "rollback-fails": 2}[scenario]
				if err == nil || next != nil || status.Ready || status.ConfigGeneration != 7 || len(starts) != wantStarts {
					t.Fatalf("unsafe restart: err=%v starts=%d status=%#v", err, len(starts), status)
				}
			}
		})
	}
}
