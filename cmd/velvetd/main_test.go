package main

import (
	"context"
	"errors"
	"testing"
	"time"
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
