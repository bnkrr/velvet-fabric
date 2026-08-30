package control

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestStatusReloadAndShutdown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var reloads atomic.Int32
	shutdown := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, path, "test", Handlers{
			Status: func() any { return map[string]bool{"ready": true} },
			Reload: func(context.Context) error {
				reloads.Add(1)
				return nil
			},
			Shutdown: func() { close(shutdown) },
		})
	}()
	deadline := time.Now().Add(time.Second)
	for {
		var result struct {
			Ready bool `json:"ready"`
		}
		if Request(context.Background(), path, "status", &result) == nil {
			if !result.Ready {
				t.Fatal("status did not preserve result")
			}
			break
		}
		select {
		case err := <-done:
			if errors.Is(err, syscall.EPERM) {
				t.Skip("sandbox forbids Unix sockets")
			}
			t.Fatalf("control server stopped: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("control socket did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := Request(context.Background(), path, "reload", nil); err != nil {
		t.Fatal(err)
	}
	if reloads.Load() != 1 {
		t.Fatalf("reload count = %d", reloads.Load())
	}
	if err := Request(context.Background(), path, "shutdown", nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-shutdown:
	case <-time.After(time.Second):
		t.Fatal("shutdown callback did not run after response")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
