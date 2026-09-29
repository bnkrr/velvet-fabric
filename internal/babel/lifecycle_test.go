package babel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
)

// Re-execute this test binary as a tiny Babel process. This exercises command
// startup, the Unix control protocol, config files and process reaping together.
func TestBabelProcessHelper(t *testing.T) {
	scenario := os.Getenv("VELVET_TEST_BABEL")
	if scenario == "" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	args = args[1:]
	config, err := os.ReadFile(args[2])
	if err != nil {
		os.Exit(2)
	}
	if args[0] == "check" {
		if scenario == "check-fails" || scenario == "check-reject" && bytes.Contains(config, []byte("10.77.0.0/24")) {
			os.Exit(1)
		}
		os.Exit(0)
	}
	if scenario == "early-exit" {
		os.Exit(1)
	}
	listener, err := net.Listen("unix", args[4])
	if err != nil {
		os.Exit(2)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(config))
	generation := 1
	for {
		conn, err := listener.Accept()
		if err != nil {
			os.Exit(2)
		}
		encoder := json.NewEncoder(conn)
		_ = encoder.Encode(map[string]any{"api_version": 1, "server_version": "test", "capabilities": []string{"status", "reload", "shutdown"}})
		var request struct {
			Command string `json:"command"`
		}
		if json.NewDecoder(conn).Decode(&request) != nil {
			_ = conn.Close()
			continue
		}
		ok := true
		if request.Command == "reload" {
			if scenario == "reload-reject" {
				ok = false
			} else {
				config, err = os.ReadFile(args[2])
				if err != nil {
					os.Exit(2)
				}
				digest = fmt.Sprintf("%x", sha256.Sum256(config))
				generation++
				if scenario == "digest-mismatch" {
					digest = "wrong"
				}
			}
		}
		_ = encoder.Encode(map[string]any{"api_version": 1, "id": 1, "ok": ok, "result": map[string]any{"ready": true, "version": "test", "config_generation": generation, "active_config_sha256": digest}, "error": map[string]string{"code": "rejected", "message": "test rejection"}})
		_ = conn.Close()
		if request.Command == "shutdown" {
			_ = listener.Close()
			os.Exit(0)
		}
	}
}

func TestManagerLifecycle(t *testing.T) {
	for _, scenario := range []string{"check-fails", "early-exit", "check-reject", "reload-reject", "digest-mismatch", "reload-success"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("VELVET_TEST_BABEL", scenario)
			t.Setenv("GORACE", os.Getenv("GORACE")+" atexit_sleep_ms=0")
			dir := t.TempDir()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			wrapper := filepath.Join(dir, "babel")
			script := "#!/bin/sh\nexec '" + strings.ReplaceAll(executable, "'", "'\"'\"'") + "' -test.run=^TestBabelProcessHelper$ -- \"$@\"\n"
			if err := os.WriteFile(wrapper, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			plan := &reconcile.BabelPlan{Executable: wrapper, ConfigPath: filepath.Join(dir, "config"), StatePath: filepath.Join(dir, "state"), ControlPath: filepath.Join(dir, "control"), Interfaces: []string{"vl-test"}}
			ctx, cancel := context.WithCancel(context.Background())
			events := make(chan Event, 16)
			manager := New(plan, func(event Event) {
				if event.Status == "retrying" {
					cancel()
				}
				events <- event
			})
			done := make(chan struct{})
			go func() { manager.Run(ctx); close(done) }()
			pid := 0
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					t.Error("manager did not stop")
				}
				if err := StopInstance(context.Background(), dir); err != nil {
					t.Error(err)
				}
				until := time.Now().Add(time.Second)
				for pid != 0 && processStart(pid) != "" && time.Now().Before(until) {
					time.Sleep(time.Millisecond)
				}
				if pid != 0 && processStart(pid) != "" {
					t.Error("explicit stop left Babel running")
				}
			})
			await := func(want string) Event {
				t.Helper()
				select {
				case event := <-events:
					if event.Status != want {
						t.Fatalf("event %#v, want %s", event, want)
					}
					return event
				case <-time.After(15 * time.Second):
					t.Fatalf("missing %s event", want)
				}
				return Event{}
			}
			if scenario == "check-fails" || scenario == "early-exit" {
				event := await("retrying")
				expected := "rejected generated config"
				if scenario == "early-exit" {
					expected = "control unavailable"
				}
				if !strings.Contains(event.Error, expected) {
					t.Fatal(event.Error)
				}
			} else {
				await("running")
				before := manager.Status()
				pid = before.PID
				active, err := os.ReadFile(plan.ConfigPath)
				if err != nil {
					t.Fatal(err)
				}
				manager.SetLinkState("vl-test", true, []netip.Prefix{netip.MustParsePrefix("10.77.0.1/24")})
				switch scenario {
				case "check-reject", "reload-reject":
					event := await("retrying")
					expected := "rejected generated config"
					if scenario == "reload-reject" {
						expected = "reload rejected"
					}
					if !strings.Contains(event.Error, expected) {
						t.Fatal(event.Error)
					}
					restored, err := os.ReadFile(plan.ConfigPath)
					if err != nil || !bytes.Equal(active, restored) {
						t.Fatalf("rejected config was not restored: %v", err)
					}
					var current daemonStatus
					if err := controlRequest(context.Background(), plan.ControlPath, "status", &current); err != nil || current.ActiveConfigSHA256 != before.ActiveConfigSHA256 || servicePID(plan) != pid {
						t.Fatalf("rejection disrupted independent daemon: %v %#v", err, current)
					}
				case "digest-mismatch":
					if event := await("retrying"); !strings.Contains(event.Error, "activated config digest") {
						t.Fatal(event.Error)
					}
				case "reload-success":
					await("reloaded")
					after := manager.Status()
					data, err := os.ReadFile(plan.ConfigPath)
					if err != nil || after.ConfigGeneration != 2 || after.ActiveConfigSHA256 != fmt.Sprintf("%x", sha256.Sum256(data)) || !bytes.Contains(data, []byte("10.77.0.0/24")) {
						t.Fatalf("reload failed: %#v %v", after, err)
					}
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("cancel did not stop manager")
			}
			if pid != 0 && servicePID(plan) != pid {
				t.Fatal("manager cancellation stopped independent Babel")
			}
			if scenario == "reload-success" {
				// A new Fabric manager attaches to the same Babel process.
				next := New(plan, nil)
				next.SetLinkState("vl-test", true, []netip.Prefix{netip.MustParsePrefix("10.77.0.1/24")})
				resumed, stop := context.WithCancel(context.Background())
				finished := make(chan struct{})
				go func() { next.Run(resumed); close(finished) }()
				deadline := time.Now().Add(5 * time.Second)
				for next.Status().State != "running" && time.Now().Before(deadline) {
					time.Sleep(10 * time.Millisecond)
				}
				if next.Status().PID != pid {
					stop()
					<-finished
					t.Fatal("reattachment replaced Babel")
				}
				stop()
				<-finished
			}
			if status := manager.Status(); status.State != "stopped" || status.PID != 0 {
				t.Fatalf("stale final status: %#v", status)
			}
		})
	}
}
