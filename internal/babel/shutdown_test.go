package babel

import (
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A daemon with no usable control socket still gets its five-second cleanup
// budget after SIGTERM. Re-exec exercises actual signal delivery and reaping.
func TestSlowShutdownProcessHelper(t *testing.T) {
	marker := os.Getenv("VELVET_TEST_SLOW_SHUTDOWN")
	if marker == "" {
		return
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM)
	if err := os.WriteFile(marker+".ready", []byte("ready"), 0o600); err != nil {
		os.Exit(2)
	}
	<-signals
	time.Sleep(4 * time.Second)
	if err := os.WriteFile(marker, []byte("cleaned"), 0o600); err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

func TestStopAllowsBabelShutdownBudgetWithoutControl(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "cleaned")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestSlowShutdownProcessHelper$")
	command.Env = append(os.Environ(), "VELVET_TEST_SLOW_SHUTDOWN="+marker, "GORACE="+os.Getenv("GORACE")+" atexit_sleep_ms=0")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	done := make(chan struct{})
	go func() { waited <- command.Wait(); close(done) }()
	t.Cleanup(func() {
		select {
		case <-done:
		default:
			_ = command.Process.Kill()
			<-done
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(marker + ".ready"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	stop(filepath.Join(dir, "missing-control"), command, waited)
	<-done
	if data, err := os.ReadFile(marker); err != nil || string(data) != "cleaned" || !command.ProcessState.Success() {
		t.Fatalf("child was interrupted before its cleanup budget: marker=%q error=%v state=%s", data, err, command.ProcessState)
	}
}
