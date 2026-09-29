package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/velvet-fabric/velvet-fabric/internal/babel"
	"github.com/velvet-fabric/velvet-fabric/internal/control"
	linuxbackend "github.com/velvet-fabric/velvet-fabric/internal/linux"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/recovery"
	velvetruntime "github.com/velvet-fabric/velvet-fabric/internal/runtime"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
)

type daemonStatus struct {
	Version          string               `json:"version"`
	Ready            bool                 `json:"ready"`
	ConfigGeneration uint64               `json:"config_generation"`
	LastReloadError  string               `json:"last_reload_error,omitempty"`
	Runtime          velvetruntime.Status `json:"runtime"`
}

type running struct {
	desired *reconcile.DesiredState
	runner  *velvetruntime.Runner
	cancel  context.CancelFunc
	done    <-chan error
}

type reloadRequest struct {
	reply chan error
}

var errRunnerDidNotStop = errors.New("runtime did not stop after cancellation")

// releaseVersion is set by release builds with -ldflags '-X main.releaseVersion=...'.
var releaseVersion string
var systemdBabel bool
var errNamespaceOwned = errors.New("another velvetd already owns this network namespace")

func main() {
	recoveryCheck := flag.Bool("recovery-check", false, "retire an instance after its recovery deadline")
	recoveryRecord := flag.Bool("recovery-record", false, "record systemd service failure")
	recoveryWindow := flag.Duration("recovery-window", 30*time.Minute, "maximum continuous local recovery failure")
	recoveryStable := flag.Duration("recovery-stable", time.Minute, "healthy maintenance required to end a failure episode")
	babelExec := flag.String("babel-exec", "", "execute an independent Babel service from its launch description")
	flag.BoolVar(&systemdBabel, "babel-systemd", false, "manage Babel using its independent systemd unit")
	configPath := flag.String("config", "", "path to a NodeSpec JSON file")
	controlPath := flag.String("control-socket", "", "Unix control socket (default: per-node runtime directory)")
	once := flag.Bool("once", false, "exit after every configured adjacent Link is established")
	interval := flag.Duration("reconcile-interval", 15*time.Second, "kernel reconciliation interval")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *babelExec != "" {
		if err := babel.ExecService(*babelExec); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *showVersion {
		fmt.Println(version())
		return
	}
	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "velvetd: --config is required")
		os.Exit(2)
	}
	if *interval <= 0 {
		fmt.Fprintln(os.Stderr, "velvetd: --reconcile-interval must be positive")
		os.Exit(2)
	}
	if *recoveryWindow <= 0 || *recoveryStable <= 0 {
		log.Fatal("recovery durations must be positive")
	}
	tracker, err := recovery.New("/var/lib/velvet", *configPath, *recoveryWindow, *recoveryStable)
	if err != nil {
		log.Fatal(err)
	}
	if *recoveryRecord {
		if result := os.Getenv("SERVICE_RESULT"); result != "" && result != "success" {
			if err := tracker.Failure(time.Now()); err != nil {
				log.Fatal(err)
			}
		}
		return
	}
	lock, err := acquireSingleton()
	if *recoveryCheck && errors.Is(err, errNamespaceOwned) {
		return
	}
	if err != nil {
		log.Fatalf("velvetd: %v", err)
	}
	defer lock.Close()
	if *recoveryCheck {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		err := tracker.Check(time.Now(), func(state recovery.State) error {
			if err := babel.StopInstance(ctx, filepath.Join("/var/lib/velvet", state.Node)); err != nil {
				return err
			}
			return linuxbackend.RetireInstance(ctx, state.Node, state.Tables)
		})
		if err != nil {
			log.Fatal(err)
		}
		return
	}
	desired, err := loadDesired(*configPath)
	if err != nil {
		log.Fatalf("velvetd: %v", err)
	}
	if err := tracker.Begin(desired, time.Now()); err != nil {
		log.Fatal(err)
	}
	if *controlPath == "" {
		*controlPath = filepath.Join("/run/velvet", desired.UUID.String(), "velvetd.ctl")
	}

	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	hangup := make(chan os.Signal, 1)
	signal.Notify(hangup, syscall.SIGHUP)
	defer signal.Stop(hangup)

	encoder := json.NewEncoder(os.Stdout)
	var logMu sync.Mutex
	logEvent := func(event velvetruntime.Event) {
		logMu.Lock()
		defer logMu.Unlock()
		_ = encoder.Encode(event)
	}
	var statusMu sync.RWMutex
	status := daemonStatus{Version: version(), ConfigGeneration: 1}
	setStatus := func(update func(*daemonStatus)) {
		statusMu.Lock()
		update(&status)
		statusMu.Unlock()
	}
	getStatus := func(active *running) daemonStatus {
		statusMu.RLock()
		value := status
		statusMu.RUnlock()
		if active != nil {
			value.Runtime = active.runner.Status()

		}
		return value
	}

	active, err := startRunner(rootCtx, desired, *interval, *once, logEvent)
	if err != nil {
		log.Fatalf("velvetd: %v", err)
	}
	setStatus(func(value *daemonStatus) { value.Ready = true })
	var activePointer atomic.Pointer[running]
	activePointer.Store(active)

	reloads := make(chan reloadRequest)
	controlCtx, controlCancel := context.WithCancel(rootCtx)
	defer controlCancel()
	controlErrors := make(chan error, 1)
	go func() {
		controlErrors <- control.Serve(controlCtx, *controlPath, version(), control.Handlers{
			Status: func() any { return getStatus(activePointer.Load()) },
			DeleteDurable: func(peer string) error {
				current := activePointer.Load()
				if current == nil {
					return errors.New("runtime unavailable")
				}
				return current.runner.DeleteDurable(peer)
			},
			Reload: func(ctx context.Context) error {
				request := reloadRequest{reply: make(chan error, 1)}
				select {
				case reloads <- request:
				case <-ctx.Done():
					return ctx.Err()
				case <-rootCtx.Done():
					return errors.New("velvetd is stopping")
				}
				select {
				case err := <-request.reply:
					return err
				case <-ctx.Done():
					return ctx.Err()
				}
			},
			Shutdown: stop,
		})
	}()

	_ = recovery.Notify("READY=1")
	health := time.NewTicker(5 * time.Second)
	defer health.Stop()
	for {
		select {
		case now := <-health.C:
			healthy := active.runner.Progressing(now)
			if err := tracker.Progress(now, healthy); err != nil {
				log.Printf("velvetd: record progress: %v", err)
				healthy = false
			}
			if healthy {
				_ = recovery.Notify("WATCHDOG=1")
			}
		case <-rootCtx.Done():
			if err := stopRunner(active); err != nil {
				log.Fatalf("velvetd: %v", err)
			}
			if err := tracker.Stop(); err != nil {
				log.Fatal(err)
			}
			return
		case err := <-active.done:
			if rootCtx.Err() != nil {
				if e := tracker.Stop(); e != nil {
					log.Fatal(e)
				}
				return
			}
			if *once && err == nil {
				_ = tracker.Stop()
				return
			}
			if err == nil || errors.Is(err, context.Canceled) {
				err = errors.New("runtime stopped unexpectedly")
			}
			log.Fatalf("velvetd: %v", err)
		case err := <-controlErrors:
			if rootCtx.Err() == nil {
				log.Fatalf("velvetd: control server: %v", err)
			}
			if err := stopRunner(active); err != nil {
				log.Fatal(err)
			}
			if err := tracker.Stop(); err != nil {
				log.Fatal(err)
			}
			return
		case <-hangup:
			active, err = reload(rootCtx, *configPath, active, *interval, *once, logEvent, setStatus)
			if active == nil {
				log.Fatalf("velvetd: configuration reload and rollback failed: %v", err)
			}
			activePointer.Store(active)
			if e := tracker.UpdateDesired(active.desired); e != nil {
				log.Fatal(e)
			}
			if err != nil {
				log.Printf("velvetd: configuration reload rejected: %v", err)
			}
		case request := <-reloads:
			active, err = reload(rootCtx, *configPath, active, *interval, *once, logEvent, setStatus)
			if active == nil {
				log.Fatalf("velvetd: configuration reload and rollback failed: %v", err)
			}
			activePointer.Store(active)
			if e := tracker.UpdateDesired(active.desired); e != nil {
				log.Fatal(e)
			}
			request.reply <- err
		}
	}
}

func loadDesired(path string) (*reconcile.DesiredState, error) {
	nodeSpec, err := spec.Load(path)
	if err != nil {
		return nil, err
	}
	desired, err := reconcile.BuildDesiredState(nodeSpec)
	if err == nil && desired.Babel != nil && systemdBabel {
		desired.Babel.ServiceName = "velvet-babel@" + desired.UUID.String() + ".service"
	}
	return desired, err
}

func startRunner(ctx context.Context, desired *reconcile.DesiredState, interval time.Duration, once bool, logEvent func(velvetruntime.Event), previous ...*velvetruntime.Runner) (*running, error) {
	runCtx, cancel := context.WithCancel(ctx)
	ready := make(chan error, 1)
	done := make(chan error, 1)
	runner := &velvetruntime.Runner{Desired: desired, Reconciler: reconcile.New(linuxbackend.New()), Interval: interval, Log: logEvent, Ready: ready}
	if len(previous) > 0 {
		runner.InheritDynamic(previous[0])
	}
	go func() { done <- runner.Run(runCtx, once) }()
	select {
	case err := <-ready:
		if err != nil {
			if stopErr := cancelAndWait(cancel, done, 10*time.Second); stopErr != nil {
				return nil, fmt.Errorf("%w after startup error: %v", stopErr, err)
			}
			return nil, err
		}
		return &running{desired: desired, runner: runner, cancel: cancel, done: done}, nil
	case err := <-done:
		cancel()
		if err == nil {
			err = errors.New("runtime stopped before readiness")
		}
		return nil, err
	case <-time.After(30 * time.Second):
		if err := cancelAndWait(cancel, done, 10*time.Second); err != nil {
			return nil, err
		}
		return nil, errors.New("runtime did not become ready within 30s")
	case <-ctx.Done():
		if err := cancelAndWait(cancel, done, 10*time.Second); err != nil {
			return nil, err
		}
		return nil, ctx.Err()
	}
}

func stopRunner(value *running) error {
	if value == nil {
		return nil
	}
	return cancelAndWait(value.cancel, value.done, 10*time.Second)
}

func cancelAndWait(cancel context.CancelFunc, done <-chan error, timeout time.Duration) error {
	cancel()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return errRunnerDidNotStop
	}
}

func reload(ctx context.Context, path string, active *running, interval time.Duration, once bool, logEvent func(velvetruntime.Event), setStatus func(func(*daemonStatus))) (*running, error) {
	candidate, err := loadDesired(path)
	if err != nil {
		setStatus(func(value *daemonStatus) { value.LastReloadError = err.Error() })
		return active, err
	}
	return reloadCandidate(candidate, active,
		func(desired *reconcile.DesiredState) (*running, error) {
			return startRunner(ctx, desired, interval, once, logEvent, active.runner)
		},
		stopRunner, setStatus)
}

// reloadCandidate performs the generation transaction after configuration loading.
func reloadCandidate(candidate *reconcile.DesiredState, active *running, start func(*reconcile.DesiredState) (*running, error), stop func(*running) error, setStatus func(func(*daemonStatus))) (*running, error) {
	if candidate.UUID != active.desired.UUID {
		err := errors.New("node.uid.uuid cannot change during reload")
		setStatus(func(value *daemonStatus) { value.LastReloadError = err.Error() })
		return active, err
	}
	if reflect.DeepEqual(candidate, active.desired) {
		setStatus(func(value *daemonStatus) { value.LastReloadError = "" })
		return active, nil
	}
	setStatus(func(value *daemonStatus) { value.Ready = false })
	if err := stop(active); err != nil {
		setStatus(func(value *daemonStatus) { value.LastReloadError = err.Error() })
		return nil, err
	}
	next, startErr := start(candidate)
	if startErr != nil {
		if errors.Is(startErr, errRunnerDidNotStop) {
			return nil, fmt.Errorf("candidate failed without stopping cleanly: %w", startErr)
		}
		rollback, rollbackErr := start(active.desired)
		if rollbackErr != nil {
			return nil, fmt.Errorf("candidate failed: %v; rollback failed: %w", startErr, rollbackErr)
		}
		setStatus(func(value *daemonStatus) {
			value.Ready = true
			value.LastReloadError = startErr.Error()
		})
		return rollback, startErr
	}
	setStatus(func(value *daemonStatus) {
		value.Ready = true
		value.ConfigGeneration++
		value.LastReloadError = ""
	})
	return next, nil
}

func acquireSingleton() (*os.File, error) {
	info, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return nil, fmt.Errorf("identify network namespace: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("identify network namespace inode")
	}
	if err := os.MkdirAll("/run/velvet", 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join("/run/velvet", fmt.Sprintf("velvetd-netns-%d.lock", stat.Ino))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errNamespaceOwned
		}
		return nil, err
	}
	return file, nil
}

func version() string {
	if releaseVersion != "" {
		return releaseVersion
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "(devel)"
}
