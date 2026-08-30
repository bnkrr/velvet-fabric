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
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/velvet-fabric/velvet-fabric/internal/control"
	linuxbackend "github.com/velvet-fabric/velvet-fabric/internal/linux"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
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

func main() {
	configPath := flag.String("config", "", "path to a NodeSpec JSON file")
	controlPath := flag.String("control-socket", "", "Unix control socket (default: per-node runtime directory)")
	once := flag.Bool("once", false, "exit after every configured adjacent Link is established")
	interval := flag.Duration("reconcile-interval", 15*time.Second, "kernel reconciliation interval")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
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
	nodeSpec, desired, err := loadDesired(*configPath)
	if err != nil {
		log.Fatalf("velvetd: %v", err)
	}
	_ = nodeSpec
	lock, err := acquireSingleton()
	if err != nil {
		log.Fatalf("velvetd: %v", err)
	}
	defer lock.Close()
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
			if value.Runtime.EstablishedLinks != value.Runtime.ConfiguredLinks || (value.Runtime.Babel != nil && (value.Runtime.Babel.State != "running" || value.Runtime.Babel.AttachedInterfaces != value.Runtime.ConfiguredLinks)) {
				value.Ready = false
			}
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

	for {
		select {
		case <-rootCtx.Done():
			stopRunner(active)
			return
		case err := <-active.done:
			if *once && err == nil {
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
			return
		case <-hangup:
			active, err = reload(rootCtx, *configPath, active, *interval, *once, logEvent, setStatus)
			if active == nil {
				log.Fatalf("velvetd: configuration reload and rollback failed: %v", err)
			}
			activePointer.Store(active)
			if err != nil {
				log.Printf("velvetd: configuration reload rejected: %v", err)
			}
		case request := <-reloads:
			active, err = reload(rootCtx, *configPath, active, *interval, *once, logEvent, setStatus)
			if active == nil {
				log.Fatalf("velvetd: configuration reload and rollback failed: %v", err)
			}
			activePointer.Store(active)
			request.reply <- err
		}
	}
}

func loadDesired(path string) (*spec.NodeSpec, *reconcile.DesiredState, error) {
	nodeSpec, err := spec.Load(path)
	if err != nil {
		return nil, nil, err
	}
	desired, err := reconcile.BuildDesiredState(nodeSpec)
	return nodeSpec, desired, err
}

func startRunner(ctx context.Context, desired *reconcile.DesiredState, interval time.Duration, once bool, logEvent func(velvetruntime.Event)) (*running, error) {
	runCtx, cancel := context.WithCancel(ctx)
	ready := make(chan error, 1)
	done := make(chan error, 1)
	runner := &velvetruntime.Runner{Desired: desired, Reconciler: reconcile.New(linuxbackend.New()), Interval: interval, Log: logEvent, Ready: ready}
	go func() { done <- runner.Run(runCtx, once) }()
	select {
	case err := <-ready:
		if err != nil {
			cancel()
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
		cancel()
		return nil, errors.New("runtime did not become ready within 30s")
	case <-ctx.Done():
		cancel()
		return nil, ctx.Err()
	}
}

func stopRunner(value *running) {
	if value == nil {
		return
	}
	value.cancel()
	select {
	case <-value.done:
	case <-time.After(10 * time.Second):
	}
}

func reload(ctx context.Context, path string, active *running, interval time.Duration, once bool, logEvent func(velvetruntime.Event), setStatus func(func(*daemonStatus))) (*running, error) {
	_, candidate, err := loadDesired(path)
	if err != nil {
		setStatus(func(value *daemonStatus) { value.LastReloadError = err.Error() })
		return active, err
	}
	if candidate.UUID != active.desired.UUID {
		err = errors.New("node.uid.uuid cannot change during reload")
		setStatus(func(value *daemonStatus) { value.LastReloadError = err.Error() })
		return active, err
	}
	setStatus(func(value *daemonStatus) { value.Ready = false })
	stopRunner(active)
	next, startErr := startRunner(ctx, candidate, interval, once, logEvent)
	if startErr != nil {
		rollback, rollbackErr := startRunner(ctx, active.desired, interval, once, logEvent)
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
		return nil, errors.New("another velvetd already owns this network namespace")
	}
	return file, nil
}

func version() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "(devel)"
}
