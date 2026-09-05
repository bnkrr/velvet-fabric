package babel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
)

type Event struct {
	Status string
	Error  string
}

type Manager struct {
	plan    *reconcile.BabelPlan
	updates chan linkUpdate
	log     func(Event)
	mu      sync.Mutex
	latest  map[string][]netip.Prefix
	status  Status
}

type Status struct {
	State              string `json:"state"`
	PID                int    `json:"pid,omitempty"`
	Version            string `json:"version,omitempty"`
	ConfigGeneration   uint64 `json:"config_generation,omitempty"`
	ActiveConfigSHA256 string `json:"active_config_sha256,omitempty"`
	AttachedInterfaces int    `json:"attached_interfaces,omitempty"`
	Neighbors          int    `json:"neighbors,omitempty"`
	SelectedRoutes     int    `json:"selected_routes,omitempty"`
	LastError          string `json:"last_error,omitempty"`
}

type linkUpdate struct {
	interfaceName string
	prefixes      []netip.Prefix
}

func New(plan *reconcile.BabelPlan, log func(Event)) *Manager {
	return &Manager{plan: plan, updates: make(chan linkUpdate, len(plan.Interfaces)+1), log: log, latest: make(map[string][]netip.Prefix), status: Status{State: "starting"}}
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

// SetLinkPrefixes updates the ordinary origins for one materialized Link. It
// is safe before or during Run; only routable negotiated prefixes are passed.
func (m *Manager) SetLinkPrefixes(interfaceName string, prefixes []netip.Prefix) {
	clean := normalizePrefixes(prefixes)
	m.mu.Lock()
	previous, existed := m.latest[interfaceName]
	if (!existed && len(clean) == 0) || prefixesEqual(previous, clean) {
		m.mu.Unlock()
		return
	}
	if len(clean) == 0 {
		delete(m.latest, interfaceName)
	} else {
		m.latest[interfaceName] = clean
	}
	m.mu.Unlock()
	select {
	case m.updates <- linkUpdate{interfaceName: interfaceName, prefixes: clean}:
	default:
		// Run always takes a fresh snapshot from latest before rendering, so a
		// full channel may coalesce redundant updates without losing state.
	}
}

func prefixesEqual(left, right []netip.Prefix) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func (m *Manager) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		err := m.runOnce(ctx)
		if ctx.Err() != nil {
			m.setStatus(Status{State: "stopped"})
			m.emit(Event{Status: "stopped"})
			return
		}
		m.setStatus(Status{State: "retrying", LastError: err.Error()})
		m.emit(Event{Status: "retrying", Error: err.Error()})
		if time.Since(started) >= time.Minute {
			backoff = time.Second
		}
		delay := backoff + time.Duration(rand.Int64N(int64(backoff/4+1)))
		if !waitContext(ctx, delay) {
			return
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (m *Manager) runOnce(ctx context.Context) error {
	data, digest, err := m.prepare()
	if err != nil {
		return err
	}
	path, err := resolveExecutable(m.plan.Executable)
	if err != nil {
		return err
	}
	if output, err := exec.CommandContext(ctx, path, "check", "--config", m.plan.ConfigPath).CombinedOutput(); err != nil {
		return fmt.Errorf("babel-rs config check: %v: %s", err, bytes.TrimSpace(output))
	}
	command := exec.Command(path, "run", "--config", m.plan.ConfigPath, "--control-socket", m.plan.ControlPath)
	command.Stdout = os.Stderr
	command.Stderr = os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	if err := command.Start(); err != nil {
		return fmt.Errorf("start babel-rs: %w", err)
	}
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	exited, err := m.waitReady(ctx, waited, digest, command.Process.Pid)
	if err != nil {
		if !exited {
			stop(m.plan.ControlPath, command, waited)
		}
		return err
	}
	m.emit(Event{Status: "running"})
	activeData := data
	statusTicker := time.NewTicker(5 * time.Second)
	defer statusTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			stop(m.plan.ControlPath, command, waited)
			return ctx.Err()
		case <-m.updates:
			candidate, candidateDigest, prepareErr := m.prepare()
			if prepareErr != nil {
				m.recordError(prepareErr)
				continue
			}
			if output, checkErr := exec.CommandContext(ctx, path, "check", "--config", m.plan.ConfigPath).CombinedOutput(); checkErr != nil {
				_ = writeAtomic(m.plan.ConfigPath, activeData, 0o600)
				m.recordError(fmt.Errorf("babel-rs rejected generated config: %v: %s", checkErr, bytes.TrimSpace(output)))
				continue
			}
			var result reloadResult
			if reloadErr := controlRequest(ctx, m.plan.ControlPath, "reload", &result); reloadErr != nil {
				var alive daemonStatus
				if controlRequest(ctx, m.plan.ControlPath, "status", &alive) == nil {
					_ = writeAtomic(m.plan.ConfigPath, activeData, 0o600)
					m.recordError(fmt.Errorf("babel-rs reload rejected: %w", reloadErr))
					continue
				}
				return fmt.Errorf("babel-rs control reload failed: %w", reloadErr)
			}
			if result.ActiveConfigSHA256 != candidateDigest {
				return fmt.Errorf("babel-rs activated config digest %s, want %s", result.ActiveConfigSHA256, candidateDigest)
			}
			activeData = candidate
			m.refreshStatus(ctx, command.Process.Pid)
			m.emit(Event{Status: "reloaded"})
		case <-statusTicker.C:
			m.refreshStatus(ctx, command.Process.Pid)
		case waitErr := <-waited:
			if waitErr == nil {
				return fmt.Errorf("babel-rs exited unexpectedly with status 0")
			}
			return fmt.Errorf("babel-rs exited: %w", waitErr)
		}
	}
}

func (m *Manager) waitReady(ctx context.Context, waited <-chan error, digest string, pid int) (bool, error) {
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case err := <-waited:
			return true, fmt.Errorf("babel-rs exited before readiness: %v", err)
		case <-deadline.C:
			return false, fmt.Errorf("babel-rs did not become ready within 10s")
		case <-ticker.C:
			var status daemonStatus
			if controlRequest(ctx, m.plan.ControlPath, "status", &status) == nil && status.Ready && status.ActiveConfigSHA256 == digest {
				m.setStatus(Status{State: "running", PID: pid, Version: status.Version, ConfigGeneration: status.ConfigGeneration, ActiveConfigSHA256: status.ActiveConfigSHA256, AttachedInterfaces: status.AttachedInterfaces, Neighbors: status.Neighbors, SelectedRoutes: status.SelectedRoutes})
				return false, nil
			}
		}
	}
}

func (m *Manager) refreshStatus(ctx context.Context, pid int) {
	var status daemonStatus
	if err := controlRequest(ctx, m.plan.ControlPath, "status", &status); err != nil {
		m.recordError(err)
		return
	}
	m.setStatus(Status{State: "running", PID: pid, Version: status.Version, ConfigGeneration: status.ConfigGeneration, ActiveConfigSHA256: status.ActiveConfigSHA256, AttachedInterfaces: status.AttachedInterfaces, Neighbors: status.Neighbors, SelectedRoutes: status.SelectedRoutes})
}

func (m *Manager) setStatus(status Status) {
	m.mu.Lock()
	m.status = status
	m.mu.Unlock()
}

func (m *Manager) recordError(err error) {
	m.mu.Lock()
	m.status.LastError = err.Error()
	m.mu.Unlock()
	m.emit(Event{Status: "degraded", Error: err.Error()})
}

func (m *Manager) prepare() ([]byte, string, error) {
	for _, path := range []string{filepath.Dir(m.plan.ConfigPath), filepath.Dir(m.plan.StatePath)} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, "", fmt.Errorf("create babel-rs directory %s: %w", path, err)
		}
	}
	m.mu.Lock()
	linkOrigins := make(map[string][]netip.Prefix, len(m.latest))
	for name, prefixes := range m.latest {
		linkOrigins[name] = append([]netip.Prefix(nil), prefixes...)
	}
	m.mu.Unlock()
	data := Render(m.plan, linkOrigins)
	if err := writeAtomic(m.plan.ConfigPath, data, 0o600); err != nil {
		return nil, "", err
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	return data, digest, nil
}

func Render(plan *reconcile.BabelPlan, linkOrigins map[string][]netip.Prefix) []byte {
	origins := append([]reconcile.BabelOrigin(nil), plan.Origins...)
	for _, prefixes := range linkOrigins {
		for _, prefix := range normalizePrefixes(prefixes) {
			origins = append(origins, reconcile.BabelOrigin{Destination: prefix.Masked()})
		}
	}
	origins = uniqueOrigins(origins)
	sort.Slice(origins, func(i, j int) bool {
		left := origins[i].Destination.String() + "|" + origins[i].Source.String()
		right := origins[j].Destination.String() + "|" + origins[j].Source.String()
		return left < right
	})

	var output bytes.Buffer
	fmt.Fprintf(&output, "state_file = %s\n", strconv.Quote(plan.StatePath))
	output.WriteString("interfaces = [")
	for i, name := range plan.Interfaces {
		if i != 0 {
			output.WriteString(", ")
		}
		output.WriteString(strconv.Quote(name))
	}
	output.WriteString("]\n\n")
	for _, origin := range origins {
		output.WriteString("[[origins]]\n")
		fmt.Fprintf(&output, "destination = %s\n", strconv.Quote(origin.Destination.String()))
		if origin.Source.IsValid() {
			fmt.Fprintf(&output, "source = %s\n", strconv.Quote(origin.Source.String()))
		}
		fmt.Fprintf(&output, "metric = %d\n\n", origin.Metric)
	}
	output.WriteString("[export]\n")
	fmt.Fprintf(&output, "protocol = %d\n", plan.Protocol)
	fmt.Fprintf(&output, "device_only = %t\n", plan.DeviceOnly)
	fmt.Fprintf(&output, "manage_rules = %t\n\n", plan.ManageRules)
	for _, view := range plan.Views {
		output.WriteString("[[export.views]]\n")
		fmt.Fprintf(&output, "table = %d\n", view.TableID)
		if view.Source.IsValid() {
			fmt.Fprintf(&output, "source = %s\n", strconv.Quote(view.Source.String()))
			fmt.Fprintf(&output, "rule_priority = %d\n", view.RulePriority)
		}
		output.WriteByte('\n')
	}
	return output.Bytes()
}

func normalizePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	seen := make(map[netip.Prefix]struct{})
	var result []netip.Prefix
	for _, prefix := range prefixes {
		if !prefix.IsValid() || prefix.Addr().IsLinkLocalUnicast() {
			continue
		}
		prefix = prefix.Masked()
		if _, exists := seen[prefix]; exists {
			continue
		}
		seen[prefix] = struct{}{}
		result = append(result, prefix)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].String() < result[j].String() })
	return result
}

func uniqueOrigins(values []reconcile.BabelOrigin) []reconcile.BabelOrigin {
	type key struct{ destination, source netip.Prefix }
	seen := make(map[key]struct{})
	var result []reconcile.BabelOrigin
	for _, value := range values {
		value.Destination = value.Destination.Masked()
		if value.Source.IsValid() {
			value.Source = value.Source.Masked()
		}
		item := key{value.Destination, value.Source}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, value)
	}
	return result
}

func resolveExecutable(value string) (string, error) {
	if filepath.IsAbs(value) {
		info, err := os.Stat(value)
		if err != nil {
			return "", fmt.Errorf("stat babel.executable: %w", err)
		}
		if info.IsDir() || info.Mode().Perm()&0o111 == 0 {
			return "", fmt.Errorf("babel.executable %q is not executable", value)
		}
		return value, nil
	}
	path, err := exec.LookPath(value)
	if err != nil {
		return "", fmt.Errorf("find babel-rs in PATH: %w", err)
	}
	return path, nil
}

func stop(controlPath string, command *exec.Cmd, waited <-chan error) {
	if command.Process == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	_ = controlRequest(ctx, controlPath, "shutdown", nil)
	cancel()
	select {
	case <-waited:
		return
	case <-time.After(3 * time.Second):
	}
	_ = command.Process.Signal(syscall.SIGTERM)
	select {
	case <-waited:
		return
	case <-time.After(3 * time.Second):
		_ = command.Process.Kill()
		select {
		case <-waited:
		case <-time.After(time.Second):
		}
	}
}

func waitContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func writeAtomic(path string, data []byte, mode os.FileMode) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".babel-rs-config-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err = tmp.Chmod(mode); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmpName, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (m *Manager) emit(event Event) {
	if m.log != nil {
		m.log(event)
	}
}
