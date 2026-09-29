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
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
)

// Match the generated daemon budget; forced stop leaves one second of margin.
const daemonShutdownTimeout = 5 * time.Second

type Event struct {
	Status string
	Error  string
}

type Manager struct {
	plan      *reconcile.BabelPlan
	updates   chan linkUpdate
	log       func(Event)
	mu        sync.Mutex
	latest    map[string][]netip.Prefix
	withdrawn map[string]bool
	status    Status
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
	return &Manager{plan: plan, updates: make(chan linkUpdate, len(plan.Interfaces)+1), log: log, latest: make(map[string][]netip.Prefix), withdrawn: make(map[string]bool), status: Status{State: "starting"}}
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

// SetLinkState admits a materialized Link to managed routing and updates its
// ordinary origins. Active link-local-only Links must remain in latest even
// with no routable prefixes. Tentative Dynamic Links are never admitted.
func (m *Manager) SetLinkState(interfaceName string, active bool, prefixes []netip.Prefix) {
	clean := normalizePrefixes(prefixes)
	m.mu.Lock()
	previous, existed := m.latest[interfaceName]
	if active == existed && (!active || prefixesEqual(previous, clean)) {
		m.mu.Unlock()
		return
	}
	if active {
		m.latest[interfaceName] = clean
		delete(m.withdrawn, interfaceName)
	} else {
		delete(m.latest, interfaceName)
		if slices.Contains(m.plan.Interfaces, interfaceName) {
			m.withdrawn[interfaceName] = true
		}
	}
	m.mu.Unlock()
	select {
	case m.updates <- linkUpdate{interfaceName: interfaceName, prefixes: clean}:
	default:
		// Run renders the latest complete snapshot, so updates may coalesce.
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
	defer func() {
		m.setStatus(Status{State: "stopped"})
		m.emit(Event{Status: "stopped"})
	}()
	backoff := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		err := m.runOnce(ctx)
		if ctx.Err() != nil {
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

// Run owns the configuration connection, never the daemon's lifetime.
func (m *Manager) runOnce(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	first := true
	lastPID := 0
	for {
		previous, _ := os.ReadFile(m.plan.ConfigPath)
		data, digest, err := m.prepare()
		if err != nil {
			return err
		}
		executable, err := resolveExecutable(m.plan.Executable)
		if err != nil {
			return err
		}
		candidate, err := os.CreateTemp(filepath.Dir(m.plan.ConfigPath), ".babel-check-*")
		if err != nil {
			return err
		}
		if _, err = candidate.Write(data); err != nil {
			candidate.Close()
			os.Remove(candidate.Name())
			return err
		}
		if err = candidate.Close(); err != nil {
			os.Remove(candidate.Name())
			return err
		}
		if output, err := exec.CommandContext(ctx, executable, "check", "--config", candidate.Name()).CombinedOutput(); err != nil {
			os.Remove(candidate.Name())
			return fmt.Errorf("babel-rs rejected generated config: %v: %s", err, bytes.TrimSpace(output))
		}
		os.Remove(candidate.Name())
		if err := writeAtomic(m.plan.ConfigPath, data, 0600); err != nil {
			return err
		}
		if err := ensureService(ctx, m.plan); err != nil {
			return err
		}
		var status daemonStatus
		readyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		for {
			err = controlRequest(readyCtx, m.plan.ControlPath, "status", &status)
			if err == nil && status.Ready {
				break
			}
			if !waitContext(readyCtx, 100*time.Millisecond) {
				cancel()
				return fmt.Errorf("babel-rs control unavailable: %w", readyCtx.Err())
			}
		}
		cancel()
		changed := status.ActiveConfigSHA256 != digest
		if changed {
			var result reloadResult
			if err := controlRequest(ctx, m.plan.ControlPath, "reload", &result); err != nil {
				if len(previous) > 0 {
					_ = writeAtomic(m.plan.ConfigPath, previous, 0600)
				}
				return fmt.Errorf("babel-rs reload rejected: %w", err)
			}
			if result.ActiveConfigSHA256 != digest {
				return fmt.Errorf("babel-rs activated config digest %s, want %s", result.ActiveConfigSHA256, digest)
			}
		}
		pid := servicePID(m.plan)
		m.refreshStatus(ctx, pid)
		if first || pid != lastPID {
			m.emit(Event{Status: "running"})
			first = false
		} else if changed {
			m.emit(Event{Status: "reloaded"})
		}
		lastPID = pid
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.updates:
		case <-ticker.C:
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
	plan := *m.plan
	plan.Interfaces = nil
	for _, name := range m.plan.Interfaces {
		if !m.withdrawn[name] {
			plan.Interfaces = append(plan.Interfaces, name)
		}
	}
	m.mu.Unlock()
	data := Render(&plan, linkOrigins)
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	return data, digest, nil
}

func Render(plan *reconcile.BabelPlan, linkOrigins map[string][]netip.Prefix) []byte {
	interfaces := append([]string(nil), plan.Interfaces...)
	var admitted []string
	for name := range linkOrigins {
		matched := false
		for _, pattern := range interfaces {
			if ok, _ := path.Match(pattern, name); ok {
				matched = true
				break
			}
		}
		if !matched {
			admitted = append(admitted, name)
		}
	}
	sort.Strings(admitted)
	interfaces = append(interfaces, admitted...)
	if len(interfaces) == 0 {
		// The pinned Babel config requires a nonempty selector. This literal
		// exceeds Linux's 15-byte interface-name limit, so it cannot admit a device.
		interfaces = []string{"velvet-no-active-links"}
	}

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
	fmt.Fprintf(&output, "shutdown_timeout_ms = %d\n\n", daemonShutdownTimeout.Milliseconds())
	output.WriteString("[[interfaces]]\nmatch = [")
	for i, name := range interfaces {
		if i != 0 {
			output.WriteString(", ")
		}
		output.WriteString(strconv.Quote(name))
	}
	output.WriteString("]\nlink_type = \"wired\"\n\n")
	output.WriteString("[interfaces.metric]\ntype = \"wired\"\nnominal_cost = 96\n\n")
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
