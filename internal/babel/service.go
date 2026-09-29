package babel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"golang.org/x/sys/unix"
)

// A persistent launch description lets systemd start Babel without Fabric.
type serviceRecord struct {
	Plan      reconcile.BabelPlan
	PID       int
	Start     string
	Namespace string
}

func servicePath(plan *reconcile.BabelPlan) string {
	return filepath.Join(filepath.Dir(plan.StatePath), "babel-service.json")
}

func readService(path string) (serviceRecord, error) {
	var record serviceRecord
	data, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(data, &record)
	}
	return record, err
}

func processStart(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ""
	}
	// comm can contain spaces and parentheses. starttime is field 22.
	tail := strings.LastIndexByte(string(data), ')')
	if tail < 0 {
		return ""
	}
	fields := strings.Fields(string(data[tail+1:]))
	if len(fields) < 20 || (fields[0] == "Z" || fields[0] == "X" || fields[0] == "x") {
		return ""
	}
	return fields[19]
}

func currentNamespace() string { value, _ := os.Readlink("/proc/self/ns/net"); return value }
func (r serviceRecord) alive() bool {
	return r.PID > 0 && r.Start != "" && r.Namespace == currentNamespace() && processStart(r.PID) == r.Start
}

func servicePID(plan *reconcile.BabelPlan) int {
	record, err := readService(servicePath(plan))
	if err == nil && record.alive() {
		return record.PID
	}
	return 0
}

func saveService(record serviceRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return writeAtomic(servicePath(&record.Plan), data, 0600)
}

// Socket credentials recover identity even if Fabric crashed between spawn and
// persisting the child PID. Never infer identity from a recycled PID alone.
func socketProcess(path string) int {
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return 0
	}
	defer conn.Close()
	raw, err := conn.(*net.UnixConn).SyscallConn()
	if err != nil {
		return 0
	}
	var pid int
	_ = raw.Control(func(fd uintptr) {
		if cred, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); e == nil {
			pid = int(cred.Pid)
		}
	})
	namespace, _ := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
	if namespace != currentNamespace() {
		return 0
	}
	return pid
}
func ensureService(ctx context.Context, plan *reconcile.BabelPlan) error {
	if err := os.MkdirAll(filepath.Dir(plan.ControlPath), 0700); err != nil {
		return err
	}
	old, readErr := readService(servicePath(plan))
	if readErr == nil && old.alive() && (old.Plan.ServiceName != plan.ServiceName || old.Plan.Executable != plan.Executable || old.Plan.ControlPath != plan.ControlPath) {
		if err := StopInstance(ctx, filepath.Dir(plan.StatePath)); err != nil {
			return err
		}
		old = serviceRecord{}
	}
	record := serviceRecord{Plan: *plan, Namespace: currentNamespace()}
	if readErr == nil && old.alive() {
		record.PID, record.Start = old.PID, old.Start
	} else if pid := socketProcess(plan.ControlPath); pid > 0 {
		record.PID, record.Start = pid, processStart(pid)
	}
	if err := saveService(record); err != nil {
		return err
	}
	if plan.ServiceName != "" {
		if record.alive() && old.Plan.ServiceName == plan.ServiceName {
			return nil
		}
		// The unit has no PartOf/BindsTo relationship with Fabric.
		startCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		out, err := exec.CommandContext(startCtx, "systemctl", "enable", "--now", plan.ServiceName).CombinedOutput()
		if err != nil {
			return fmt.Errorf("start independent Babel service: %w: %s", err, out)
		}
		return nil
	}
	// Standalone/netns use: attach to the existing daemon or launch a detached one.
	// Independent automatic restart is supplied by the packaged systemd unit.
	if record.alive() {
		return nil
	}
	var status daemonStatus
	if controlRequest(ctx, plan.ControlPath, "status", &status) == nil {
		return nil
	}
	log, err := os.OpenFile(filepath.Join(filepath.Dir(plan.StatePath), "babel-rs.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	executable, err := resolveExecutable(plan.Executable)
	if err != nil {
		return err
	}
	command := exec.Command(executable, "run", "--config", plan.ConfigPath, "--control-socket", plan.ControlPath)
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		return err
	}
	record.PID, record.Start = command.Process.Pid, processStart(command.Process.Pid)
	go func() { _ = command.Wait() }()
	return saveService(record)
}

// ExecService replaces the unit's launcher, so systemd supervises Babel itself.
func ExecService(path string) error {
	record, err := readService(path)
	if err != nil {
		return err
	}
	executable, err := resolveExecutable(record.Plan.Executable)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(record.Plan.ControlPath), 0700); err != nil {
		return err
	}
	record.PID, record.Start, record.Namespace = os.Getpid(), processStart(os.Getpid()), currentNamespace()
	if err := saveService(record); err != nil {
		return err
	}
	return syscall.Exec(executable, []string{executable, "run", "--config", record.Plan.ConfigPath, "--control-socket", record.Plan.ControlPath}, os.Environ())
}

// StopInstance is only for explicit disable or whole-instance retirement.
func StopInstance(ctx context.Context, stateDirectory string) error {
	path := filepath.Join(stateDirectory, "babel-service.json")
	record, err := readService(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if record.Namespace != currentNamespace() && record.Start != "" && processStart(record.PID) == record.Start {
		return errors.New("Babel service belongs to another network namespace")
	}
	if record.Plan.ServiceName != "" {
		output, err := exec.CommandContext(ctx, "systemctl", "disable", "--now", record.Plan.ServiceName).CombinedOutput()
		if err != nil {
			return fmt.Errorf("stop Babel service: %w: %s", err, output)
		}
	} else {
		if !record.alive() && record.Namespace == currentNamespace() {
			if pid := socketProcess(record.Plan.ControlPath); pid > 0 {
				record.PID, record.Start = pid, processStart(pid)
			}
		}
		// Pin the process before signaling, and verify its saved generation.
		fd, openErr := unix.PidfdOpen(record.PID, 0)
		if openErr == nil {
			defer unix.Close(fd)
			if record.alive() {
				if err := controlRequest(ctx, record.Plan.ControlPath, "shutdown", nil); err != nil {
					_ = unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0)
				}
				poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
				n, err := unix.Poll(poll, 7000)
				if err != nil {
					return err
				}
				if n == 0 {
					_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
					n, err = unix.Poll(poll, 2000)
				}
				if err != nil || n == 0 {
					return fmt.Errorf("Babel process %s did not stop", strconv.Itoa(record.PID))
				}
			}
		} else if record.alive() {
			return openErr
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
