// Package recovery records a service failure episode across process restarts.
// A separate systemd timer executes cleanup while holding the daemon's lock.
package recovery

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"golang.org/x/sys/unix"
)

type State struct {
	Node         string
	Namespace    string
	Tables       []int
	Running      bool
	Retired      bool
	FailureSince time.Time
	HealthySince time.Time
	LastProgress time.Time
	Window       time.Duration
	Stable       time.Duration
}

type Tracker struct {
	Path           string
	Window, Stable time.Duration
}

func New(root, config string, window, stable time.Duration) (*Tracker, error) {
	absolute, err := filepath.Abs(config)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(absolute))
	return &Tracker{filepath.Join(root, "recovery", fmt.Sprintf("%x.json", digest[:16])), window, stable}, nil
}

func namespace() string { value, _ := os.Readlink("/proc/self/ns/net"); return value }

func (t *Tracker) update(fn func(*State) error) error {
	if err := os.MkdirAll(filepath.Dir(t.Path), 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(t.Path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	var state State
	data, err := os.ReadFile(t.Path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		if err := json.Unmarshal(data, &state); err != nil {
			return err
		}
	}
	if err := fn(&state); err != nil {
		return err
	}
	data, err = json.Marshal(state)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(t.Path), ".recovery-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(file.Name(), t.Path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(t.Path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (t *Tracker) Begin(desired *reconcile.DesiredState, now time.Time) error {
	return t.update(func(s *State) error {
		if s.Node != desired.UUID.String() || s.Namespace != namespace() || s.Retired || !s.Running {
			*s = State{FailureSince: now}
		}
		if s.FailureSince.IsZero() {
			s.FailureSince = s.LastProgress
			if s.FailureSince.IsZero() {
				s.FailureSince = now
			}
		}
		s.Node, s.Namespace, s.Running = desired.UUID.String(), namespace(), true
		s.HealthySince, s.LastProgress = time.Time{}, now
		s.Window, s.Stable = t.Window, t.Stable
		tables := map[int]bool{desired.FabricTableID: true}
		for _, table := range s.Tables {
			tables[table] = true
		}
		for _, r := range desired.Routes {
			tables[r.TableID] = true
		}
		for _, r := range desired.Rules {
			tables[r.TableID] = true
		}
		s.Tables = nil
		for table := range tables {
			s.Tables = append(s.Tables, table)
		}
		sort.Ints(s.Tables)
		return nil
	})
}

func (t *Tracker) Progress(now time.Time, healthy bool) error {
	return t.update(func(s *State) error {
		if !s.Running || s.Retired {
			return nil
		}
		if !healthy {
			s.HealthySince = time.Time{}
			return nil
		}
		s.LastProgress = now
		if s.HealthySince.IsZero() {
			s.HealthySince = now
		}
		if now.Sub(s.HealthySince) >= s.Stable {
			s.FailureSince = time.Time{}
		}
		return nil
	})
}

func (t *Tracker) Stop() error {
	return t.update(func(s *State) error {
		s.Running = false
		s.FailureSince, s.HealthySince = time.Time{}, time.Time{}
		return nil
	})
}

func (t *Tracker) Failure(now time.Time) error {
	return t.update(func(s *State) error {
		if s.Node == "" || s.Retired {
			return nil
		}
		if s.FailureSince.IsZero() {
			s.FailureSince = now
		}
		s.Running, s.HealthySince = true, time.Time{}
		return nil
	})
}

// Check must be called with exclusive ownership of the Fabric namespace lock.
func (t *Tracker) Check(now time.Time, retire func(State) error) error {
	return t.update(func(s *State) error {
		if !s.Running || s.Retired || s.Namespace != namespace() {
			return nil
		}
		if s.FailureSince.IsZero() {
			s.FailureSince = s.LastProgress
			if s.FailureSince.IsZero() {
				s.FailureSince = now
			}
		}
		if s.Window <= 0 || now.Sub(s.FailureSince) < s.Window {
			return nil
		}
		if err := retire(*s); err != nil {
			return err
		}
		s.Retired, s.Running = true, false
		return nil
	})
}

func Notify(message string) error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return nil
	}
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer connection.Close()
	_, err = connection.Write([]byte(message))
	return err
}

// UpdateDesired keeps cleanup ownership current without resetting the episode.
func (t *Tracker) UpdateDesired(d *reconcile.DesiredState) error {
	return t.update(func(s *State) error {
		if s.Node != d.UUID.String() {
			return errors.New("recovery identity changed")
		}
		tables := map[int]bool{}
		for _, table := range s.Tables {
			tables[table] = true
		}
		tables[d.FabricTableID] = true
		for _, route := range d.Routes {
			tables[route.TableID] = true
		}
		for _, rule := range d.Rules {
			tables[rule.TableID] = true
		}
		s.Tables = nil
		for table := range tables {
			s.Tables = append(s.Tables, table)
		}
		sort.Ints(s.Tables)
		return nil
	})
}
