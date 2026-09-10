package runtime

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// reservePolicyRevision is serialized across processes, writes before publishing,
// and fsyncs both the replacement and directory. A malformed existing counter
// is an error, never an invitation to reset the revision under the same UUID.
func reservePolicyRevision(path string) (uint64, error) {
	dir := filepath.Dir(path)
	if err := makePolicyDirectory(dir); err != nil {
		return 0, err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return 0, err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return 0, err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	var revision uint64
	f, err := os.Open(path)
	if err == nil {
		var raw [9]byte
		n, readErr := io.ReadFull(f, raw[:])
		f.Close()
		if n != 8 || !errors.Is(readErr, io.ErrUnexpectedEOF) {
			return 0, errors.New("invalid persisted Dynamic-Link policy revision")
		}
		revision = binary.BigEndian.Uint64(raw[:8])
		if revision == 0 {
			return 0, errors.New("zero persisted Dynamic-Link policy revision")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	if revision == ^uint64(0) {
		return 0, errors.New("Dynamic-Link policy revision exhausted")
	}
	revision++
	tmp, err := os.CreateTemp(dir, ".policy-revision-*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], revision)
	if _, err := tmp.Write(raw[:]); err != nil {
		return 0, err
	}
	if err := tmp.Sync(); err != nil {
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return 0, err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return 0, err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return 0, fmt.Errorf("sync policy directory: %w", err)
	}
	return revision, nil
}

// fsyncing the counter directory does not persist its entry in a newly created
// parent. Persist each new directory entry too before publishing the first revision.
func makePolicyDirectory(dir string) error {
	var missing []string
	for current := dir; ; current = filepath.Dir(current) {
		if _, err := os.Stat(current); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		missing = append(missing, current)
		if filepath.Dir(current) == current {
			return errors.New("policy state has no existing parent")
		}
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	for i := len(missing) - 1; i >= 0; i-- {
		parent, err := os.Open(filepath.Dir(missing[i]))
		if err != nil {
			return err
		}
		err = parent.Sync()
		parent.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
