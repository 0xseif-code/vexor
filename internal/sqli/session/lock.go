package session

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// lockHoldTimeout is how long a stale lock file is assumed valid before it is
// considered abandoned by a crashed process and reclaimed.
const lockHoldTimeout = 30 * time.Minute

// ErrLocked is returned when a lock cannot be acquired.
var ErrLocked = errors.New("session is locked by another process")

// lockFile takes an advisory lock by exclusively creating the lock file
// (O_CREATE|O_EXCL is atomic on every OS). It retries up to the deadline,
// reclaiming stale locks left by crashed runs, and returns the open file the
// caller must close.
func lockFile(path string) (*os.File, error) {
	deadline := time.Now().Add(15 * time.Second)

	for {
		lf, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			fmt.Fprintf(lf, "%d\n", os.Getpid())
			return lf, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		// Existing lock: check if stale and reclaimable.
		if info, statErr := os.Stat(path); statErr == nil {
			if time.Since(info.ModTime()) > lockHoldTimeout {
				_ = os.Remove(path)
				continue
			}
		}
		if time.Now().After(deadline) {
			return nil, ErrLocked
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// unlockFile removes the lock file, releasing the advisory lock, and closes
// the handle.
func unlockFile(f *os.File) error {
	if f == nil {
		return nil
	}
	path := f.Name()
	_ = f.Close()
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
