// Package session persists long-running SQLi scan state so scans can be
// resumed across restarts. A session is identified per-target (or by a
// user-supplied name) and stored under ~/.vexor/sessions/.
package session

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ErrCorrupt is returned when a session file cannot be decoded. The caller
// should back it up and start a fresh session.
var ErrCorrupt = errors.New("session file corrupt")

// storage holds the low-level file system primitives: atomic JSON writes,
// optional gzip compression, read with corruption recovery, and locking.
type storage struct {
	dir string
}

// dir returns the session directory, creating it if needed.
func (s *storage) dirPath() (string, error) {
	if s.dir == "" {
		return "", errors.New("session storage dir not set")
	}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return "", fmt.Errorf("create session dir: %w", err)
	}
	return s.dir, nil
}

// filePath resolves the path to a session file given its key (name without
// extension).
func (s *storage) filePath(key string) (string, error) {
	dir, err := s.dirPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, key+".json"), nil
}

// writeJSON serialises v to JSON, optionally gzip-compresses it, then writes
// it atomically (temp file + rename) to avoid partial writes on crash.
func (s *storage) writeJSON(key string, v any, compress bool) error {
	path, err := s.filePath(key)
	if err != nil {
		return err
	}

	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	if compress {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(data); err != nil {
			return fmt.Errorf("gzip session: %w", err)
		}
		if err := gz.Close(); err != nil {
			return fmt.Errorf("close gzip: %w", err)
		}
		data = buf.Bytes()
		// Mark compressed with a suffix so read can route correctly.
		path = path + ".gz"
	}

	return s.atomicWrite(path, data)
}

// atomicWrite writes data to path via a temp file in the same directory and
// an atomic rename.
func (s *storage) atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".session-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp session file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp session: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp session: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp session: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename session into place: %w", err)
	}
	return nil
}

// readJSON loads a session into v. It transparently reads gzip-compressed
// files (key.json.gz) and plain files, failing with ErrCorrupt on decode
// errors.
func (s *storage) readJSON(key string, v any) error {
	var raw []byte
	var err error

	// Prefer compressed if present, else plain.
	path, err := s.filePath(key)
	if err != nil {
		return err
	}
	gzPath := path + ".gz"

	if fileExists(gzPath) {
		raw, err = readGzip(gzPath)
		if err != nil {
			return err
		}
	} else if fileExists(path) {
		raw, err = os.ReadFile(path)
		if err != nil {
			return err
		}
	} else {
		return os.ErrNotExist
	}

	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	return nil
}

func readGzip(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("open gzip: %w", err)
	}
	defer gz.Close()
	data, err := io.ReadAll(gz)
	if err != nil {
		return nil, fmt.Errorf("read gzip: %w", err)
	}
	return data, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// delete removes a session file (both plain and gzipped variants).
func (s *storage) delete(key string) error {
	path, err := s.filePath(key)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(path + ".gz"); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// list returns the session keys (without extension) currently stored.
func (s *storage) list() ([]string, error) {
	dir, err := s.dirPath()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var keys []string
	seen := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		key := ""
		nameLower := filepath.Ext(name)
		switch {
		case nameLower == ".json":
			key = name[:len(name)-len(".json")]
		case nameLower == ".gz" && strings.HasSuffix(name, ".json.gz"):
			key = name[:len(name)-len(".json.gz")]
		}
		if key != "" && !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}
	return keys, nil
}
