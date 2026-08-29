package session

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0xseif-code/vexor/internal/sqli"
)

// DumpMeta describes a table/data dump stored in a session.
type DumpMeta struct {
	Table      string `json:"table"`
	Database   string `json:"database"`
	Rows       int    `json:"rows"`
	Columns    int    `json:"columns"`
	Bytes      int64  `json:"bytes"`
	DumpedAt   string `json:"dumped_at"`
	Hash       string `json:"hash"`
	Compressed bool   `json:"compressed"`
}

// Session is the persisted scan state for one target. EnumerationData holds
// extracted/computed values keyed by semantic name (e.g. "current_db").
type Session struct {
	ID              string                 `json:"id"`
	Target          string                 `json:"target"`
	Name            string                 `json:"name,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
	Detections      []sqli.Detection       `json:"detections"`
	EnumerationData map[string]interface{} `json:"enumeration_data,omitempty"`
	DumpedTables    map[string]DumpMeta    `json:"dumped_tables,omitempty"`
}

// SessionInfo is a lightweight listing entry for a stored session.
type SessionInfo struct {
	Name       string    `json:"name"`
	Target     string    `json:"target"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	Detections int       `json:"detections"`
	Size       int64     `json:"size"`
}

// Manager owns the storage directory and per-session locking.
type Manager struct {
	dir   string
	store *storage
	mu    sync.Mutex
	locks map[string]*sessionLock
}

// NewManager builds a Manager rooted at ~/.vexor/sessions.
func NewManager() (*Manager, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home dir: %w", err)
	}
	dir := filepath.Join(home, ".vexor", "sessions")
	return NewManagerWithDir(dir)
}

// NewManagerWithDir builds a Manager with an explicit session directory.
func NewManagerWithDir(dir string) (*Manager, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create sessions dir: %w", err)
	}
	return &Manager{
		dir:   dir,
		store: &storage{dir: dir},
		locks: make(map[string]*sessionLock),
	}, nil
}

// hashTarget produces a stable, deterministic identifier for a target URL so
// the same target always maps to the same session file.
func (m *Manager) hashTarget(target string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(target))))
	return hex.EncodeToString(sum[:8])
}

// sessionKey resolves the storage key for a target (hashed) or explicit name.
func (m *Manager) sessionKey(target, name string) string {
	if name != "" {
		return sanitizeName(name)
	}
	return m.hashTarget(target)
}

func sanitizeName(name string) string {
	var sb strings.Builder
	for _, r := range name {
		if r == '/' || r == '\\' || r == ':' || r == '*' || r == '?' ||
			r == '"' || r == '<' || r == '>' || r == '|' || r == ' ' || r == '.' {
			sb.WriteByte('_')
			continue
		}
		sb.WriteRune(r)
	}
	out := strings.Trim(sb.String(), "_")
	if out == "" {
		out = "session"
	}
	return out
}

// sessionLock is an advisory lock file holder that prevents two processes
// writing the same session concurrently.
type sessionLock struct {
	f      *os.File
	path   string
	key    string
	reason string
}

// acquire grabs an exclusive advisory lock for a session key. It blocks with
// a timeout. The returned release function frees the lock.
func (m *Manager) acquire(key string) (func(), error) {
	m.mu.Lock()
	if l, ok := m.locks[key]; ok {
		m.mu.Unlock()
		return nil, fmt.Errorf("session %q already locked (reason: %s)", key, l.reason)
	}
	m.mu.Unlock()

	lockPath := filepath.Join(m.dir, key+".lock")
	f, err := lockFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("lock session %q: %w", key, err)
	}

	m.mu.Lock()
	m.locks[key] = &sessionLock{f: f, path: lockPath, key: key, reason: "manual"}
	m.mu.Unlock()

	var once sync.Once
	release := func() {
		once.Do(func() {
			m.mu.Lock()
			if l, ok := m.locks[key]; ok {
				_ = unlockFile(l.f)
				delete(m.locks, key)
			}
			m.mu.Unlock()
		})
	}
	return release, nil
}

// Load loads a session by target URL (auto hash) or by explicit name. It
// returns os.ErrNotExist when no session exists yet.
func (m *Manager) Load(targetURL string) (*Session, error) {
	return m.load(m.sessionKey(targetURL, ""), targetURL)
}

// LoadByName loads a session by its user-given name.
func (m *Manager) LoadByName(name string) (*Session, error) {
	key := m.sessionKey("", name)
	return m.load(key, name)
}

func (m *Manager) load(key, display string) (*Session, error) {
	var s Session
	if err := m.store.readJSON(key, &s); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		if errors.Is(err, ErrCorrupt) {
			// Back up the corrupt file and return a fresh session so the
			// caller can continue without losing the whole run.
			backupErr := m.backupCorrupt(key)
			if backupErr == nil {
				return NewSessionFor(display), nil
			}
			return nil, fmt.Errorf("session corrupt (%v) and backup failed: %w", err, backupErr)
		}
		return nil, err
	}
	return &s, nil
}

// backupCorrupt renames a corrupt session file to a .corrupt-<ts> name.
func (m *Manager) backupCorrupt(key string) error {
	path, err := m.store.filePath(key)
	if err != nil {
		return err
	}
	candidates := []string{path, path + ".gz"}
	var renamed bool
	for _, p := range candidates {
		if fileExistsLocal(p) {
			dst := fmt.Sprintf("%s.corrupt-%d", p, time.Now().UnixNano())
			if err := os.Rename(p, dst); err != nil {
				return err
			}
			renamed = true
		}
	}
	if !renamed {
		return os.ErrNotExist
	}
	return nil
}

func fileExistsLocal(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// NewSessionFor creates and registers a fresh, empty Session for a target.
func NewSessionFor(target string) *Session {
	now := time.Now()
	return &Session{
		ID:        fmt.Sprintf("%d-%d", now.UnixNano(), idCounter.Add(1)),
		Target:    target,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

var idCounter atomic.Int64

// Save persists the session atomically and gzip-compressed. Credentials are
// never stored, only detection/enumeration/dump data.
func (m *Manager) Save(s *Session) error {
	if s == nil {
		return errors.New("nil session")
	}
	s.UpdatedAt = time.Now()
	key := m.sessionKey(s.Target, s.Name)
	release, err := m.acquire(key)
	if err != nil {
		// If we cannot acquire the lock (e.g. already locked in-process),
		// still attempt the write; concurrent process safety is best-effort.
		_ = err
	} else {
		defer release()
	}
	return m.store.writeJSON(key, s, true)
}

// Flush removes the session for a target URL.
func (m *Manager) Flush(targetURL string) error {
	key := m.sessionKey(targetURL, "")
	return m.store.delete(key)
}

// FlushByName removes a named session.
func (m *Manager) FlushByName(name string) error {
	key := m.sessionKey("", name)
	return m.store.delete(key)
}

// List returns metadata for every stored session, sorted by most recently
// updated first.
func (m *Manager) List() ([]SessionInfo, error) {
	keys, err := m.store.list()
	if err != nil {
		return nil, err
	}
	infos := make([]SessionInfo, 0, len(keys))
	for _, key := range keys {
		var s Session
		if err := m.store.readJSON(key, &s); err != nil {
			continue // skip corrupt/unreadable entries silently
		}
		infos = append(infos, SessionInfo{
			Name:       s.Name,
			Target:     s.Target,
			CreatedAt:  s.CreatedAt,
			UpdatedAt:  s.UpdatedAt,
			Detections: len(s.Detections),
			Size:       estimateSize(&s),
		})
	}
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].UpdatedAt.After(infos[j].UpdatedAt)
	})
	return infos, nil
}

func estimateSize(s *Session) int64 {
	var n int64
	for _, d := range s.Detections {
		n += int64(len(d.Payload)) + int64(len(d.Evidence))
	}
	for k, v := range s.EnumerationData {
		n += int64(len(k))
		if str, ok := v.(string); ok {
			n += int64(len(str))
		}
	}
	return n
}

// ResolveKey returns the session key for a target/name pair without touching
// disk. It is exposed for diagnostics and CLI mirroring.
func (m *Manager) ResolveKey(target, name string) string {
	return m.sessionKey(target, name)
}
