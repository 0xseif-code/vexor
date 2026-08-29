package session

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xseif-code/vexor/internal/sqli"
	"github.com/0xseif-code/vexor/internal/sqli/injection"
)

func tempManager(t *testing.T) *Manager {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "sessions")
	m, err := NewManagerWithDir(dir)
	if err != nil {
		t.Fatalf("NewManagerWithDir: %v", err)
	}
	return m
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	m := tempManager(t)
	s := NewSessionFor("https://example.com/?id=1")
	s.Detections = []sqli.Detection{
		{Technique: "boolean", DBMS: "MySQL", Payload: "1 AND 1=1", Confidence: 95},
	}
	s.EnumerationData = map[string]interface{}{"current_db": "appdb"}
	s.DumpedTables = map[string]DumpMeta{
		"users": {Table: "users", Database: "appdb", Rows: 10},
	}
	if err := m.Save(s); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := m.Load("https://example.com/?id=1")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Target != "https://example.com/?id=1" {
		t.Errorf("target mismatch: %q", loaded.Target)
	}
	if len(loaded.Detections) != 1 {
		t.Errorf("detections = %d", len(loaded.Detections))
	}
	if loaded.EnumerationData["current_db"] != "appdb" {
		t.Errorf("enumeration data = %v", loaded.EnumerationData)
	}
	if loaded.DumpedTables["users"].Rows != 10 {
		t.Errorf("dumped table = %+v", loaded.DumpedTables["users"])
	}
}

func TestLoadByNameAndHashReset(t *testing.T) {
	m := tempManager(t)
	s := NewSessionFor("https://example.com/?id=1")
	s.Name = "run_1"
	if err := m.Save(s); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := m.LoadByName("run_1")
	if err != nil {
		t.Fatalf("LoadByName: %v", err)
	}
	if loaded.Name != "run_1" {
		t.Errorf("name = %q", loaded.Name)
	}
}

func TestFlush(t *testing.T) {
	m := tempManager(t)
	s := NewSessionFor("https://example.com/?id=1")
	if err := m.Save(s); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := m.Flush("https://example.com/?id=1"); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	_, err := m.Load("https://example.com/?id=1")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected ErrNotExist after flush, got %v", err)
	}
}

func TestList(t *testing.T) {
	m := tempManager(t)
	_ = m.Save(NewSessionFor("https://a.com/"))
	_ = m.Save(NewSessionFor("https://b.com/"))
	infos, err := m.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(infos) != 2 {
		t.Errorf("list count = %d", len(infos))
	}
}

func TestCorruptSessionRecovery(t *testing.T) {
	m := tempManager(t)
	key := "deadbeef"
	path := filepath.Join(m.dir, key+".json")
	if err := os.WriteFile(path, []byte("{invalid json"), 0o644); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}
	s, err := m.load(key, "corrupt-target")
	if err != nil {
		t.Fatalf("expected recovery, got %v", err)
	}
	if s == nil {
		t.Fatal("expected fresh session")
	}
	// Corrupt file should have been backed up.
	entries, _ := os.ReadDir(m.dir)
	for _, e := range entries {
		if contains(e.Name(), ".corrupt-") {
			return
		}
	}
	t.Error("corrupt file was not backed up")
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestLocking(t *testing.T) {
	m := tempManager(t)
	key := "some-key"
	release, err := m.acquire(key)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// Attempting to acquire the same key again in-process is rejected.
	if _, err := m.acquire(key); err == nil {
		t.Error("expected second acquire to fail while held")
	}
	release()
	// After release we can acquire again.
	release2, err := m.acquire(key)
	if err != nil {
		t.Errorf("re-acquire after release failed: %v", err)
	}
	if release2 != nil {
		release2()
	}
}

var _ = injection.TypeGET
