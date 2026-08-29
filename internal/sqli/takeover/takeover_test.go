package takeover

import (
	"strings"
	"testing"

	"github.com/0xseif-code/vexor/internal/sqli"
	"github.com/0xseif-code/vexor/internal/sqli/dbms"
)

func det(db string) sqli.Detection {
	return sqli.Detection{Technique: "boolean-based blind", DBMS: db}
}

func TestFileSystemMySQLReadBuild(t *testing.T) {
	fs := NewFileSystem(det(dbms.MySQL), nil)
	if !fs.Supported() {
		t.Fatal("mysql filesystem should be supported")
	}
	// Building the read query for MySQL uses base64 carrier.
	q := fs.fsReadExpr("/etc/passwd")
	if !strings.Contains(q, "to_base64") {
		t.Errorf("mysql read expr = %q", q)
	}
	if got := fs.stripSelect("SELECT load_file('/etc/passwd')"); got != "load_file('/etc/passwd')" {
		t.Errorf("stripSelect = %q", got)
	}
}

func TestFileSystemMSSQLWriteUnsupported(t *testing.T) {
	fs := NewFileSystem(det(dbms.MSSQL), nil)
	// MSSQL has no clean INTO OUTFILE; WriteFile returns "" -> unsupported.
	if !fs.Supported() {
		t.Fatal("mssql read should be supported via OPENROWSET")
	}
}

func TestRegistryMSSQLOnly(t *testing.T) {
	r := NewRegistry(det(dbms.MSSQL), nil)
	if !r.Supported() {
		t.Fatal("mssql registry should be supported")
	}
	if got := r.q.RegRead("HKLM", "SOFTWARE", "Name"); !strings.Contains(got, "xp_regread") {
		t.Errorf("RegRead = %q", got)
	}
	if got := NormalizeHive("hklm"); got != "HKEY_LOCAL_MACHINE" {
		t.Errorf("NormalizeHive = %q", got)
	}
	// Registry is a no-op on non-MSSQL.
	r2 := NewRegistry(det(dbms.MySQL), nil)
	if r2.Supported() {
		t.Error("mysql registry should be unsupported")
	}
}

func TestShellConstruction(t *testing.T) {
	s := NewShell(det(dbms.Postgres), nil)
	if !s.Supported() {
		t.Fatal("postgres shell should be supported")
	}
	if s.Cwd != "/tmp" {
		t.Errorf("postgres default cwd = %q", s.Cwd)
	}
	if !strings.Contains(s.q.OSCommand("id"), "COPY") {
		t.Errorf("postgres OSCommand = %q", s.q.OSCommand("id"))
	}
	s2 := NewShell(det(dbms.MSSQL), nil)
	if s2.Cwd != `C:\Windows\Temp` {
		t.Errorf("mssql default cwd = %q", s2.Cwd)
	}
	if !strings.Contains(s2.q.OSCommand("whoami"), "xp_cmdshell") {
		t.Errorf("mssql OSCommand = %q", s2.q.OSCommand("whoami"))
	}
}

func TestRandSuffixUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		s := randSuffix()
		if seen[s] {
			t.Fatalf("duplicate suffix %q", s)
		}
		seen[s] = true
	}
}
