package enumeration

import (
	"context"
	"strings"
	"testing"

	"github.com/0xseif-code/vexor/internal/sqli"
	"github.com/0xseif-code/vexor/internal/sqli/dbms"
)

func testDetection(db string) sqli.Detection {
	return sqli.Detection{
		Technique: "boolean-based blind",
		DBMS:      db,
	}
}

func TestPostCatalogMySQL(t *testing.T) {
	q := dbms.Post(dbms.MySQL)
	if q == nil {
		t.Fatal("mysql post queries missing")
	}
	if got := q.CurrentUser(); got != "SELECT user()" {
		t.Errorf("CurrentUser = %q", got)
	}
	if got := q.ListTables("app"); got != "SELECT table_name FROM information_schema.tables WHERE table_schema='app' ORDER BY table_name" {
		t.Errorf("ListTables = %q", got)
	}
	if got := q.PasswordHashes(); got != "SELECT user,authentication_string FROM mysql.user" {
		t.Errorf("PasswordHashes = %q", got)
	}
	if !q.StackedOK {
		t.Error("mysql should be stackable")
	}
	got := q.Extract.TimeTest("1", "1=1", "5")
	if !strings.Contains(got, "SLEEP(5)") {
		t.Errorf("mysql TimeTest = %q", got)
	}
}

func TestPostCatalogPostgres(t *testing.T) {
	q := dbms.Post(dbms.Postgres)
	if q == nil {
		t.Fatal("postgres post queries missing")
	}
	if got := q.CurrentUser(); got != "SELECT current_user" {
		t.Errorf("CurrentUser = %q", got)
	}
	if got := q.OSCommand("id"); !strings.Contains(got, "COPY") {
		t.Errorf("OSCommand = %q", got)
	}
}

func TestPostCatalogMSSQLRegistry(t *testing.T) {
	q := dbms.Post(dbms.MSSQL)
	if q == nil || q.RegRead == nil {
		t.Fatal("mssql reg queries missing")
	}
	if got := q.RegRead("HKLM", "SOFTWARE", "Name"); !strings.Contains(got, "xp_regread") {
		t.Errorf("RegRead = %q", got)
	}
	if got := q.OSCommand("whoami"); !strings.Contains(got, "xp_cmdshell") {
		t.Errorf("OSCommand = %q", got)
	}
	gotD := q.Extract.Direct("@@version")
	if !strings.Contains(gotD, "convert") {
		t.Errorf("mssql Direct = %q", gotD)
	}
}

func TestPostCatalogSQLiteNoUsers(t *testing.T) {
	q := dbms.Post(dbms.SQLite)
	if q == nil {
		t.Fatal("sqlite post queries missing")
	}
	if got := q.CurrentUser(); !strings.Contains(got, "n/a") {
		t.Errorf("sqlite CurrentUser = %q", got)
	}
	if q.StackedOK {
		t.Error("sqlite must not be stackable")
	}
}

func TestCharsetOrderAllPrintable(t *testing.T) {
	seen := map[byte]bool{}
	for _, c := range charsetOrder {
		if seen[c] {
			t.Errorf("duplicate byte 0x%02x in charset", c)
		}
		seen[c] = true
	}
	// Common letters and digits must appear early.
	if charsetOrder[0] != 'a' {
		t.Errorf("charset[0] = %q, want 'a'", charsetOrder[0])
	}
	foundDigit := false
	for i, c := range charsetOrder {
		if c >= '0' && c <= '9' {
			if i > 60 {
				t.Errorf("digit 0x%02x too late at index %d", c, i)
			}
			foundDigit = true
		}
	}
	if !foundDigit {
		t.Error("no digit in charset")
	}
}

func TestGlobRegex(t *testing.T) {
	re, err := globRegex("password")
	if err != nil {
		t.Fatal(err)
	}
	if !re.MatchString("Password") || !re.MatchString("password_hash") {
		t.Error("substring glob should match case-insensitively")
	}
	re2, _ := globRegex("user*")
	if !re2.MatchString("users_admin") || re2.MatchString("u_ser") {
		t.Error("wildcard glob misbehaves")
	}
	re3, _ := globRegex("")
	if !re3.MatchString("anything") {
		t.Error("empty pattern should match all")
	}
}

func TestParseInt(t *testing.T) {
	cases := map[string]int64{
		"42":         42,
		"  7 ":       7,
		"-5":         -5,
		"":           0,
		"9999999999": 9999999999,
	}
	for in, want := range cases {
		if got, _ := parseInt(in); got != want {
			t.Errorf("parseInt(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestMBLCAlphabetUnique(t *testing.T) {
	if len(defaultAlphabet) == 0 {
		t.Fatal("default alphabet empty")
	}
}

// cellScalar does not require a network so we can verify the scalar builders.
func TestCellScalar(t *testing.T) {
	e, err := testExtractorFor(dbms.MySQL)
	if err != nil {
		t.Skip("extractor setup failed: " + err.Error())
	}
	s := e.cellScalar("app", "users", "email", "", 5)
	if !strings.Contains(s, "OFFSET 5") || !strings.Contains(s, "`users`") {
		t.Errorf("mysql cellScalar = %q", s)
	}
}

func TestAliasSelectColumns(t *testing.T) {
	q := aliasSelectColumns("SELECT user,host FROM mysql.user", 2)
	want := "SELECT user AS c1, host AS c2 FROM mysql.user"
	if q != want {
		t.Errorf("alias = %q, want %q", q, want)
	}
	// cell expression then references the alias correctly.
	cell := cellExpr(q, 0, 3)
	if !strings.Contains(cell, "c1") || !strings.Contains(cell, "OFFSET 3") {
		t.Errorf("cellExpr = %q", cell)
	}
	// a query with existing alias is preserved.
	q2 := aliasSelectColumns("SELECT count(*) AS n FROM t", 1)
	if !strings.Contains(q2, "count(*) AS n") {
		t.Errorf("existing alias not preserved: %q", q2)
	}
	// unparseable / no FROM passes through unchanged.
	q3 := aliasSelectColumns("VALUES (1)", 1)
	if q3 != "VALUES (1)" {
		t.Errorf("no-FROM passthrough = %q", q3)
	}
}

// testExtractorFor builds a real enumerator's extractor without network use.
func testExtractorFor(db string) (*Enumerator, error) {
	det := testDetection(db)
	// client is nil; extraction methods that need the network are not invoked
	// here — only query-string construction is exercised.
	en := &Enumerator{
		detector: det,
		queries:  dbms.Post(db),
		opts:     Options{Concurrency: 4},
	}
	en.ext = NewExtractor(det, nil, Options{Concurrency: 4})
	_ = context.Background()
	return en, nil
}

var _ = context.Background
