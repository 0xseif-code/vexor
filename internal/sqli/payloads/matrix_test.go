package payloads

import "testing"

func TestTotalPayloadTemplates(t *testing.T) {
	if Total() < 220 {
		t.Fatalf("matrix has %d payloads, want >= 220", Total())
	}
}

// TestPayloadMatrixCounts prints the coverage summary and enforces every hard
// gate (total, per-DBMS, per-technique) with t.Fatalf so a drop in coverage can
// never pass silently.
func TestPayloadMatrixCounts(t *testing.T) {
	total := Total()
	dbCounts := CountByDBMS()
	techCounts := CountByTechnique()

	t.Logf("TOTAL=%d", total)
	t.Logf("by DBMS:")
	for _, db := range []string{DBMySQL, DBPostgres, DBMSSQL, DBOracle, DBSQLite, DBGeneric} {
		t.Logf("  %-8s %d", db, dbCounts[db])
	}
	t.Logf("by technique:")
	for _, tech := range AllTechniques {
		t.Logf("  %-8s %d", tech, techCounts[tech])
	}

	dbMin := map[string]int{
		DBMySQL: 90, DBPostgres: 35, DBMSSQL: 35,
		DBOracle: 30, DBSQLite: 20, DBGeneric: 20,
	}
	techMin := map[Technique]int{
		TechBoolean: 40, TechError: 50, TechTime: 35,
		TechUnion: 25, TechStacked: 20, TechInline: 15, TechOOB: 10,
	}

	if total < 220 {
		t.Fatalf("TOTAL=%d, want >= 220", total)
	}
	for db, min := range dbMin {
		if dbCounts[db] < min {
			t.Fatalf("%s has %d templates, want >= %d", db, dbCounts[db], min)
		}
	}
	for tech, min := range techMin {
		if techCounts[tech] < min {
			t.Fatalf("technique %s has %d templates, want >= %d", tech, techCounts[tech], min)
		}
	}
}

func TestUniqueIDs(t *testing.T) {
	seen := map[string]string{}
	for _, p := range All() {
		if prev, ok := seen[p.ID]; ok {
			t.Fatalf("duplicate ID %q registered by %q and %q", p.ID, prev, p.Title)
		}
		seen[p.ID] = p.Title
	}
}

func TestPerDBMSMinimums(t *testing.T) {
	targets := map[string]int{
		DBMySQL:    90,
		DBPostgres: 35,
		DBMSSQL:    35,
		DBOracle:   30,
		DBSQLite:   20,
		DBGeneric:  20,
	}
	counts := CountByDBMS()
	for db, min := range targets {
		if counts[db] < min {
			t.Errorf("%s has %d payloads, want >= %d", db, counts[db], min)
		}
	}
}

func TestSelectLevelGrowth(t *testing.T) {
	opt := SelectOptions{DBMS: DBMySQL, Risk: 3}
	opt.Level = 1
	small := Select(opt)
	opt.Level = 5
	large := Select(opt)
	if len(small) >= len(large) {
		t.Fatalf("Select(level=1) has %d >= Select(level=5) %d, want strictly smaller", len(small), len(large))
	}
	if len(small) == 0 {
		t.Fatal("level-1 selection empty")
	}
}

func TestExpandWrappersGrowWithLevel(t *testing.T) {
	p := Get("mysql-bool-and-num")
	if p.ID == "" {
		t.Fatal("mysql-bool-and-num missing from matrix")
	}
	m := DefaultMacro()
	l1 := len(Expand(p, 1, m))
	l2 := len(Expand(p, 2, m))
	l3 := len(Expand(p, 3, m))
	if !(l2 > l1) {
		t.Errorf("level2 (%d) not > level1 (%d)", l2, l1)
	}
	if l3 <= l2 {
		t.Errorf("level3 (%d) not > level2 (%d)", l3, l2)
	}
	// Sanity: wrapper expansion never returns empty.
	if l1 == 0 {
		t.Fatal("no wrappers at level 1")
	}
}

func TestLevel4AddsMutations(t *testing.T) {
	// A payload containing the AND keyword gains comment-obfuscated mutations
	// at level 4.
	p := Get("mysql-bool-and-num")
	m := DefaultMacro()
	l3 := len(Expand(p, 3, m))
	l4 := len(Expand(p, 4, m))
	if l4 <= l3 {
		t.Errorf("level4 (%d) not > level3 (%d) despite mutations", l4, l3)
	}
}

func TestTitlesUniquePerID(t *testing.T) {
	seen := map[string]string{} // title -> id
	for _, p := range All() {
		if prev, ok := seen[p.Title]; ok {
			t.Errorf("duplicate title %q for IDs %q and %q", p.Title, prev, p.ID)
			continue
		}
		seen[p.Title] = p.ID
	}
}

func TestNoEmptyTemplates(t *testing.T) {
	for _, p := range All() {
		if p.Template == "" {
			t.Errorf("payload %s (%s) has empty template", p.ID, p.Title)
		}
		if p.Title == "" {
			t.Errorf("payload %s has empty title", p.ID)
		}
	}
}

func TestDuplicateIDsRejected(t *testing.T) {
	// MustRegister must panic on a duplicate ID; verify it does not corrupt the
	// registry when the same payload is added twice via a fresh capture.
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on duplicate ID registration")
		}
	}()
	// Register a sentinel ID twice by aliasing an existing unique synthetic
	// payload (never actually pollutes the registry because we panic first).
	MustRegister(Payload{ID: "test-dup-sentinel-xyz", Title: "x", DBMS: DBMySQL, Template: "1"})
	MustRegister(Payload{ID: "test-dup-sentinel-xyz", Title: "y", DBMS: DBMySQL, Template: "2"})
}

func TestTechniqueCoverage(t *testing.T) {
	byTech := CountByTechnique()
	for _, tech := range AllTechniques {
		if byTech[tech] == 0 {
			t.Errorf("no payloads for technique %q", tech)
		}
	}
}

func TestFillPlaceholders(t *testing.T) {
	m := Macro{Orig: "cat=1", Query: "SELECT 1", Seconds: "3", Marker: "99", ColCount: "NULL,NULL", Domain: "att.d", M1: "3e", M2: "3f"}
	got := Fill("{orig} AND SLEEP({seconds})-- {query}", m)
	want := "cat=1 AND SLEEP(3)-- SELECT 1"
	if got != want {
		t.Errorf("Fill = %q, want %q", got, want)
	}
	if got := Fill("{marker}|{colcount}|{domain}|{m1}|{m2}", m); got != "99|NULL,NULL|att.d|3e|3f" {
		t.Errorf("Fill macros = %q", got)
	}
}
