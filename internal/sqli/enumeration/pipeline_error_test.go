package enumeration

// End-to-end pipeline test over the error-based channel. A tiny MySQL
// "backend" simulator answers every request the enumeration/dump engine emits
// (EXTRACTVALUE leaks, count wrappers, derived-table cell reads, direct
// LIMIT/OFFSET scalars) so the four sqlmap-style flows — --dbs, --tables,
// --columns, --dump — run against the real public API exactly as
// cmd/vexor/sqli.go drives them, including the wp_user -> wp_users fallback.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/0xseif-code/vexor/internal/httpclient"
	"github.com/0xseif-code/vexor/internal/sqli"
	"github.com/0xseif-code/vexor/internal/sqli/dbms"
	"github.com/0xseif-code/vexor/internal/sqli/injection"
	"github.com/0xseif-code/vexor/internal/sqli/techniques"
)

// mockMySQL holds the schema/table data the simulated backend serves.
type mockMySQL struct {
	databases []string
	tables    map[string][]string // db -> table names
	columns   map[string][]string // "db.table" -> column order
	rows      map[string][][]string
}

func newMockMySQL() *mockMySQL {
	return &mockMySQL{
		databases: []string{"information_schema", "mysql", "performance_schema", "wordpress"},
		tables: map[string][]string{
			"information_schema": {"TABLES", "COLUMNS", "SCHEMATA"},
			"mysql":              {"user", "db"},
			"wordpress":          {"wp_options", "wp_posts", "wp_users"},
		},
		columns: map[string][]string{
			"wordpress.wp_posts": {"ID", "post_author", "post_date", "post_content"},
			"wordpress.wp_users": {"ID", "user_login", "user_pass", "user_nicename", "user_email"},
		},
		rows: map[string][][]string{
			"wordpress.wp_users": {
				{"1", "admin", "$P$B1abcdeghijklmnopqrstuvwxyz234567", "", "admin@example.com"},
				{"2", "editor", "$P$B2xyzzy9876543210abcdefghijk", "", "editor@example.com"},
			},
		},
	}
}

var (
	reSubstring = regexp.MustCompile(`(?s)^ifnull\(substring\(\((.*)\),(\d+),(\d+)\),''\)$`)
	reCountWrap = regexp.MustCompile(`(?s)^\(SELECT count\(\*\) FROM \((.*)\) AS x\)$`)
	reCellWrap  = regexp.MustCompile(`(?s)^SELECT c(\d+) FROM \((.*)\) AS x$`)
	reTrailLim  = regexp.MustCompile(`(?is)\s+LIMIT\s+(\d+)(?:\s+OFFSET\s+(\d+))?\s*$`)
	reFromTable = regexp.MustCompile(`(?i)\bfrom\s+([a-z0-9_]+)\.([a-z0-9_]+)`)
	reSelFrom   = regexp.MustCompile(`(?is)^select\s+([a-z0-9_]+)\s+from\s+`)
)

// substringAt extracts bytes [pos, pos+chunk) of s with 1-based pos.
func substringAt(s string, pos, chunk int) string {
	if pos < 1 {
		pos = 1
	}
	start := pos - 1
	if start >= len(s) {
		return ""
	}
	end := start + chunk
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}

func atoi2(s string) (int, error) { return strconv.Atoi(strings.TrimSpace(s)) }

// tableRows evaluates a SELECT query text against the mock data, returning the
// full row matrix after any trailing LIMIT/OFFSET is applied.
func (m *mockMySQL) tableRows(query string) [][]string {
	q := strings.ReplaceAll(query, "`", "")
	low := strings.ToLower(q)
	var out [][]string

	findStr := func(marker string) string {
		i := strings.Index(low, marker)
		if i < 0 {
			return ""
		}
		rest := low[i+len(marker):]
		j := strings.IndexByte(rest, '\'')
		if j < 0 {
			return ""
		}
		return rest[:j]
	}

	switch {
	case strings.Contains(low, "information_schema.schemata"):
		for _, db := range m.databases {
			out = append(out, []string{db})
		}
	case strings.Contains(low, "information_schema.tables"):
		db := findStr("table_schema='")
		for _, t := range m.tables[db] {
			out = append(out, []string{t})
		}
	case strings.Contains(low, "information_schema.columns"):
		db := findStr("table_schema='")
		tbl := findStr("table_name='")
		for _, c := range m.columns[db+"."+tbl] {
			out = append(out, []string{c})
		}
	default:
		if fm := reFromTable.FindStringSubmatch(q); len(fm) == 3 {
			db, tbl := fm[1], fm[2]
			out = append(out, m.rows[db+"."+tbl]...)
		}
	}

	if lm := reTrailLim.FindStringSubmatch(low); lm != nil {
		limit, _ := atoi2(lm[1])
		off := 0
		if lm[2] != "" {
			off, _ = atoi2(lm[2])
		}
		if off > len(out) {
			return nil
		}
		out = out[off:]
		if limit > 0 && limit < len(out) {
			out = out[:limit]
		}
	}
	return out
}

func stripOuterParens(s string) string {
	if len(s) < 2 || s[0] != '(' {
		return s
	}
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				if i == len(s)-1 {
					return s[1 : len(s)-1]
				}
				return s
			}
		}
	}
	return s
}

// eval evaluates one SQL scalar expression string and returns its value.
func (m *mockMySQL) eval(expr string) (string, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return "", false
	}
	if sm := reSubstring.FindStringSubmatch(expr); sm != nil {
		pos, _ := atoi2(sm[2])
		chunk, _ := atoi2(sm[3])
		inner, ok := m.eval(sm[1])
		if !ok {
			return "", false
		}
		return substringAt(inner, pos, chunk), true
	}

	norm := strings.ReplaceAll(expr, "`", "")
	if cm := reCountWrap.FindStringSubmatch(norm); cm != nil {
		return itoa(int64(len(m.tableRows(cm[1])))), true
	}
	if cm := reCellWrap.FindStringSubmatch(norm); cm != nil {
		col, _ := atoi2(cm[1])
		rows := m.tableRows(cm[2])
		if len(rows) == 0 || col < 1 || col > len(rows[0]) {
			return "", false
		}
		return rows[0][col-1], true
	}

	inner := strings.ReplaceAll(stripOuterParens(norm), "`", "")
	if len(inner) >= 2 && inner[0] == '\'' && inner[len(inner)-1] == '\'' {
		return inner[1 : len(inner)-1], true // string literal, e.g. ('VEXORTEST')
	}
	if strings.Contains(strings.ToLower(inner), "database()") {
		return "wordpress", true
	}
	if strings.Contains(strings.ToLower(inner), "count(*)") {
		if len(reFromTable.FindStringSubmatch(inner)) == 3 {
			return itoa(int64(len(m.tableRows(inner)))), true
		}
	}
	if fm := reFromTable.FindStringSubmatch(inner); len(fm) == 3 {
		colName, _ := m.directCellParts(inner)
		db, tbl := fm[1], fm[2]
		order := m.columns[db+"."+tbl]
		colIdx := -1
		for i, c := range order {
			if strings.EqualFold(c, colName) {
				colIdx = i
				break
			}
		}
		if colIdx < 0 {
			return "", false
		}
		rows := m.tableRows(inner)
		if len(rows) == 0 || colIdx >= len(rows[0]) {
			return "", false
		}
		// tableRows already applied the trailing LIMIT/OFFSET, so the single
		// remaining row is the requested one.
		return rows[0][colIdx], true
	}
	return "", false
}

func (m *mockMySQL) directCellParts(q string) (col string, off int) {
	if cm := reSelFrom.FindStringSubmatch(q); len(cm) == 2 {
		col = cm[1]
	}
	if lm := reTrailLim.FindStringSubmatch(q); lm != nil && lm[2] != "" {
		off, _ = atoi2(lm[2])
	}
	return
}

// evalInjected extracts the value expression from an injected error-channel
// payload and evaluates it against the mock backend.
func (m *mockMySQL) evalInjected(v string) (val string, evalled, dup bool) {
	up := strings.ToUpper(v)
	var start, end string
	if strings.Contains(up, "0X7E7E,(") {
		start, end = "0x7e7e,(", "),0x7e7e"
		dup = true
	} else if strings.Contains(up, "0X7E,(") {
		start, end = "0x7e,(", "),0x7e)"
	} else {
		return "", false, false
	}
	i := strings.Index(v, start)
	if i < 0 {
		return "", false, false
	}
	i += len(start)
	rest := v[i:]
	j := strings.Index(rest, end)
	if j < 0 {
		return "", false, false
	}
	val, evalled = m.eval(rest[:j])
	return
}

// serve is the simulated error-based MySQL HTTP handler.
func (m *mockMySQL) serve() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		if val, ok, dup := m.evalInjected(v); ok {
			w.WriteHeader(500)
			if dup {
				fmt.Fprintf(w, "You have an error in your SQL syntax; Duplicate entry '~~%s~~1' for key 'group_key'", val)
			} else {
				fmt.Fprintf(w, "You have an error in your SQL syntax; XPATH syntax error: '~%s~'", val)
			}
			return
		}
		w.WriteHeader(200)
		fmt.Fprintln(w, "<!doctype html><html><body>normal page</body></html>")
	})
}

func hasStr(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

// TestErrorPipelineFullFlow is the code-form of the four acceptance flows plus
// the wrong-table-name fallback, run over the real error-based channel.
func TestErrorPipelineFullFlow(t *testing.T) {
	mock := newMockMySQL()
	srv := httptest.NewServer(mock.serve())
	defer srv.Close()

	client := httpclient.NewClient(httpclient.ClientOptions{})
	points, err := injection.Enumerate(injection.RequestSource{
		Method: "GET",
		URL:    srv.URL + "/?id=1",
	}, injection.Options{Level: 1})
	if err != nil {
		t.Fatalf("enumerate point: %v", err)
	}

	det := sqli.Detection{
		Technique: techniques.TechError,
		DBMS:      dbms.MySQL,
		Point:     *points[0],
		Payload:   "1 AND EXTRACTVALUE(1,CONCAT(0x7e,version(),0x7e))-- -",
	}
	enum := NewEnumeratorOpts(det, client, Options{
		Concurrency: 1,
		Progress:    io.Discard,
		Crack:       CrackNever,
	})
	ctx := context.Background()

	// 1) --dbs
	dbs, err := enum.ListDatabases(ctx)
	if err != nil {
		t.Fatalf("ListDatabases: %v", err)
	}
	if !hasStr(dbs, "wordpress") || !hasStr(dbs, "mysql") {
		t.Errorf("ListDatabases = %v, expected to contain wordpress/mysql", dbs)
	}

	// 2) -D wordpress --tables, and the current-database default (no -D).
	tables, err := enum.ListTables(ctx, "wordpress")
	if err != nil {
		t.Fatalf("ListTables(wordpress): %v", err)
	}
	if !hasStr(tables, "wp_users") || !hasStr(tables, "wp_posts") {
		t.Errorf("ListTables = %v, expected wp_users/wp_posts", tables)
	}
	tablesCur, err := enum.ListTables(ctx, "")
	if err != nil {
		t.Fatalf("ListTables(empty db = current): %v", err)
	}
	if !hasStr(tablesCur, "wp_users") {
		t.Errorf("ListTables(current db) = %v, expected wp_users", tablesCur)
	}

	// 3) -T wp_users --columns (via exact name).
	cols, err := enum.ListColumns(ctx, "wordpress", "wp_users")
	if err != nil {
		t.Fatalf("ListColumns: %v", err)
	}
	names := columnsOf(cols)
	for _, want := range []string{"ID", "user_login", "user_pass", "user_email"} {
		if !hasStr(names, want) {
			t.Errorf("ListColumns = %v, missing %q", names, want)
		}
	}

	// 4) -T wp_user --dump (wrong name must fall back to wp_users and dump).
	res, err := enum.Dump(ctx, DumpOptions{Database: "wordpress", Table: "wp_user"})
	if err != nil {
		t.Fatalf("Dump(wp_user): %v", err)
	}
	if res.Table != "wp_users" {
		t.Fatalf("Dump resolved table = %q, want wp_users", res.Table)
	}
	if len(res.Rows) != 2 {
		t.Fatalf("Dump rows = %d, want 2", len(res.Rows))
	}
	if res.Rows[0][1] != "admin" || res.Rows[1][1] != "editor" {
		t.Errorf("Dump user_login column wrong: %v / %v", res.Rows[0], res.Rows[1])
	}
	if res.Rows[0][4] != "admin@example.com" {
		t.Errorf("Dump user_email wrong: %q", res.Rows[0][4])
	}

	// The extracted password hash must survive chunked (>30 byte) reads.
	if len(res.Rows[0][2]) < 30 {
		t.Errorf("user_pass truncated: %q", res.Rows[0][2])
	}
}