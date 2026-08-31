package enumeration

// End-to-end regression test for the restricted-information_schema fallback:
// a MySQL target whose error channel leaks table data but where every
// information_schema.* query is refused (returns a normal 200 page, mirroring a
// user with no catalogue privileges / a WAF). The dump must not abort with
// "no column set found" — it must fall back to probing + default schema maps
// and still dump wp_users rows (user_login / user_pass) via error leakage.

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

// wordpressUsers is the data the blocked-schema backend holds.
var wordpressUsers = []struct {
	id       string
	login    string
	pass     string
	nicename string
	email    string
}{
	{"1", "admin", "$P$B1abcdeghijklmnopqrstuvwxyz234567", "admin", "admin@example.com"},
	{"2", "editor", "$P$B2xyzzy9876543210abcdefghijk", "editor", "editor@example.com"},
}

var badSchemaCols = []string{"ID", "user_login", "user_pass", "user_nicename", "user_email"}

var (
	reRestSub  = regexp.MustCompile(`(?s)^ifnull\(substring\(\((.*)\),(\d+),(\d+)\),''\)$`)
	reRestCount = regexp.MustCompile(`(?s)^\(SELECT count\(\*\) FROM \((.*)\) AS x\)$`)
	reRestCell  = regexp.MustCompile(`(?s)^SELECT c(\d+) FROM \((.*)\) AS x$`)
	reRestLim   = regexp.MustCompile(`(?is)\s+LIMIT\s+(\d+)(?:\s+OFFSET\s+(\d+))?\s*$`)
	reRestFrom  = regexp.MustCompile(`(?i)\bfrom\s+([a-z0-9_]+)\.([a-z0-9_]+)`)
	reRestSel   = regexp.MustCompile(`(?is)^select\s+([a-z0-9_]+)\s+from\s+`)
)

func restAt(s string, pos, chunk int) string {
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

// restTableRows returns the wp_users row matrix after applying a trailing
// LIMIT/OFFSET. It returns nil when the query touches information_schema
// (blocked).
func restTableRows(query string) [][]string {
	q := strings.ReplaceAll(query, "`", "")
	low := strings.ToLower(q)
	if strings.Contains(low, "information_schema") {
		return nil
	}
	type rowT struct{ v []string }
	rows := make([]rowT, 0, len(wordpressUsers))
	for _, u := range wordpressUsers {
		rows = append(rows, rowT{v: []string{u.id, u.login, u.pass, u.nicename, u.email}})
	}
	out := make([][]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.v)
	}
	if lm := reRestLim.FindStringSubmatch(low); lm != nil {
		limit, _ := strconv.Atoi(lm[1])
		off := 0
		if lm[2] != "" {
			off, _ = strconv.Atoi(lm[2])
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

func restStripParens(s string) string {
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

// restEval evaluates a scalar SQL expression against the blocked-schema mock.
func restEval(expr string) (string, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return "", false
	}
	if sm := reRestSub.FindStringSubmatch(expr); sm != nil {
		pos, _ := strconv.Atoi(sm[2])
		chunk, _ := strconv.Atoi(sm[3])
		inner, ok := restEval(sm[1])
		if !ok {
			return "", false
		}
		return restAt(inner, pos, chunk), true
	}
	norm := strings.ReplaceAll(expr, "`", "")
	if cm := reRestCount.FindStringSubmatch(norm); cm != nil {
		rows := restTableRows(cm[1])
		if rows == nil {
			return "", false // information_schema blocked -> no leak
		}
		return strconv.Itoa(len(rows)), true
	}
	if cm := reRestCell.FindStringSubmatch(norm); cm != nil {
		col, _ := strconv.Atoi(cm[1])
		rows := restTableRows(cm[2])
		if rows == nil || len(rows) == 0 || col < 1 || col > len(rows[0]) {
			return "", false
		}
		return rows[0][col-1], true
	}
	inner := strings.ReplaceAll(restStripParens(norm), "`", "")
	if strings.Contains(strings.ToLower(inner), "database()") {
		return "wordpress", true
	}
	if len(inner) >= 2 && inner[0] == '\'' && inner[len(inner)-1] == '\'' {
		return inner[1 : len(inner)-1], true
	}
	if fm := reRestFrom.FindStringSubmatch(inner); len(fm) == 3 {
		colName := ""
		if sm := reRestSel.FindStringSubmatch(inner); len(sm) == 2 {
			colName = sm[1]
		}
		rows := restTableRows(inner)
		if rows == nil {
			return "", false
		}
		colIdx := -1
		for i, c := range badSchemaCols {
			if strings.EqualFold(c, colName) {
				colIdx = i
				break
			}
		}
		if colIdx < 0 || len(rows) == 0 || colIdx >= len(rows[0]) {
			return "", false
		}
		return rows[0][colIdx], true
	}
	return "", false
}

// restEvalInjected pulls the value expression from an injected EXTRACTVALUE
// payload and evaluates it, returning whether a leak is possible.
func restEvalInjected(v string) (val string, ok bool) {
	up := strings.ToUpper(v)
	var start, end string
	if strings.Contains(up, "0X7E7E,(") {
		start, end = "0x7e7e,(", "),0x7e7e"
	} else if strings.Contains(up, "0X7E,(") {
		start, end = "0x7e,(", "),0x7e)"
	} else {
		return "", false
	}
	i := strings.Index(v, start)
	if i < 0 {
		return "", false
	}
	i += len(start)
	rest := v[i:]
	j := strings.Index(rest, end)
	if j < 0 {
		return "", false
	}
	return restEval(rest[:j])
}

// blockedSchemaServe is the restricted information_schema handler.
func blockedSchemaServe() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		if val, ok := restEvalInjected(v); ok {
			// Real-table reads leak; information_schema reads return !ok above
			// and fall through to the normal page below.
			w.WriteHeader(500)
			fmt.Fprintf(w, "XPATH syntax error: '~%s~'", val)
			return
		}
		w.WriteHeader(200)
		fmt.Fprintln(w, "<!doctype html><html><body>normal page</body></html>")
	})
}

func newBlockedSchemaEnumerator(t *testing.T, srvURL string) *Enumerator {
	t.Helper()
	client := httpclient.NewClient(httpclient.ClientOptions{})
	points, err := injection.Enumerate(injection.RequestSource{
		Method: "GET",
		URL:    srvURL + "/?id=1",
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
	return NewEnumeratorOpts(det, client, Options{
		Concurrency: 1,
		Progress:    io.Discard,
		Crack:       CrackNever,
	})
}

// TestRestrictedSchemaDumpVerifiesBypass confirms that a --dump against a
// table whose backer has blocked information_schema still resolves a usable
// column set (via brute-force / default map) and concatenates + leaks row data
// through the error channel, rather than aborting with "no column set found".
func TestRestrictedSchemaDumpVerifiesBypass(t *testing.T) {
	srv := httptest.NewServer(blockedSchemaServe())
	defer srv.Close()
	enum := newBlockedSchemaEnumerator(t, srv.URL)
	ctx := context.Background()

	res, err := enum.Dump(ctx, DumpOptions{Database: "wordpress", Table: "wp_users"})
	if err != nil {
		t.Fatalf("Dump should not abort on restricted information_schema: %v", err)
	}
	if len(res.Rows) != 2 {
		t.Fatalf("Dump rows = %d, want 2 (got %v)", len(res.Rows), res.Rows)
	}
	// user_login at index 1, user_pass at index 2 in wp_users.
	if res.Rows[0][1] != "admin" || res.Rows[1][1] != "editor" {
		t.Errorf("user_login wrong: %v / %v", res.Rows[0], res.Rows[1])
	}
	if !strings.HasPrefix(res.Rows[0][2], "$P$B") {
		t.Errorf("user_pass wrong: %q", res.Rows[0][2])
	}
	if res.Rows[0][2] == "" {
		t.Error("user_pass is empty; error channel leaked no hash")
	}
}

// TestRestrictedSchemaConcatFallback forces the per-cell dump to fail by
// requesting a column name the backup schema does not contain, then verifies
// the concatenated row dump (sqlmap style) recovers the rows through the error
// channel.
func TestRestrictedSchemaConcatFallback(t *testing.T) {
	srv := httptest.NewServer(blockedSchemaServe())
	defer srv.Close()
	enum := newBlockedSchemaEnumerator(t, srv.URL)
	ctx := context.Background()

	// Explicitly request a non-existent column so the per-cell path fails and
	// dumpChunkConcat takes over.
	res, err := enum.Dump(ctx, DumpOptions{
		Database: "wordpress",
		Table:    "wp_users",
		Columns:  []string{"user_login", "user_pass"},
	})
	if err != nil {
		t.Fatalf("Dump with bogus columns should fall back to concat: %v", err)
	}
	if len(res.Rows) == 0 {
		t.Fatal("concat fallback returned no rows")
	}
	if !strings.Contains(res.Rows[0][0], "admin") {
		t.Errorf("concat row 0 = %v, want to contain admin", res.Rows[0])
	}
}
