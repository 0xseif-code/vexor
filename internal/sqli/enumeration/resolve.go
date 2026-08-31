package enumeration

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/0xseif-code/vexor/internal/sqli/ui"
)

// wpCoreTables are the tables every WordPress install ships with. When the
// requested table starts with a `wp` prefix we map a singular/underscored
// shorthand back onto this family (e.g. `wp_user` -> `wp_users`).
var wpCoreTables = []string{
	"users", "user", "user_meta", "usermeta",
	"posts", "post", "post_meta", "postmeta",
	"comments", "comment", "comment_meta", "commentmeta",
	"links", "link", "options", "option",
	"terms", "term", "term_taxonomy", "term_relationships", "termmeta",
	"actionscheduler_actions", "actionscheduler_claims",
	"actionscheduler_schedules", "actionscheduler_groups", "actionscheduler_logs",
	"tua_activities", "tua_activities_count",
}

// pluralSwap flips between common singular and plural spellings.
func pluralSwap(s string) string {
	if s == "" {
		return s
	}
	switch {
	case strings.HasSuffix(s, "ies") && len(s) > 3:
		return s[:len(s)-3] + "y"
	case strings.HasSuffix(s, "ss") && len(s) > 2:
		return s[:len(s)-2]
	case strings.HasSuffix(s, "s") && len(s) > 1:
		return s[:len(s)-1]
	case strings.HasSuffix(s, "y") && len(s) > 1:
		return s[:len(s)-1] + "ies"
	default:
		return s + "s"
	}
}

// singularize strips a trailing "s" when present (used for wp family matching).
func singularize(s string) string {
	if strings.HasSuffix(s, "s") && len(s) > 1 {
		return s[:len(s)-1]
	}
	return s
}

// capitalize upper-cases the first rune.
func capitalize(s string) string {
	if s == "" {
		return s
	}
	r := []rune(strings.ToLower(s))
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

// normIdent lower-cases and strips quoting decorations for comparison.
func normIdent(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "`", "")
	s = strings.ReplaceAll(s, `"`, "")
	s = strings.ReplaceAll(s, "[", "")
	s = strings.ReplaceAll(s, "]", "")
	s = strings.ReplaceAll(s, "'", "")
	return strings.ToLower(strings.TrimSpace(s))
}

// tableCandidates produces the ordered list of table spellings worth probing,
// starting from the exact user-supplied name.
func tableCandidates(table string) []string {
	raw := strings.TrimSpace(table)
	base := strings.ToLower(raw)

	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}

	add(raw)
	add(base)
	upper := strings.ToUpper(raw)
	if upper != raw {
		add(upper)
	}
	capBase := capitalize(base)
	if capBase != raw && capBase != base {
		add(capBase)
	}
	add(pluralSwap(base))
	capPlural := capitalize(pluralSwap(base))
	if capPlural != base {
		add(capPlural)
	}

	if strings.HasPrefix(base, "wp") {
		stem := strings.TrimPrefix(base, "wp_")
		stem = strings.TrimPrefix(stem, "wp")
		stem = strings.Trim(stem, "_")
		pref := "wp_"
		if !strings.HasPrefix(base, "wp_") {
			pref = "wp"
		}
		for _, w := range wpCoreTables {
			wn := normIdent(w)
			if stem == wn || stem == pluralSwap(wn) || stem == singularize(wn) {
				add(pref + wn)
			}
		}
		add(pref + stem)
		add(pref + pluralSwap(stem))
	}
	return out
}

// fuzzyTableMatch finds the closest live table for a requested name. An exact
// normalized hit wins; otherwise the shortest containment match is returned.
func fuzzyTableMatch(tables []string, requested string, candidates []string) string {
	req := normIdent(requested)
	targets := map[string]bool{req: true}
	for _, c := range candidates {
		targets[normIdent(c)] = true
	}
	for _, t := range tables {
		if targets[normIdent(t)] {
			return t
		}
	}
	best, bestLen := "", 0
	for _, t := range tables {
		n := normIdent(t)
		if n == "" {
			continue
		}
		if strings.Contains(n, req) || strings.Contains(req, n) {
			if best == "" || len(n) < bestLen {
				best, bestLen = t, len(n)
			}
		}
	}
	return best
}

// ResolutionError describes why a table (or its column set) could not be
// resolved. It carries every diagnostic needed to tell the operator what was
// probed and why it failed.
type ResolutionError struct {
	Database       string
	Table          string
	Technique      string
	Candidates     []string
	InfoSchemaOK   bool
	TablesSeen     []string
	ExtractionErr  error
	AttemptedQuery string
	ErrorSnippet   string
	// probedExisting records that the requested table (tested case-neutrally
	// against the live schema list) does not actually exist in this database.
	probedExisting bool
}

func (e *ResolutionError) Error() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "cannot resolve table %s.%s: no column set found for any probed name", e.Database, e.Table)
	if e.Technique != "" {
		fmt.Fprintf(&sb, "\n  extraction technique: %s", e.Technique)
	}
	if len(e.Candidates) > 0 {
		sb.WriteString("\n  probed table names: " + strings.Join(e.Candidates, ", "))
	}
	if e.AttemptedQuery != "" {
		sb.WriteString("\n  representative query: " + e.AttemptedQuery)
	}
	fmt.Fprintf(&sb, "\n  information_schema accessible: %t", e.InfoSchemaOK)
	if e.probedExisting {
		fmt.Fprintf(&sb, "\n  note: table %q does not exist in database %q (case-insensitive check against the live table list)", e.Table, e.Database)
	}
	if len(e.TablesSeen) > 0 {
		sb.WriteString("\n  tables currently visible in " + e.Database + ": " + strings.Join(e.TablesSeen, ", "))
	}
	if e.ExtractionErr != nil {
		sb.WriteString("\n  extraction failure: " + e.ExtractionErr.Error())
	}
	if e.ErrorSnippet != "" {
		sb.WriteString("\n  raw DBMS error observed: " + e.ErrorSnippet)
	}
	sb.WriteString("\n  suggestion: confirm the database and table names, or run \"--dbs\" / \"--tables -D <db>\" to list what is reachable")
	return sb.String()
}

// listColumnsRaw is the un-resolved column lister used internally (resolve.go
// and dump flow call it with validated db/table names).
func (e *Enumerator) listColumnsRaw(ctx context.Context, database, table string) ([]Column, error) {
	if e.queries == nil || e.queries.ListCols == nil {
		return nil, errors.New("column listing not supported for this DBMS")
	}
	ui.Infof("fetching columns for table '%s' in database '%s'", table, database)
	rows, err := e.ext.ExtractRows(ctx, e.queries.ListCols(database, table), 2)
	if err != nil {
		return nil, err
	}
	out := make([]Column, 0, len(rows))
	for _, r := range rows {
		if len(r) > 0 && r[0] != "" {
			c := Column{Name: r[0]}
			if len(r) > 1 {
				c.Type = r[1]
			}
			out = append(out, c)
			ui.Infof("retrieved: '%s'", c.Name)
			if c.Type != "" {
				ui.Infof("retrieved: '%s'", c.Type)
			}
		}
	}
	return out, nil
}

// listTablesRaw is the un-resolved table lister.
func (e *Enumerator) listTablesRaw(ctx context.Context, database string) ([]string, error) {
	if e.queries == nil || e.queries.ListTables == nil {
		return nil, errors.New("table listing not supported for this DBMS")
	}
	ui.Infof("fetching tables in database '%s'", database)
	rows, err := e.ext.ExtractRows(ctx, e.queries.ListTables(database), 1)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if len(r) > 0 && r[0] != "" {
			out = append(out, r[0])
			ui.Infof("retrieved: '%s'", r[0])
		}
	}
	return out, nil
}

// countRowsRaw is the un-resolved row counter.
func (e *Enumerator) countRowsRaw(ctx context.Context, database, table string) (int64, error) {
	if e.queries == nil || e.queries.CountRows == nil {
		return 0, errors.New("row counting not supported for this DBMS")
	}
	return e.queryInt(ctx, e.queries.CountRows(database, table))
}

// cacheColumns records a successfully resolved column set.
func (e *Enumerator) cacheColumns(db, table string, cols []Column) {
	e.lastResolvedDB = db
	e.lastResolvedTable = table
	e.lastResolvedColumns = append([]Column(nil), cols...)
}

// ResolveTable maps the user's (database, table) request onto a real table the
// backend can read columns from. It probes common spellings of the requested
// name, and only when the exact/plural attempts are empty does it fuzzy-match
// against the live information_schema table list. It returns the resolved
// database and table, or a ResolutionError with full diagnostics.
func (e *Enumerator) ResolveTable(ctx context.Context, database, table string) (string, string, error) {
	table = strings.Trim(strings.TrimSpace(table), "`\"[] ")
	if table == "" {
		return "", "", errors.New("no table name given")
	}
	db := strings.TrimSpace(database)
	if db == "" {
		cur, err := e.CurrentDatabase(ctx)
		if err != nil {
			return "", "", fmt.Errorf("resolve current database: %w", err)
		}
		db = cur
	}

	re := &ResolutionError{Database: db, Table: table}
	re.Candidates = tableCandidates(table)

	var extractionErr error
	for _, cand := range re.Candidates {
		cols, err := e.listColumnsRaw(ctx, db, cand)
		if err != nil {
			if extractionErr == nil {
				extractionErr = err
				re.ErrorSnippet = e.ext.LastErrorSnippet()
			}
			continue
		}
		if len(cols) > 0 {
			e.cacheColumns(db, cand, cols)
			return db, cand, nil
		}
	}

	// Every exact attempt returned no columns: fall back to a fuzzy match
	// against the live table list. This runs even when a hard extraction error
	// occurred, because listing tables reads a different region of the schema
	// and may still succeed — it also produces far more actionable errors.
	if tables, lerr := e.listTablesRaw(ctx, db); lerr == nil {
		re.InfoSchemaOK = true
		re.TablesSeen = tables
		if len(re.TablesSeen) > 24 {
			re.TablesSeen = append([]string(nil), re.TablesSeen[:24]...)
		}
		existing := normIdentSet(tables)
		if hit := fuzzyTableMatch(tables, table, re.Candidates); hit != "" {
			if cols, cerr := e.listColumnsRaw(ctx, db, hit); cerr == nil && len(cols) > 0 {
				e.cacheColumns(db, hit, cols)
				return db, hit, nil
			}
		}
		if len(re.TablesSeen) > 0 && !existing[normIdent(table)] {
			re.probedExisting = true // requested table is absent from the schema
		}
	}

	// Last resort for a fully schema-blocked backend: fall back to the
	// schema-agnostic + brute-force column chain against the requested name.
	if cols, ferr := e.resolveColumnSet(ctx, db, table); ferr == nil && len(cols) > 0 {
		e.progressf("[table] schema probing blocked; accepted %q by %d column(s)", table, len(cols))
		e.cacheColumns(db, table, cols)
		return db, table, nil
	}

	re.ExtractionErr = extractionErr
	re.Technique = e.ext.Technique()
	if e.queries != nil && e.queries.ListCols != nil {
		re.AttemptedQuery = e.queries.ListCols(db, table)
	}
	return "", "", re
}

// normIdentSet builds a normalized identifier lookup set.
func normIdentSet(list []string) map[string]bool {
	out := make(map[string]bool, len(list))
	for _, s := range list {
		out[normIdent(s)] = true
	}
	return out
}
