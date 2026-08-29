package enumeration

import (
	"context"
	"strings"
)

// Column describes one table column.
type Column struct {
	Name string
	Type string // best-effort data type when available
}

// SchemaInfo is a per-database summary produced by GetSchema.
type SchemaInfo struct {
	Database string      `json:"database"`
	Tables   []TableInfo `json:"tables"`
}

// TableInfo is a per-table summary produced by GetSchema.
type TableInfo struct {
	Name    string   `json:"name"`
	Rows    int64    `json:"rows"`
	Columns []Column `json:"columns"`
}

// GetSchema enumerates every table and, lazily, their columns + row counts for
// the given database. Column/row data is gathered only for tables whose size is
// below maxRows when maxRows > 0, to avoid hammering huge tables.
func (e *Enumerator) GetSchema(ctx context.Context, database string, maxRows int64) (*SchemaInfo, error) {
	if strings.TrimSpace(database) == "" {
		cur, err := e.CurrentDatabase(ctx)
		if err != nil {
			return nil, err
		}
		database = cur
	}
	tables, err := e.ListTables(ctx, database)
	if err != nil {
		return nil, err
	}
	info := &SchemaInfo{Database: database}
	for _, t := range tables {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		ti := TableInfo{Name: t}
		cols, err := e.ListColumns(ctx, database, t)
		if err != nil {
			cols = nil
		}
		ti.Columns = cols
		if maxRows <= 0 {
			cnt, err := e.CountRows(ctx, database, t)
			if err == nil {
				ti.Rows = cnt
			}
		}
		info.Tables = append(info.Tables, ti)
	}
	return info, nil
}

// TableRowCount is a convenience returning just the row count of one table.
func (e *Enumerator) TableRowCount(ctx context.Context, database, table string) (int64, error) {
	return e.CountRows(ctx, database, table)
}
