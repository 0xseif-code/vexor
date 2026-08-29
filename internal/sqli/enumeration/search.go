package enumeration

import (
	"context"
	"regexp"
	"strings"
)

// ColumnMatch is a search hit locating a column across databases/tables.
type ColumnMatch struct {
	Database string
	Table    string
	Column   string
}

// SearchDatabases returns database/schema names matching the pattern. The
// pattern supports `*` wildcards and is matched case-insensitively.
func (e *Enumerator) SearchDatabases(ctx context.Context, pattern string) ([]string, error) {
	re, err := globRegex(pattern)
	if err != nil {
		return nil, err
	}
	dbs, err := e.ListDatabases(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(dbs))
	for _, d := range dbs {
		if re.MatchString(d) {
			out = append(out, d)
		}
	}
	return out, nil
}

// SearchTables returns tables matching the pattern across one or all
// databases. The result maps a database name onto its matching tables.
func (e *Enumerator) SearchTables(ctx context.Context, pattern string) (map[string][]string, error) {
	re, err := globRegex(pattern)
	if err != nil {
		return nil, err
	}
	dbs, err := e.ListDatabases(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]string)
	for _, d := range dbs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		tables, err := e.ListTables(ctx, d)
		if err != nil {
			continue
		}
		for _, t := range tables {
			if re.MatchString(t) {
				out[d] = append(out[d], t)
			}
		}
	}
	return out, nil
}

// SearchColumns finds columns matching the pattern across the given database
// (or all databases when database is empty). Set searchAllTables to also scan
// every table in scope; otherwise it samples the first maxTables tables.
func (e *Enumerator) SearchColumns(ctx context.Context, database, pattern string, maxTables int) ([]ColumnMatch, error) {
	re, err := globRegex(pattern)
	if err != nil {
		return nil, err
	}
	dbs := []string{}
	if strings.TrimSpace(database) != "" {
		dbs = append(dbs, database)
	} else {
		all, err := e.ListDatabases(ctx)
		if err != nil {
			return nil, err
		}
		dbs = all
	}
	var out []ColumnMatch
	for _, d := range dbs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		tables, err := e.ListTables(ctx, d)
		if err != nil {
			continue
		}
		if maxTables > 0 && len(tables) > maxTables {
			tables = tables[:maxTables]
		}
		for _, t := range tables {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			cols, err := e.ListColumns(ctx, d, t)
			if err != nil {
				continue
			}
			for _, c := range cols {
				if re.MatchString(c.Name) {
					out = append(out, ColumnMatch{Database: d, Table: t, Column: c.Name})
				}
			}
		}
	}
	return out, nil
}

// globRegex converts a glob-ish pattern (with `*` wildcards) into a
// case-insensitive regex. A plain substring (no wildcards) is matched
// anywhere. An empty pattern matches everything.
func globRegex(pattern string) (*regexp.Regexp, error) {
	p := strings.TrimSpace(pattern)
	if p == "" || p == "*" {
		return regexp.Compile(`(?i).*`)
	}
	var sb strings.Builder
	sb.WriteString("(?i)")
	if !strings.Contains(p, "*") {
		sb.WriteString(regexp.QuoteMeta(p))
	} else {
		for _, r := range p {
			if r == '*' {
				sb.WriteString(".*")
			} else {
				sb.WriteString(regexp.QuoteMeta(string(r)))
			}
		}
	}
	return regexp.Compile(sb.String())
}
