// Package dbms holds hardcoded per-database payload sets used by the detection
// techniques, plus the fingerprinting logic that narrows which set applies.
package dbms

import (
	"fmt"
	"strings"
)

// DB names as reported to users.
const (
	MySQL    = "mysql"
	Postgres = "postgres"
	MSSQL    = "mssql"
	Oracle   = "oracle"
	SQLite   = "sqlite"
	Generic  = "generic"
)

// Marker is an unlikely number embedded in a UNION select column to detect
// printable (reflected) columns.
const Marker = "7343237"

// BoolPair is a true / false expression injected in place of the parameter
// value.
type BoolPair struct {
	True  string
	False string
}

// TimeTpl is a template that delays the query; {orig} and {delay} macros exist.
type TimeTpl struct {
	Payload string
	Risk    int // 1 = light, 2 = medium, 3 = heavy (only used at matching risk level)
}

// UnionTemplates holds the two payload families for UNION-based reflection.
type UnionTemplates struct {
	OrderBy     []string // templates with {orig} and {n}
	UnionSelect []string // templates with {orig} and {cols}
}

// Payloads is the complete detection payload set for one DBMS.
type Payloads struct {
	Name      string
	Boolean   []BoolPair
	Inline    []BoolPair
	Time      []TimeTpl
	Error     []string
	Union     UnionTemplates
	Stacked   []TimeTpl
	OOB       []string
	StackedOK bool // supports statement stacking
}

// Expand substitutes payload placeholders in a template using the given
// macros. Unused macros are left untouched.
func Expand(tpl string, m Macros) string {
	return expand(tpl, m)
}

// ExpandOrig fills only the {orig} macro — the common case for boolean/error
// payloads that carry no other macros.
func ExpandOrig(tpl, orig string) string {
	return expand(tpl, Macros{Orig: orig})
}

// Macros substitutes payload placeholders.
type Macros struct {
	Orig   string
	Delay  string
	Domain string
	Unc    string
	Cols   string
	N      int
}

func expand(tpl string, m Macros) string {
	r := strings.NewReplacer(
		"{orig}", m.Orig,
		"{delay}", m.Delay,
		"{domain}", m.Domain,
		"{unc}", m.Unc,
		"{cols}", m.Cols,
	)
	out := r.Replace(tpl)
	if m.N > 0 {
		out = strings.ReplaceAll(out, "{n}", fmt.Sprintf("%d", m.N))
	}
	return out
}

// registry of payload sets, keyed by normalized name.
var registry = map[string]*Payloads{}

func register(p *Payloads) {
	if p != nil && p.Name != "" {
		registry[p.Name] = p
	}
}

// Get returns the payload set for a normalized DB name (or nil).
func Get(name string) *Payloads {
	return registry[NormalizeName(name)]
}

// All returns the payload sets in the order they should be tried when the DB
// is unknown.
func All() []*Payloads {
	names := []string{MySQL, Postgres, MSSQL, Oracle, SQLite}
	out := make([]*Payloads, 0, len(names)+1)
	for _, n := range names {
		if p := registry[n]; p != nil {
			out = append(out, p)
		}
	}
	return out
}

// NormalizeName maps sibling / legacy product names onto the canonical set.
func NormalizeName(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "mariadb", "mysql", "mariadbreader":
		return MySQL
	case "postgres", "postgresql", "pgsql", "redshift", "gres":
		return Postgres
	case "mssql", "sqlserver", "sql server", "sybase", "sap", "ase", "sapase", "sap ase":
		return MSSQL
	case "oracle", "oracledb":
		return Oracle
	case "sqlite", "sqlite3":
		return SQLite
	case "db2", "firebird", "informix", "none", "unknown", "generic":
		return Generic
	default:
		return strings.ToLower(strings.TrimSpace(name))
	}
}
