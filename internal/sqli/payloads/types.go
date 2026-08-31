// Package payloads implements Vexor's expanded SQL injection payload matrix:
// a database-version / clause / technique / wrapper aware registry of 220+
// distinct test vectors, a level-and-risk driven selector, and a wrapper
// expansion engine that turns each base template into many concrete probes.
//
// The matrix is an original Go implementation (templates, metadata and
// expansion logic are authored here, not copied from other tools).
package payloads

import (
	"strings"
)

// Technique identifies the detection family a payload belongs to.
type Technique string

// Detection technique families.
const (
	TechBoolean Technique = "boolean"
	TechError   Technique = "error"
	TechTime    Technique = "time"
	TechUnion   Technique = "union"
	TechStacked Technique = "stacked"
	TechInline  Technique = "inline"
	TechOOB     Technique = "oob"
)

// Clause identifies the SQL clause the payload is designed to be injected
// into. Generic payloads are agnostic of clause.
type Clause string

// Supported clauses.
const (
	ClauseWhere   Clause = "where"
	ClauseHaving  Clause = "having"
	ClauseOrderBy Clause = "orderby"
	ClauseGroupBy Clause = "groupby"
	ClauseLimit   Clause = "limit"
	ClauseGeneric Clause = "generic"
)

// Canonical DBMS identifiers used by the matrix.
const (
	DBMySQL    = "mysql"
	DBPostgres = "postgres"
	DBMSSQL    = "mssql"
	DBOracle   = "oracle"
	DBSQLite   = "sqlite"
	DBGeneric  = "generic"
)

// AllTechniques lists every technique family in declaration order.
var AllTechniques = []Technique{
	TechBoolean,
	TechError,
	TechTime,
	TechUnion,
	TechStacked,
	TechInline,
	TechOOB,
}

// Prefix / suffix mode constants used to classify how a payload attaches to
// the original value.
const (
	// PrefixModeValue: the payload replaces / carries the {orig} value itself.
	PrefixModeValue = "value"
	// PrefixModeAnd: the payload prepends an AND operator.
	PrefixModeAnd = "and"
	// PrefixModeOr: the payload prepends an OR operator.
	PrefixModeOr = "or"
	// PrefixModeReplace: the payload stands in for the whole value (parameter
	// replacement / table or column name contexts).
	PrefixModeReplace = "replace"

	// SuffixModeNone: no trailing terminator.
	SuffixModeNone = "none"
	// SuffixModeComment: payload ends with an SQL comment.
	SuffixModeComment = "comment"
	// SuffixModeTerm: payload ends with a statement terminator (;).
	SuffixModeTerm = "term"
)

// Payload is one distinct test vector in the matrix. Every template may carry
// placeholders that are filled at expansion time via Macro.
type Payload struct {
	// ID is a stable, unique identifier for the payload.
	ID string
	// Title is a human readable, sqlmap-style descriptive title.
	Title string
	// DBMS is one of the DBMySQL..DBGeneric constants.
	DBMS string
	// Technique is the detection family.
	Technique Technique
	// MinVersion / MaxVersion bound the target engine versions (optional).
	MinVersion string
	MaxVersion string
	// Clause is the SQL clause the payload targets.
	Clause Clause
	// Risk is 1..3 (1 safe, 3 aggressive/noisy).
	Risk int
	// Level is the minimum --level at which this payload is considered.
	Level int
	// PrefixMode / SuffixMode describe how the payload attaches to the value.
	PrefixMode string
	SuffixMode string
	// Template carries the SQL skeleton with placeholders.
	Template string
	// Confidence is the base confidence weight (0..100).
	Confidence int
}

// Macro holds the runtime values substituted into payload placeholders.
type Macro struct {
	Orig     string // {orig}    - original parameter value
	Query    string // {query}   - a subquery / expression to leak
	Seconds  string // {seconds} - delay magnitude in seconds
	Marker   string // {marker}  - reflection marker for UNION
	ColCount string // {colcount}- precomputed UNION column list
	Domain   string // {domain}  - OOB callback domain
	M1       string // {m1}      - hex delimiter marker (error payloads), e.g. "7e"
	M2       string // {m2}      - closing hex delimiter marker
}

// DefaultMacro returns a Macro with sensible defaults for expansion when a
// caller only cares about the wrapper output, not live injection values.
func DefaultMacro() Macro {
	return Macro{
		Seconds:  "5",
		Marker:   "7343237",
		ColCount: "NULL",
		Domain:   "vexor.example.com",
		M1:       "7e",
		M2:       "7e",
	}
}

// Fill substitutes every known placeholder in tpl with values from m.
// Unused / unknown placeholders are left untouched so callers can inspect the
// raw skeleton if needed.
func Fill(tpl string, m Macro) string {
	r := strings.NewReplacer(
		"{orig}", m.Orig,
		"{query}", m.Query,
		"{seconds}", m.Seconds,
		"{marker}", m.Marker,
		"{colcount}", m.ColCount,
		"{domain}", m.Domain,
		"{m1}", m.M1,
		"{m2}", m.M2,
	)
	return r.Replace(tpl)
}

// RenderedPayload is the result of expanding a base payload through one
// wrapper. It pairs the source metadata (for titles / selection) with the final
// concrete injection value.
type RenderedPayload struct {
	// Source references the base template that produced this probe.
	Source Payload
	// Wrapper is a short human description of the applied wrapper, e.g.
	// "single-quote + comment".
	Wrapper string
	// Rendered is the fully-substituted injection value.
	Rendered string
	// Prefix / Suffix are the wrapper fragments around the core payload.
	Prefix string
	Suffix string
}

// Normalize maps sibling / legacy DB names onto the canonical set used by the
// matrix selector.
func Normalize(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "mariadb", "mysql":
		return DBMySQL
	case "postgres", "postgresql", "pgsql", "redshift":
		return DBPostgres
	case "mssql", "sqlserver", "sql server", "sybase", "sap ase":
		return DBMSSQL
	case "oracle", "oracledb":
		return DBOracle
	case "sqlite", "sqlite3":
		return DBSQLite
	case "generic", "db2", "firebird", "informix", "*", "":
		return DBGeneric
	default:
		return strings.ToLower(strings.TrimSpace(name))
	}
}
