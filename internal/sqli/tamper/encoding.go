package tamper

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// charencode URL-encodes every non-alphanumeric byte, e.g. "SELECT" ->
// "%53%45%4C%45%43%54". It does not encode characters that are safe in most
// SQL contexts so the payload still parses after WAF decoding.
func charencode(payload string) string {
	var sb strings.Builder
	for i := 0; i < len(payload); i++ {
		c := payload[i]
		if isURLSafe(c) {
			sb.WriteByte(c)
		} else {
			fmt.Fprintf(&sb, "%%%02X", c)
		}
	}
	return sb.String()
}

// chardoubleencode double URL-encodes every non-alphanumeric byte, e.g.
// "SELECT" -> "%2553%2545%254C%2545%2543%2554". Bypasses filters that decode
// only one level.
func chardoubleencode(payload string) string {
	var sb strings.Builder
	for i := 0; i < len(payload); i++ {
		c := payload[i]
		if isURLSafe(c) {
			sb.WriteByte(c)
		} else {
			fmt.Fprintf(&sb, "%%25%02X", c)
		}
	}
	return sb.String()
}

// charunicodeencode encodes non-ASCII-safe bytes as \uXXXX escapes, e.g.
// "SELECT" -> "\u0053\u0045\u004C\u0045\u0043\u0054".
func charunicodeencode(payload string) string {
	var sb strings.Builder
	for _, r := range payload {
		if isPlainASCII(r) {
			sb.WriteRune(r)
		} else {
			fmt.Fprintf(&sb, "\\u%04X", r)
		}
	}
	return sb.String()
}

// charunicodeescape encodes bytes as %uXXXX escapes, e.g. "SELECT" ->
// "%u0053%u0045%u004C%u0045%u0043%u0054".
func charunicodeescape(payload string) string {
	var sb strings.Builder
	for _, r := range payload {
		if isPlainASCII(r) {
			sb.WriteRune(r)
		} else {
			fmt.Fprintf(&sb, "%%u%04X", r)
		}
	}
	return sb.String()
}

// base64encode base64-encodes the entire payload, e.g. "SELECT 1" ->
// "U0VMRUNUIDE=". Must be chained LAST.
func base64encode(payload string) string {
	return base64.StdEncoding.EncodeToString([]byte(payload))
}

// hex2char converts consecutive hex literal tokens like "0x414243" into a
// CONCAT of CHAR() calls where feasible. For arbitrary payloads it leaves the
// bytes that are not hex literals untouched. This converts quoted hex strings
// into an equivalent character expression.
func hex2char(payload string) string {
	// Heuristic: if the payload already contains 0x... hex literals, wrap them
	// into CONCAT(CHAR(...)) form. Otherwise leave it unchanged to avoid
	// breaking valid SQL.
	lower := strings.ToLower(payload)
	if !strings.Contains(lower, "0x") {
		return payload
	}
	const hexDigits = "0123456789abcdefABCDEF"
	var sb strings.Builder
	i := 0
	n := len(payload)
	for i < n {
		// Detect a 0x / 0X token.
		if i+1 < n && payload[i] == '0' && (payload[i+1] == 'x' || payload[i+1] == 'X') {
			j := i + 2
			start := j
			for j < n && strings.IndexByte(hexDigits, payload[j]) >= 0 {
				j++
			}
			if j > start {
				hx := payload[start:j]
				// Even-length hex resolves directly to characters.
				if len(hx)%2 == 0 {
					var hexBytes strings.Builder
					hexBytes.WriteString("CHAR(")
					for k := 0; k < len(hx); k += 2 {
						if k > 0 {
							hexBytes.WriteString(",")
						}
						dec, _ := strconv.ParseInt(hx[k:k+2], 16, 32)
						hexBytes.WriteString(strconv.FormatInt(dec, 10))
					}
					hexBytes.WriteString(")")
					sb.WriteString(hexBytes.String())
				} else {
					sb.WriteString(payload[i : j+1-1])
					sb.WriteString(" ")
				}
				i = j
				continue
			}
		}
		sb.WriteByte(payload[i])
		i++
	}
	return sb.String()
}

// htmlencode encodes every non-ASCII byte as an HTML numeric entity, e.g.
// "SELECT" -> "&#83;&#69;&#76;&#69;&#67;&#84;".
func htmlencode(payload string) string {
	var sb strings.Builder
	for _, r := range payload {
		if isPlainASCII(r) {
			sb.WriteRune(r)
		} else {
			fmt.Fprintf(&sb, "&#%d;", r)
		}
	}
	return sb.String()
}

// percentage inserts a '%' between every alphabetic character, e.g. "SELECT"
// -> "%S%E%L%E%C%T". Evades filters matching contiguous keyword strings.
func percentage(payload string) string {
	var sb strings.Builder
	lastAlpha := false
	for _, r := range payload {
		if isAlphaByte(byte(r)) {
			if lastAlpha {
				sb.WriteByte('%')
			}
			sb.WriteRune(r)
			lastAlpha = true
		} else {
			sb.WriteRune(r)
			lastAlpha = false
		}
	}
	return sb.String()
}

// apostrophenullencode encodes the apostrophe as %00%27. Some filters block a
// bare single quote but allow percent-encoded forms.
func apostrophenullencode(payload string) string {
	return strings.ReplaceAll(payload, "'", "%00%27")
}

// apostrophemask replaces single quotes with their full-width Unicode
// equivalent %EF%BC%87 (the ' character). Many WAFs do not recognise it.
func apostrophemask(payload string) string {
	return strings.ReplaceAll(payload, "'", "%EF%BC%87")
}

// equaltolike rewrites '=' into an equivalent LIKE comparison, e.g.
// "WHERE x=1" -> "WHERE x LIKE 1". Guards against token filters for '='.
func equaltolike(payload string) string {
	return strings.ReplaceAll(payload, "=", " LIKE ")
}

// equaltorlike rewrites '=' into an equivalent RLIKE comparison, e.g.
// "WHERE x=1" -> "WHERE x RLIKE 1".
func equaltorlike(payload string) string {
	return strings.ReplaceAll(payload, "=", " RLIKE ")
}

// greatest replaces '>' comparison with a GREATEST() function that is
// effectively always true, e.g. "x > 1" -> "GREATEST(x,1) > 0". This evades
// filters matching on the bare '>' operator.
func greatest(payload string) string {
	return strings.ReplaceAll(payload, ">", " GREATEST ")
}

// between rewrites a "> n" into a BETWEEN cartesian range, e.g. "x > 5" ->
// "x BETWEEN 6 AND 999". Filters matching the '>' operator are bypassed.
func between(payload string) string {
	// Replace only simple "> <integer>" occurrences.
	var sb strings.Builder
	i := 0
	for i < len(payload) {
		if payload[i] == '>' {
			j := i + 1
			for j < len(payload) && payload[j] == ' ' {
				j++
			}
			start := j
			for j < len(payload) && isASCIIDigit(payload[j]) {
				j++
			}
			if j > start {
				val, _ := strconv.Atoi(payload[start:j])
				sb.WriteString(" BETWEEN ")
				sb.WriteString(strconv.Itoa(val + 1))
				sb.WriteString(" AND 999 ")
				i = j
				continue
			}
		}
		sb.WriteByte(payload[i])
		i++
	}
	return sb.String()
}
