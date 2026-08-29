package injection

import "strings"

// The encoding functions escape only the characters that would break the
// surrounding container's syntax. Payload syntax (quotes, parens, --, etc.)
// is deliberately left intact so it reaches the SQL parser unchanged.

// encQuery encodes a value embedded into a URL query string.
func encQuery(v string) string {
	return encodeBytes(v, map[byte]bool{
		' ': true, '&': true, '=': true, '#': true, '+': true, '\t': true,
	})
}

// encForm encodes a value embedded into a form-encoded body. Space becomes +.
func encForm(v string) string {
	return encodeBytesPlus(v)
}

// encPath encodes a value embedded into a URL path.
func encPath(v string) string {
	return encodeBytes(v, map[byte]bool{
		' ': true, '?': true, '#': true, '\t': true, '\n': true, '\r': true,
	})
}

// encCookie encodes a value embedded into a Cookie header.
func encCookie(v string) string {
	return encodeBytes(v, map[byte]bool{
		' ': true, ';': true, ',': true, '&': true, '=': true, '#': true, '\t': true,
	})
}

// encHeader sanitises a value placed into an arbitrary header, preventing
// request smuggling via injected CR/LF.
func encHeader(v string) string {
	return encodeBytes(v, map[byte]bool{
		'\r': true, '\n': true, '\t': true,
	})
}

func encodeBytes(s string, special map[byte]bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || special[c] {
			b.WriteByte('%')
			b.WriteString(hexUpper(c))
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func encodeBytesPlus(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ':
			b.WriteByte('+')
		case c < 0x20 || c == '&' || c == '=' || c == '#' || c == '+':
			b.WriteByte('%')
			b.WriteString(hexUpper(c))
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func hexUpper(b byte) string {
	const digits = "0123456789ABCDEF"
	return string([]byte{digits[b>>4], digits[b&0x0F]})
}
