package tamper

// isURLSafe reports whether the byte can be emitted raw in a URL-encoded
// context without being percent-encoded. Alphanumerics and a small set of
// safe punctuation are left raw so the payload still reads as SQL.
func isURLSafe(c byte) bool {
	return isAlphaByte(c) || isASCIIDigit(c) ||
		c == '_' || c == '-' || c == '.' || c == '~' ||
		c == '/' || c == '?' || c == '&' || c == '=' || c == '#' ||
		c == ':' || c == '@' || c == '+' || c == '$'
}

// isPlainASCII reports whether the rune is a printable ASCII character that
// should be left unescaped.
func isPlainASCII(r rune) bool {
	return r >= 0x20 && r <= 0x7e
}

// isAlphaByte reports whether c is an ASCII letter.
func isAlphaByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// isASCIIDigit reports whether c is an ASCII digit.
func isASCIIDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

// isKeywordChar reports whether c belongs to a SQL keyword token.
func isKeywordChar(c byte) bool {
	return isAlphaByte(c) || isASCIIDigit(c) || c == '_'
}
