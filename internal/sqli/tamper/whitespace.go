package tamper

import "strings"

// space2tab replaces spaces with a horizontal tab, e.g. "SELECT\t1\tFROM".
func space2tab(payload string) string {
	var sb strings.Builder
	sb.Grow(len(payload))
	for _, r := range payload {
		if isSpace(r) {
			sb.WriteByte('\t')
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// space2newline replaces spaces with a newline, e.g. "SELECT\n1\nFROM".
func space2newline(payload string) string {
	var sb strings.Builder
	sb.Grow(len(payload))
	for _, r := range payload {
		if isSpace(r) {
			sb.WriteByte('\n')
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// space2randomblank replaces each space with a random whitespace character
// (tab, newline, vertical tab, form feed, carriage return, space, nbsp).
func space2randomblank(payload string) string {
	var sb strings.Builder
	sb.Grow(len(payload))
	for _, r := range payload {
		if isSpace(r) {
			sb.WriteByte(randWhitespace())
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// multiplespaces inserts an extra random number of spaces after each existing
// space, producing "SELECT    1    FROM". This evades filters that collapse
// only a fixed number of spaces.
func multiplespaces(payload string) string {
	var sb strings.Builder
	sb.Grow(len(payload) + 16)
	for _, r := range payload {
		if isSpace(r) {
			n := 1 + randSource().IntN(5)
			for i := 0; i < n; i++ {
				sb.WriteByte(' ')
			}
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// overlongutf8 replaces whitespace bytes with overlong UTF-8 sequences that
// decode to the same character. Filters that never decode overlong forms will
// see the payload as harmless bytes.
func overlongutf8(payload string) string {
	var sb strings.Builder
	sb.Grow(len(payload))
	for _, r := range payload {
		if r == ' ' || r == '\t' {
			sb.WriteString(randOverlongWhitespace())
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
