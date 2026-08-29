package tamper

import (
	"strings"
	"unicode"
)

// randomcase mutates each alphabetic letter to a random upper/lowercase
// variant, producing payloads like "SeLeCt 1 FrOm". This defeats naive
// case-sensitive keyword filters.
func randomcase(payload string) string {
	var sb strings.Builder
	sb.Grow(len(payload))
	for _, r := range payload {
		if unicode.IsLetter(r) {
			if randBool() {
				r = unicode.ToUpper(r)
			} else {
				r = unicode.ToLower(r)
			}
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// lowercase converts every alphabetic character to lowercase, producing
// "select 1 from". Useful when an upper/lower mix is uncommon or when a
// filter only blocks a specific casing.
func lowercase(payload string) string {
	return strings.ToLower(payload)
}

// uppercase converts every alphabetic character to uppercase, producing
// "SELECT 1 FROM".
func uppercase(payload string) string {
	return strings.ToUpper(payload)
}

// swapcase inverts the case of every alphabetic character, producing
// "sELECT 1 fROM".
func swapcase(payload string) string {
	var sb strings.Builder
	sb.Grow(len(payload))
	for _, r := range payload {
		if unicode.IsUpper(r) {
			r = unicode.ToLower(r)
		} else if unicode.IsLower(r) {
			r = unicode.ToUpper(r)
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
