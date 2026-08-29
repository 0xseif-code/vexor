package injection

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// jsonLeaf is a single value position inside a JSON document.
type jsonLeaf struct {
	key   string // dotted path, used as the point name
	start int    // offset of the value token (first content byte)
	end   int    // offset one past the last content byte
	str   bool   // true for string values, false for numbers
}

// scanJSON collects every string/number value in document order, with byte
// offsets spans that can be replaced in place. It does not allocate beyond the
// input, so splicing keeps the surrounding document byte-identical.
func scanJSON(data []byte) ([]jsonLeaf, error) {
	var leaves []jsonLeaf
	p := 0
	n := len(data)

	skipWS := func() {
		for p < n {
			switch data[p] {
			case ' ', '\t', '\n', '\r':
				p++
			default:
				return
			}
		}
	}

	// parseString returns the span of the raw value text between quotes and
	// leaves p just past the closing quote.
	parseString := func() (int, int, error) {
		// data[p] == '"'
		p++
		start := p
		for p < n {
			c := data[p]
			if c == '\\' {
				p += 2
				continue
			}
			if c == '"' {
				end := p
				p++
				return start, end, nil
			}
			p++
		}
		return 0, 0, fmt.Errorf("json: unterminated string at offset %d", start)
	}

	parseNumber := func() (int, int) {
		start := p
		for p < n {
			c := data[p]
			if c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E' || (c >= '0' && c <= '9') {
				p++
				continue
			}
			break
		}
		return start, p
	}

	var walk func(path string) error
	walk = func(path string) error {
		skipWS()
		if p >= n {
			return fmt.Errorf("json: unexpected end of document")
		}
		c := data[p]
		switch c {
		case '{':
			p++
			skipWS()
			if p < n && data[p] == '}' {
				p++
				return nil
			}
			for {
				skipWS()
				if p >= n || data[p] != '"' {
					return fmt.Errorf("json: expected object key at offset %d", p)
				}
				ks, ke, err := parseString()
				if err != nil {
					return err
				}
				key := string(data[ks:ke])
				child := path + "." + key
				skipWS()
				if p >= n || data[p] != ':' {
					return fmt.Errorf("json: expected ':' after key %q", key)
				}
				p++
				if err := walk(child); err != nil {
					return err
				}
				skipWS()
				if p >= n {
					return fmt.Errorf("json: unexpected end after key %q", key)
				}
				switch data[p] {
				case ',':
					p++
					continue
				case '}':
					p++
					return nil
				default:
					return fmt.Errorf("json: expected ',' or '}' at offset %d", p)
				}
			}
		case '[':
			p++
			skipWS()
			if p < n && data[p] == ']' {
				p++
				return nil
			}
			idx := 0
			for {
				child := path + "[]"
				if err := walk(child); err != nil {
					return err
				}
				idx++
				skipWS()
				if p >= n {
					return fmt.Errorf("json: unexpected end of array")
				}
				switch data[p] {
				case ',':
					p++
					continue
				case ']':
					p++
					return nil
				default:
					return fmt.Errorf("json: expected ',' or ']' at offset %d", p)
				}
			}
		case '"':
			s, e, err := parseString()
			if err != nil {
				return err
			}
			leaves = append(leaves, jsonLeaf{key: leafKey(path), start: s, end: e, str: true})
			return nil
		case 't':
			if p+4 <= n && string(data[p:p+4]) == "true" {
				p += 4
				return nil
			}
			return fmt.Errorf("json: bad literal at offset %d", p)
		case 'f':
			if p+5 <= n && string(data[p:p+5]) == "false" {
				p += 5
				return nil
			}
			return fmt.Errorf("json: bad literal at offset %d", p)
		case 'n':
			if p+4 <= n && string(data[p:p+4]) == "null" {
				p += 4
				return nil
			}
			return fmt.Errorf("json: bad literal at offset %d", p)
		default:
			if c == '-' || c == '+' || (c >= '0' && c <= '9') {
				s, e := parseNumber()
				leaves = append(leaves, jsonLeaf{key: leafKey(path), start: s, end: e, str: false})
				return nil
			}
			return fmt.Errorf("json: unexpected character %q at offset %d", string(c), p)
		}
	}

	if err := walk(""); err != nil {
		return nil, err
	}
	skipWS()
	if p != n {
		return nil, fmt.Errorf("json: trailing data at offset %d", p)
	}
	return leaves, nil
}

// leafKey maps a dotted path into a readable parameter name.
func leafKey(path string) string {
	path = strings.TrimPrefix(path, ".")
	if path == "" {
		return "value"
	}
	return path
}

// encJSON escapes the characters that would break a JSON string literal.
func encJSON(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				b.WriteString(`\u00`)
				b.WriteString(hex2(r))
			} else if unicode.IsControl(r) {
				b.WriteString(`\u`)
				b.WriteString(strconv.FormatInt(int64(r), 16))
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

func hex2(r rune) string {
	s := strconv.FormatInt(int64(r), 16)
	if len(s) == 1 {
		return "0" + s
	}
	return s
}
