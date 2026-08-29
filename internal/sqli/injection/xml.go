package injection

import (
	"strings"
)

// xmlSpan is a replaceable text position inside an XML document: either the
// text content of an element or the value of an attribute.
type xmlSpan struct {
	key   string // element tag or attribute name, used as the point name
	start int
	end   int
	attr  bool
}

// scanXML collects meaningful text-run and attribute-value spans in an XML
// document. Offsets are absolute into the input. Markup that carries no data
// (comments, CDATA, processing instructions, doctypes) is skipped.
func scanXML(data []byte) []xmlSpan {
	var spans []xmlSpan
	lastTag := ""
	p := 0
	n := len(data)

	for p < n {
		if data[p] != '<' {
			// Accumulate a text run, then trim surrounding whitespace.
			start := p
			for p < n && data[p] != '<' {
				p++
			}
			ts, te := start, p
			for ts < te && isXMLWS(data[ts]) {
				ts++
			}
			for te > ts && isXMLWS(data[te-1]) {
				te--
			}
			if te > ts && lastTag != "" {
				spans = append(spans, xmlSpan{key: nameOf(lastTag), start: ts, end: te})
			}
			continue
		}
		closeIdx := indexByteFrom(data, '>', p+1)
		if closeIdx < 0 {
			break
		}
		handleTag(data, p+1, closeIdx, &lastTag, &spans)
		p = closeIdx + 1
	}
	return spans
}

func indexByteFrom(data []byte, b byte, from int) int {
	for i := from; i < len(data); i++ {
		if data[i] == b {
			return i
		}
	}
	return -1
}

func isXMLWS(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// handleTag interprets the byte span of one tag body (between < and >),
// records attribute value spans with absolute offsets and updates the last
// element name seen.
func handleTag(data []byte, start, end int, lastTag *string, spans *[]xmlSpan) {
	// Locate the tag name.
	nameEnd := start
	for nameEnd < end {
		c := data[nameEnd]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '/' || c == '!' || c == '?' {
			break
		}
		nameEnd++
	}
	if nameEnd == start {
		return
	}
	first := data[start]
	switch {
	case first == '!':
		return // comment / CDATA / doctype
	case first == '?':
		return // processing instruction
	case data[start] == '/':
		return // closing tag
	}

	name := string(data[start:nameEnd])
	if !strings.HasSuffix(name, "/") {
		*lastTag = name
	}

	// Scan attributes.
	i := nameEnd
	for i < end {
		for i < end && isXMLWS(data[i]) {
			i++
		}
		if i >= end {
			return
		}
		attrNameStart := i
		for i < end {
			c := data[i]
			if c == '=' || isXMLWS(c) {
				break
			}
			i++
		}
		attrName := string(data[attrNameStart:i])
		for i < end && (isXMLWS(data[i]) || data[i] == '=') {
			i++
		}
		if i >= end || (data[i] != '"' && data[i] != '\'') {
			return
		}
		quote := data[i]
		valStart := i + 1
		endQ := indexByteFrom(data, quote, valStart)
		if endQ < 0 || endQ >= end {
			return
		}
		if attrName != "" {
			*spans = append(*spans, xmlSpan{
				key:   nameOf(attrName),
				start: valStart,
				end:   endQ,
				attr:  true,
			})
		}
		i = endQ + 1
	}
}

// nameOf returns the last path component of a dotted name.
func nameOf(s string) string {
	if i := strings.LastIndex(s, "."); i >= 0 {
		return s[i+1:]
	}
	return s
}

// encXML escapes characters that would otherwise break the document structure.
func encXML(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
