// Package injection models injection points (parameters, body fields,
// headers, cookies, path segments and explicit `*` markers) and renders
// per-test requests from a base request.
package injection

import (
	"bytes"
	"strings"
)

// Marker is the character a user embeds in a URL, header or body to force an
// injection position.
const Marker = "*"

// Template is a string with zero or more * markers. Render keeps one marker
// populated and empties the rest, so each marker is exercised independently
// while the document stays syntactically valid.
type Template struct {
	parts []string
}

// NewTemplate splits raw on the marker character, preserving empties so that
// round-tripping reconstructs the original exactly.
func NewTemplate(raw string) *Template {
	return &Template{parts: strings.Split(raw, Marker)}
}

// HasMarkers reports whether the template contains at least one marker.
func (t *Template) HasMarkers() bool {
	return len(t.parts) > 1
}

// Render returns the template with the marker at idx replaced by value and
// every other marker emptied.
func (t *Template) Render(idx int, value string) string {
	var b bytes.Buffer
	for i, p := range t.parts {
		b.WriteString(p)
		if i < len(t.parts)-1 {
			if i == idx {
				b.WriteString(value)
			}
		}
	}
	return b.String()
}

// RenderAllEmpty returns the template with every marker emptied. This is used
// for the clean (baseline) request when markers are present.
func (t *Template) RenderAllEmpty() string {
	return strings.Join(t.parts, "")
}
