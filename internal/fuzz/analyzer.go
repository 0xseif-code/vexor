package fuzz

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/bits"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/0xseif-code/vexor/internal/httpclient"
)

// baselineSignature captures the fingerprint of a "no interesting behavior"
// response. Fuzz responses that diverge from it are flagged.
type baselineSignature struct {
	StatusCode  int
	ContentLen  int64
	Words       int
	Lines       int
	Duration    time.Duration
	BodyHash256 string // SHA-256 of the first maxBodyHashBytes bytes
}

const (
	calibrationSamples = 4
	maxBodyHashBytes   = 1024
)

// baselineCapture issues several requests with random "garbage" payloads and
// distills a baseline signature. If the target is unreachable it returns a
// clear error. Varying baselines are summarized into the most common status
// with average size/duration.
type baselineCapture struct {
	injector *payloadInjector
	client   *httpclient.Client
	method   string
	headers  map[string]string
	limit    *rateController
}

// newBaselineCapture builds a capture using the configured injector and the
// request-per-iteration callback to build request signatures.
func newBaselineCapture(cfg Config, inj *payloadInjector, client *httpclient.Client, controller *rateController) *baselineCapture {
	return &baselineCapture{
		injector: inj,
		client:   client,
		method:   methodOrDefault(cfg.Method),
		headers:  inj.buildRequestHeaders(cfg),
		limit:    controller,
	}
}

// Capture probes with random payloads and returns the distilled baseline. It
// fails fast (ErrTargetUnreachable) if no request succeeds.
func (b *baselineCapture) Capture(ctx context.Context) (*baselineSignature, error) {
	var (
		byStatus   = make(map[int][]*baselineSignature)
		anySuccess bool
	)

	for i := 0; i < calibrationSamples; i++ {
		payload := map[string]string{b.injector.primaryMarker(): randomValue(16)}
		req := b.injector.render(payload)

		if b.limit != nil {
			if err := b.limit.wait(ctx); err != nil {
				return nil, err
			}
		}

		sig, err := b.probeOnce(ctx, req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		if sig == nil {
			continue
		}
		anySuccess = true
		byStatus[sig.StatusCode] = append(byStatus[sig.StatusCode], sig)
	}

	if !anySuccess {
		return nil, ErrTargetUnreachable
	}

	// Pick the status code observed most often and average its metrics.
	var (
		bestStatus int
		bestCount  int
	)
	for status, list := range byStatus {
		if len(list) > bestCount {
			bestStatus = status
			bestCount = len(list)
		}
	}
	return averageSignatures(byStatus[bestStatus]), nil
}

// probeOnce performs a single request through the httpclient and returns its
// signature, or nil if the response is binary/non-capturable.
func (b *baselineCapture) probeOnce(ctx context.Context, req *injectedRequest) (*baselineSignature, error) {
	resp, err := b.client.Do(ctx, b.method, req.url, req.body, b.headers)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	return signatureOf(resp), nil
}

// averageSignatures averages size/duration/words/lines and takes the status
// from the first signature (they all share the same status here).
func averageSignatures(list []*baselineSignature) *baselineSignature {
	if len(list) == 0 {
		return nil
	}
	out := &baselineSignature{
		StatusCode: list[0].StatusCode,
	}
	var (
		sizeSum, durationSum, wordsSum, linesSum int64
	)
	for _, s := range list {
		sizeSum += s.ContentLen
		durationSum += int64(s.Duration)
		wordsSum += int64(s.Words)
		linesSum += int64(s.Lines)
	}
	n := int64(len(list))
	out.ContentLen = sizeSum / n
	out.Duration = time.Duration(durationSum / n)
	out.Words = int(wordsSum / n)
	out.Lines = int(linesSum / n)
	// Body hash from the longest sample (most representative).
	var largest *baselineSignature
	for _, s := range list {
		if largest == nil || s.ContentLen > largest.ContentLen {
			largest = s
		}
	}
	if largest != nil {
		out.BodyHash256 = largest.BodyHash256
	}
	return out
}

// signatureOf computes a baselineSignature from a response.
func signatureOf(resp *httpclient.Response) *baselineSignature {
	return &baselineSignature{
		StatusCode:  resp.StatusCode,
		ContentLen:  int64(len(resp.Body)),
		Words:       wordCount(resp.Body),
		Lines:       lineCount(resp.Body),
		Duration:    resp.Duration,
		BodyHash256: hashPrefix(resp.Body, maxBodyHashBytes),
	}
}

func wordCount(data []byte) int {
	return len(bytes.Fields(data))
}

func lineCount(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	n := bytes.Count(data, []byte{'\n'})
	if data[len(data)-1] != '\n' {
		n++
	}
	return n
}

func hashPrefix(data []byte, n int) string {
	if len(data) > n {
		data = data[:n]
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// isProbablyBinary reports whether a response body looks like binary content
// (large run of NUL bytes or non-text high-bytes).
func isProbablyBinary(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	// Count control bytes / NULs in first 512 bytes.
	check := body
	if len(check) > 512 {
		check = check[:512]
	}
	suspicious := 0
	for _, c := range check {
		if c == 0x00 {
			suspicious++
		}
	}
	// A fraction >= 5% NUL bytes strongly suggests binary.
	return len(check) > 0 && suspicious*20 >= len(check)
}

// ---- filter matching ----

// Range represents an inclusive numeric range for word/line matching.
type Range struct {
	Min int64
	Max int64
}

// contains reports whether v falls within the range.
func (r Range) contains(v int64) bool {
	return v >= r.Min && v <= r.Max
}

// timeCriterion is a parsed --match-time / --filter-time comparator.
type timeCriterion struct {
	op  byte  // '>', '<', '='
	val int64 // milliseconds
}

// parseTimeCriterion parses values like ">2000", "<100", "=500", "200".
func parseTimeCriterion(s string) (*timeCriterion, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	op := byte('=')
	switch s[0] {
	case '>', '<', '=':
		op = s[0]
		s = s[1:]
	}
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid time criterion %q: %w", s, err)
	}
	return &timeCriterion{op: op, val: v}, nil
}

func (t *timeCriterion) matches(ms int64) bool {
	if t == nil {
		return true
	}
	switch t.op {
	case '>':
		return ms > t.val
	case '<':
		return ms < t.val
	default:
		return ms == t.val
	}
}

// analyzer encapsulates baseline comparison and user-defined filters.
type analyzer struct {
	baseline *baselineSignature
	cfg      Config

	filterTime *timeCriterion
	matchTime  *timeCriterion
	filterRe   *regexp.Regexp
	matchRe    *regexp.Regexp

	// thresholds
	sizeThreshold int64 // ±N bytes tolerance (default 0 = exact after baseline)
}

// newAnalyzer builds an analyzer from config and baseline.
func newAnalyzer(cfg Config, baseline *baselineSignature) (*analyzer, error) {
	a := &analyzer{
		baseline:      baseline,
		cfg:           cfg,
		sizeThreshold: 0,
	}
	var err error
	if cfg.FilterTime != "" {
		if a.filterTime, err = parseTimeCriterion(cfg.FilterTime); err != nil {
			return nil, err
		}
	}
	if cfg.MatchTime != "" {
		if a.matchTime, err = parseTimeCriterion(cfg.MatchTime); err != nil {
			return nil, err
		}
	}
	if cfg.FilterRegex != "" {
		if a.filterRe, err = regexp.Compile(cfg.FilterRegex); err != nil {
			return nil, fmt.Errorf("invalid filter regex: %w", err)
		}
	}
	if cfg.MatchRegex != "" {
		if a.matchRe, err = regexp.Compile(cfg.MatchRegex); err != nil {
			return nil, fmt.Errorf("invalid match regex: %w", err)
		}
	}
	return a, nil
}

// Analyze decides whether a response is interesting, and if so why. It
// applies the user filters first (reject), then the match filters (accept),
// then falls back to baseline divergence detection.
func (a *analyzer) Analyze(resp *httpclient.Response, reqURL string) (bool, string) {
	sig := signatureOf(resp)
	body := resp.Body

	// 1. Explicit filter-out rules (take precedence).
	if reason := a.rejectedByFilters(sig, body); reason != "" {
		return false, reason
	}

	// 2. Explicit match rules override everything.
	if a.hasMatchFilters() {
		if reason := a.matchedByCriteria(sig, body); reason != "" {
			return true, reason
		}
		return false, "no match criteria satisfied"
	}

	// 3. Baseline divergence detection (default interesting behavior).
	return a.differsFromBaseline(sig)
}

// rejectedByFilters returns a rejection reason if any explicit filter
// matches, else "".
func (a *analyzer) rejectedByFilters(sig *baselineSignature, body []byte) string {
	if len(a.cfg.FilterStatus) > 0 && intIn(sig.StatusCode, a.cfg.FilterStatus) {
		return "filtered: status=" + strconv.Itoa(sig.StatusCode)
	}
	if len(a.cfg.FilterSize) > 0 && int64In(sig.ContentLen, a.cfg.FilterSize) {
		return "filtered: size=" + strconv.FormatInt(sig.ContentLen, 10)
	}
	for _, r := range a.cfg.FilterWords {
		if r.contains(int64(sig.Words)) {
			return "filtered: words"
		}
	}
	for _, r := range a.cfg.FilterLines {
		if r.contains(int64(sig.Lines)) {
			return "filtered: lines"
		}
	}
	if a.filterTime != nil && !a.filterTime.matches(sig.Duration.Milliseconds()) {
		return "filtered: time"
	}
	if a.filterRe != nil && !isProbablyBinary(body) && a.filterRe.Match(body) {
		return "filtered: regex"
	}
	return ""
}

// hasMatchFilters reports whether any explicit positive criteria were set.
func (a *analyzer) hasMatchFilters() bool {
	return len(a.cfg.MatchStatus) > 0 ||
		len(a.cfg.MatchSize) > 0 ||
		len(a.cfg.MatchWords) > 0 ||
		len(a.cfg.MatchLines) > 0 ||
		a.matchTime != nil ||
		a.matchRe != nil
}

// matchedByCriteria returns a match reason if any explicit match criterion is
// satisfied. A response is flagged if at least one criterion matches.
func (a *analyzer) matchedByCriteria(sig *baselineSignature, body []byte) string {
	var reasons []string
	if len(a.cfg.MatchStatus) > 0 && intIn(sig.StatusCode, a.cfg.MatchStatus) {
		reasons = append(reasons, "status="+strconv.Itoa(sig.StatusCode))
	}
	if len(a.cfg.MatchSize) > 0 && int64In(sig.ContentLen, a.cfg.MatchSize) {
		reasons = append(reasons, "size="+strconv.FormatInt(sig.ContentLen, 10))
	}
	for _, r := range a.cfg.MatchWords {
		if r.contains(int64(sig.Words)) {
			reasons = append(reasons, "words")
		}
	}
	for _, r := range a.cfg.MatchLines {
		if r.contains(int64(sig.Lines)) {
			reasons = append(reasons, "lines")
		}
	}
	if a.matchTime != nil && a.matchTime.matches(sig.Duration.Milliseconds()) {
		reasons = append(reasons, "time="+strconv.FormatInt(sig.Duration.Milliseconds(), 10)+"ms")
	}
	if a.matchRe != nil && !isProbablyBinary(body) && a.matchRe.Match(body) {
		reasons = append(reasons, "regex")
	}
	if len(reasons) == 0 {
		return ""
	}
	return strings.Join(reasons, ",")
}

// differsFromBaseline detects baseline divergence and returns whether the
// response is interesting, plus the reason.
func (a *analyzer) differsFromBaseline(sig *baselineSignature) (bool, string) {
	if a.baseline == nil {
		return true, "no baseline"
	}
	b := a.baseline

	if sig.StatusCode != b.StatusCode {
		return true, "status " + strconv.Itoa(b.StatusCode) + "->" + strconv.Itoa(sig.StatusCode)
	}

	// Size divergence beyond tolerance.
	delta := sig.ContentLen - b.ContentLen
	if delta < 0 {
		delta = -delta
	}
	if delta > a.sizeThreshold {
		return true, fmt.Sprintf("size %s->%s", humanSize(b.ContentLen), humanSize(sig.ContentLen))
	}

	// Time divergence (blind SQLi / slow responses) — flag if notably slower.
	if sig.Duration > b.Duration && sig.Duration-b.Duration > 1000*time.Millisecond {
		return true, fmt.Sprintf("time %dms->%dms", b.Duration.Milliseconds(), sig.Duration.Milliseconds())
	}

	// Body divergence despite same size (content changed).
	if sig.BodyHash256 != "" && a.baseline.BodyHash256 != "" &&
		sig.BodyHash256 != a.baseline.BodyHash256 && sig.ContentLen == b.ContentLen {
		return true, "content differs"
	}

	return false, ""
}

// humanSize formats a byte count compactly.
func humanSize(n int64) string {
	switch {
	case n >= 1024*1024:
		return strconv.FormatInt(n/(1024*1024), 10) + "M"
	case n >= 1024:
		return strconv.FormatInt(n/1024, 10) + "K"
	default:
		return strconv.Itoa(int(n))
	}
}

func intIn(v int, list []int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func int64In(v int64, list []int64) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// ---- payload injection / encoding ----

// injectedRequest is a fully rendered HTTP request ready to send.
type injectedRequest struct {
	url  string
	body []byte
}

// payloadInjector replaces FUZZ / FUZZ1..FUZZN markers in the URL, headers,
// cookies and body with concrete payload values. It applies context-appropriate
// escaping (URL-encoding, JSON escaping, header CRLF protection).
type payloadInjector struct {
	rawURL   string
	rawBody  string
	bodyType bodyKind
	// Marker list in canonical order (FUZZ, FUZZ1, FUZZ2, ...).
	markers []string
}

type bodyKind int

const (
	bodyNone bodyKind = iota
	bodyRaw
	bodyJSON
	bodyForm
)

// primaryMarker returns the marker that gets a default random payload when
// calibrating (typically the first configured marker).
func (pi *payloadInjector) primaryMarker() string {
	if len(pi.markers) == 0 {
		return "FUZZ"
	}
	return pi.markers[0]
}

func (pi *payloadInjector) render(payload map[string]string) *injectedRequest {
	url := pi.rawURL
	for _, m := range pi.markers {
		if v, ok := payload[m]; ok {
			url = replaceURLMarker(url, m, v)
		}
	}

	var body []byte
	if pi.rawBody != "" {
		b := pi.rawBody
		for _, m := range pi.markers {
			if v, ok := payload[m]; ok {
				b = replaceBodyMarker(b, m, v, pi.bodyType)
			}
		}
		body = []byte(b)
	}
	return &injectedRequest{url: url, body: body}
}

// extractMarkers scans the URL for marker tokens and returns the distinct set
// in canonical order.
func extractMarkers(rawURL string) []string {
	seen := map[string]bool{}
	var list []string
	// Scan for "FUZZ" optionally followed by digits.
	idx := 0
	lower := []byte(rawURL)
	for idx < len(lower) {
		if lower[idx] == 'F' || lower[idx] == 'f' {
			if matchMarkerAt(lower, idx) {
				marker, _ := markerAt(lower, idx)
				if !seen[marker] {
					seen[marker] = true
					list = append(list, marker)
				}
				idx += len(marker)
				continue
			}
		}
		_, size := utf8.DecodeRune(lower[idx:])
		if size == 0 {
			size = 1
		}
		idx += size
	}
	return list
}

// matchMarkerAt reports whether lower[idx:] begins with a marker token.
func matchMarkerAt(b []byte, idx int) bool {
	s, _ := markerAt(b, idx)
	return s != ""
}

// markerAt returns the marker string starting at idx (which must be an 'F'),
// or "" if no marker.
func markerAt(b []byte, idx int) (string, int) {
	if idx >= len(b) || (b[idx] != 'F' && b[idx] != 'f') {
		return "", 0
	}
	j := idx + 1
	if j < len(b) && b[j] == 'U' {
		j++
	}
	if j < len(b) && b[j] == 'Z' {
		j++
	}
	if j < len(b) && b[j] == 'Z' {
		j++
	}
	// Optional numeric suffix for FUZZ1..FUZZN.
	for j < len(b) && b[j] >= '0' && b[j] <= '9' {
		j++
	}
	// Allow FUZZ with no digits only when "FUZZ" exact.
	name := string(b[idx:j])
	if name != "FUZZ" && !isFUZZNumbered(name) {
		return "", 0
	}
	return name, j - idx
}

func isFUZZNumbered(name string) bool {
	if len(name) < 5 || !strings.HasPrefix(name, "FUZZ") {
		return false
	}
	for _, c := range name[4:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// replaceURLMarker replaces a marker with a URL-escaped value.
func replaceURLMarker(s, marker, value string) string {
	return strings.ReplaceAll(s, marker, urlQueryEscape(value))
}

// replaceBodyMarker replaces a marker in a body using context-appropriate
// escaping.
func replaceBodyMarker(s, marker, value string, kind bodyKind) string {
	switch kind {
	case bodyJSON:
		return strings.ReplaceAll(s, marker, jsonEscape(value))
	case bodyForm:
		return strings.ReplaceAll(s, marker, urlFormEscape(value))
	default:
		return strings.ReplaceAll(s, marker, value)
	}
}

// urlQueryEscape percent-encodes value for use in query strings.
func urlQueryEscape(v string) string {
	var sb strings.Builder
	for _, c := range []byte(v) {
		if isURLSafe(c) {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('%')
			sb.WriteByte(hexDigit(c >> 4))
			sb.WriteByte(hexDigit(c & 0xf))
		}
	}
	return sb.String()
}

func urlFormEscape(v string) string {
	return strings.ReplaceAll(urlQueryEscape(v), "%20", "+")
}

func isURLSafe(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '-', '_', '.', '~':
		return true
	}
	return false
}

func hexDigit(v byte) byte {
	const digits = "0123456789ABCDEF"
	return digits[v&0xf]
}

// jsonEscape escapes a value for embedding in a JSON string.
func jsonEscape(v string) string {
	var sb strings.Builder
	for _, r := range v {
		switch r {
		case '"':
			sb.WriteString("\\\"")
		case '\\':
			sb.WriteString("\\\\")
		case '\n':
			sb.WriteString("\\n")
		case '\r':
			sb.WriteString("\\r")
		case '\t':
			sb.WriteString("\\t")
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// buildRequestHeaders merges configured headers and cookies, protecting
// against CRLF injection in values that came from the marker substitution.
func (pi *payloadInjector) buildRequestHeaders(cfg Config) map[string]string {
	h := make(map[string]string)
	for k, v := range cfg.Headers {
		h[k] = sanitizeHeaderValue(v)
	}
	if len(cfg.Cookies) > 0 {
		var sb strings.Builder
		first := true
		for k, v := range cfg.Cookies {
			if !first {
				sb.WriteString("; ")
			}
			first = false
			sb.WriteString(sanitizeHeaderValue(k))
			sb.WriteString("=")
			sb.WriteString(sanitizeHeaderValue(v))
		}
		h["Cookie"] = sb.String()
	}
	return h
}

// sanitizeHeaderValue strips CR/LF characters to prevent header injection.
func sanitizeHeaderValue(v string) string {
	v = strings.ReplaceAll(v, "\r", "")
	v = strings.ReplaceAll(v, "\n", "")
	return v
}

// randomValue generates a random alphanumeric string of length n for baseline
// calibration.
func randomValue(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	var x uint64 = uint64(time.Now().UnixNano())
	out := make([]byte, n)
	for i := range out {
		// xorshift PRNG.
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		out[i] = alphabet[binaryMask(x)%uint64(len(alphabet))]
	}
	return string(out)
}

// binaryMask maps a uint64 to a small integer using high bits only, avoiding
// modulo bias for the tiny alphabet.
func binaryMask(x uint64) uint64 {
	if bits.Len64(x) < 32 {
		return x & 0xFFFF
	}
	return (x >> 29) & 0xFFFF
}

func methodOrDefault(m string) string {
	m = strings.ToUpper(strings.TrimSpace(m))
	if m == "" {
		return "GET"
	}
	return m
}
