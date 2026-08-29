package directory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"

	"github.com/0xseif-code/vexor/internal/httpclient"
)

// baselineSignature captures the fingerprint of a "not found" response so
// that soft-404 responses matching it can be filtered out during the scan.
type baselineSignature struct {
	StatusCode  int
	ContentLen  int64
	Words       int
	Lines       int
	BodyHash512 string // SHA-256 of the first 512 bytes of the body
}

// fingerprinter performs the baseline calibration: it issues several
// requests to random non-existent paths and distills a baseline signature
// from the responses.
type fingerprinter struct {
	baseURL string
	client  *httpclient.Client
	headers map[string]string
}

// newFingerprinter builds a fingerprinter bound to the base URL.
func newFingerprinter(client *httpclient.Client, baseURL string, headers map[string]string) *fingerprinter {
	return &fingerprinter{client: client, baseURL: baseURL, headers: headers}
}

// calibrate returns a matcher that detects soft-404 responses. It sends up
// to calibrationSamples requests to random paths. If the target is down (all
// requests fail), it returns an error so the caller can abort — baseline
// calibration is mandatory.
func (f *fingerprinter) calibrate(ctx context.Context) (*responseMatcher, error) {
	sig, err := f.collectBaseline(ctx)
	if err != nil {
		return nil, err
	}
	return newMatcher(sig), nil
}

// collectBaseline resolves the most common "not found" fingerprinter among a
// small set of random-path probes. It favours the status code that appears
// most frequently and returns its signature. If the target is unreachable it
// returns a sentinel error.
func (f *fingerprinter) collectBaseline(ctx context.Context) (*baselineSignature, error) {
	var (
		byStatus = make(map[int][]*baselineSignature)
	)

	for i := 0; i < calibrationSamples; i++ {
		randPath := randomPath(i)
		url := joinURL(f.baseURL, randPath)

		resp, err := f.client.Get(ctx, url, f.headers)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			// One failed probe is OK; target may be momentarily slow.
			continue
		}

		sig := signatureOf(resp)
		byStatus[sig.StatusCode] = append(byStatus[sig.StatusCode], sig)
	}

	if len(byStatus) == 0 {
		return nil, ErrTargetUnreachable
	}

	// Pick the status code with the most agreeing samples.
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

	list := byStatus[bestStatus]
	// Use the first signature of the winning status as the baseline; it is
	// representative enough for soft-404 detection.
	return list[0], nil
}

// randomPath produces a random-looking non-existent path rooted at "/".
func randomPath(seed int) string {
	const randChars = "abcdef0123456789"
	path := make([]byte, 16)
	var h = dummyHash() + uint32(seed)*2654435761
	for i := range path {
		h ^= h << 13
		h ^= h >> 17
		h ^= h << 5
		path[i] = randChars[h%uint32(len(randChars))]
	}
	return "vexor_" + string(path)
}

// dummyHash seeds the pseudo-random generator for randomPath. It is a small
// PRNG helper; the exact sequence is irrelevant as long as it varies.
func dummyHash() uint32 {
	return 0x9E3779B9
}

// signatureOf computes a baselineSignature from a response.
func signatureOf(resp *httpclient.Response) *baselineSignature {
	return &baselineSignature{
		StatusCode:  resp.StatusCode,
		ContentLen:  int64(len(resp.Body)),
		Words:       countWords(resp.Body),
		Lines:       countLines(resp.Body),
		BodyHash512: hashPrefix(resp.Body, 512),
	}
}

// hashPrefix returns the SHA-256 hex of the first n bytes of data.
func hashPrefix(data []byte, n int) string {
	if len(data) > n {
		data = data[:n]
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// countWords counts whitespace-delimited tokens in data.
func countWords(data []byte) int {
	fields := bytes.Fields(data)
	return len(fields)
}

// countLines counts newline-terminated lines in data.
func countLines(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	n := bytes.Count(data, []byte{'\n'})
	if data[len(data)-1] != '\n' {
		n++
	}
	return n
}

// responseMatcher encapsulates baseline and user-defined response filters.
// It decides whether a probe response should be kept as a finding.
type responseMatcher struct {
	// baseline matching (soft-404)
	baselineEnabled bool
	baseline        *baselineSignature

	// user filters
	matchStatus  map[int]bool
	filterStatus map[int]bool
	filterSize   map[int64]bool
	filterWords  map[int]bool
	filterLines  map[int]bool
	filterRegex  *regexp.Regexp
	matchRegex   *regexp.Regexp
}

// newMatcher builds a responseMatcher with soft-404 baseline filtering
// enabled against the given baseline signature.
func newMatcher(base *baselineSignature) *responseMatcher {
	return &responseMatcher{
		baselineEnabled: base != nil,
		baseline:        base,
		matchStatus:     make(map[int]bool),
		filterStatus:    make(map[int]bool),
		filterSize:      make(map[int64]bool),
		filterWords:     make(map[int]bool),
		filterLines:     make(map[int]bool),
	}
}

// applyConfig layers user-defined filters from Config onto the matcher. It
// returns an error if any supplied regex is invalid.
func (m *responseMatcher) applyConfig(cfg Config) error {
	for _, s := range cfg.MatchStatus {
		m.matchStatus[s] = true
	}
	for _, s := range cfg.FilterStatus {
		m.filterStatus[s] = true
	}
	for _, s := range cfg.FilterSize {
		m.filterSize[s] = true
	}
	for _, w := range cfg.FilterWords {
		m.filterWords[w] = true
	}
	for _, l := range cfg.FilterLines {
		m.filterLines[l] = true
	}
	if cfg.FilterRegex != "" {
		re, err := regexp.Compile(cfg.FilterRegex)
		if err != nil {
			return fmt.Errorf("%w (filter): %v", ErrInvalidPattern, err)
		}
		m.filterRegex = re
	}
	if cfg.MatchRegex != "" {
		re, err := regexp.Compile(cfg.MatchRegex)
		if err != nil {
			return fmt.Errorf("%w (match): %v", ErrInvalidPattern, err)
		}
		m.matchRegex = re
	}
	return nil
}

// Decide reports whether a probe response should be reported as a finding.
// The logic:
//   - If a match filter is set, only responses satisfying it are kept.
//   - Otherwise, apply the default rejection rules (soft-404, explicit
//     rejects, certain 4xx/5xx) plus the user reject filters.
//   - If both --match-status and --filter-status are given, match wins.
func (m *responseMatcher) Decide(resp *httpclient.Response, body string) bool {
	sig := signatureOf(resp)
	hasMatch := m.hasMatchFilter()

	if hasMatch {
		return m.satisfiesMatch(sig, body)
	}

	// Default behaviour: reject known-negative responses.
	if m.rejectedByUser(sig, body) {
		return false
	}
	if isDefaultReject(sig.StatusCode) {
		return false
	}
	return true
}

// hasMatchFilter reports whether any positive match criteria were set.
func (m *responseMatcher) hasMatchFilter() bool {
	return len(m.matchStatus) > 0 || m.matchRegex != nil
}

// satisfiesMatch evaluates whether a response meets an explicit match
// criterion. When multiple match types are set, ALL must be satisfied.
func (m *responseMatcher) satisfiesMatch(sig *baselineSignature, body string) bool {
	if len(m.matchStatus) > 0 && !m.matchStatus[sig.StatusCode] {
		return false
	}
	if m.matchRegex != nil && !m.matchRegex.MatchString(body) {
		return false
	}
	return true
}

// rejectedByUser applies the explicit reject filters (status, size, words,
// lines, regex) and the baseline soft-404 check.
func (m *responseMatcher) rejectedByUser(sig *baselineSignature, body string) bool {
	if len(m.filterStatus) > 0 && m.filterStatus[sig.StatusCode] {
		return true
	}
	if len(m.filterSize) > 0 && m.filterSize[sig.ContentLen] {
		return true
	}
	if len(m.filterWords) > 0 && m.filterWords[sig.Words] {
		return true
	}
	if len(m.filterLines) > 0 && m.filterLines[sig.Lines] {
		return true
	}
	if m.filterRegex != nil && m.filterRegex.MatchString(body) {
		return true
	}
	return m.isSoft404(sig, body)
}

// isSoft404 reports whether a response closely matches the calibrated
// baseline (i.e. it is a catch-all "not found" response).
func (m *responseMatcher) isSoft404(sig *baselineSignature, body string) bool {
	if m.baseline == nil {
		return false
	}
	b := m.baseline
	// A response with a different status code is certainly not a soft 404.
	if sig.StatusCode != b.StatusCode {
		return false
	}
	// Compare body hash and size. Tolerate small size differences to avoid
	// missing true positives from minor dynamic content.
	if sameBodyHash(sig.BodyHash512, b.BodyHash512) {
		return true
	}
	if sig.ContentLen == b.ContentLen {
		return true
	}
	if sig.Words == b.Words && sig.Words > 0 {
		return true
	}
	return false
}

// sameBodyHash compares two body-hash strings directly.
func sameBodyHash(a, b string) bool {
	return a != "" && a == b
}

// isDefaultReject reports status codes rejected by default when no match
// filter overrides them.
func isDefaultReject(status int) bool {
	switch status {
	case 404, 500, 502, 503, 504:
		return true
	}
	return false
}
