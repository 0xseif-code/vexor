package directory

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0xseif-code/vexor/internal/httpclient"
	"github.com/0xseif-code/vexor/internal/wordlists"
	"golang.org/x/time/rate"
)

// Default configuration values.
const (
	DefaultConcurrency  = 50
	DefaultTimeout      = 10 * time.Second
	DefaultMaxRecursion = 0 // no recursion by default
	calibrationSamples  = 4 // random probes for soft-404 baseline
	rateLimitBurst      = 2
	maxConsecutive5xx   = 5
	concurrencyCooldown = 2 * time.Second
	retryAfterCap       = 10 * time.Second
	pollInterval        = 10 * time.Millisecond
)

var (
	// ErrNoTarget indicates the target URL is empty or invalid.
	ErrNoTarget = errors.New("no or invalid target URL")

	// ErrTargetUnreachable indicates baseline calibration could not reach the
	// target at startup.
	ErrTargetUnreachable = errors.New("target unreachable during baseline calibration")

	// ErrWordlist indicates the wordlist could not be loaded.
	ErrWordlist = errors.New("wordlist error")

	// ErrInvalidPattern indicates an invalid regex was supplied.
	ErrInvalidPattern = errors.New("invalid regex pattern")

	// ErrNoClient indicates the HTTP client was not provided.
	ErrNoClient = errors.New("http client not configured")

	// ErrNoSelector indicates the wordlist selector was not provided.
	ErrNoSelector = errors.New("wordlist selector not configured")
)

// ExtensionPresets maps common extension presets to their extensions.
var ExtensionPresets = map[string][]string{
	"php":    {"php"},
	"asp":    {"asp", "aspx"},
	"python": {"py"},
	"backup": {"bak", "old", "orig", "save", "swp", "zip", "tar", "gz"},
	"all":    {"php", "asp", "aspx", "jsp", "html", "htm", "bak", "old", "txt", "zip", "xml", "json", "log", "conf", "config", "ini", "sql", "tar", "gz", "js", "css"},
}

// Config controls a directory/endpoint discovery run.
type Config struct {
	TargetURL          string
	Extensions         []string
	Concurrency        int
	RateLimit          int
	Timeout            time.Duration
	Recursion          bool
	MaxDepth           int
	RecursionBlacklist []string

	// Response filters
	MatchStatus  []int
	FilterStatus []int
	FilterSize   []int64
	FilterWords  []int
	FilterLines  []int
	FilterRegex  string
	MatchRegex   string

	// Request customization
	Headers         map[string]string
	Cookies         map[string]string
	UserAgent       string
	FollowRedirects bool

	WordlistOpts wordlists.Options
}

// Finding represents a single discovered endpoint.
type Finding struct {
	URL           string
	StatusCode    int
	ContentLength int64
	Duration      time.Duration
	ContentType   string
	RedirectTo    string
	Title         string
	Words         int
	Lines         int
	Depth         int
}

// Stats tracks cumulative discovery metrics.
type Stats struct {
	Findings  int64
	Requests  int64
	Errors    int64
	StartedAt time.Time
	Duration  time.Duration
	Completed bool
}

// Atomic counters for stats (plain struct with atomic fields).
type counters struct {
	findings atomic.Int64
	requests atomic.Int64
	errs     atomic.Int64
}

// Scanner coordinates a directory enumeration run.
type Scanner struct {
	cfg      Config
	client   *httpclient.Client
	selector *wordlists.Selector
	baseURL  string
	basePath string
	limiter  *rate.Limiter
	matcher  *responseMatcher
	headers  map[string]string

	queue     chan scanTask
	pending   atomic.Int64
	seen      sync.Map // full URL -> struct{}
	runCtx    context.Context
	done      atomic.Bool
	serverErr atomic.Int64
	started   time.Time

	cnt counters
}

// scanTask represents a single path to probe, at a given recursion depth.
type scanTask struct {
	path  string
	depth int
}

// New constructs a Scanner, normalizing the target and preparing defaults.
func New(cfg Config, httpClient *httpclient.Client, wlSelector *wordlists.Selector) *Scanner {
	cfg = applyDefaults(cfg)
	baseURL, basePath := splitBase(cfg.TargetURL)
	s := &Scanner{
		cfg:      cfg,
		client:   httpClient,
		selector: wlSelector,
		baseURL:  baseURL,
		basePath: basePath,
		headers:  buildHeaders(cfg),
		started:  time.Now(),
	}
	if cfg.RateLimit > 0 {
		s.limiter = rate.NewLimiter(rate.Limit(cfg.RateLimit), rateLimitBurst)
	}
	return s
}

// Stats returns a snapshot of current metrics.
func (s *Scanner) Stats() Stats {
	return Stats{
		Findings:  s.cnt.findings.Load(),
		Requests:  s.cnt.requests.Load(),
		Errors:    s.cnt.errs.Load(),
		StartedAt: s.started,
		Duration:  time.Since(s.started),
		Completed: s.done.Load(),
	}
}

// Run executes the scan. It returns a channel of findings and a channel of
// non-fatal errors. Both are closed on completion or cancellation.
func (s *Scanner) Run(ctx context.Context) (<-chan Finding, <-chan error) {
	out := make(chan Finding)
	errCh := make(chan error, 1)
	go s.run(ctx, out, errCh)
	return out, errCh
}

// run is the internal orchestrator.
func (s *Scanner) run(ctx context.Context, out chan<- Finding, errCh chan<- error) {
	defer close(out)
	defer close(errCh)
	defer s.done.Store(true)

	s.runCtx = ctx

	if s.baseURL == "" {
		errCh <- ErrNoTarget
		return
	}
	if s.client == nil {
		errCh <- ErrNoClient
		return
	}
	if s.selector == nil {
		errCh <- ErrNoSelector
		return
	}

	// Baseline calibration is mandatory for soft-404 filtering.
	fp := newFingerprinter(s.client, s.baseURL, s.headers)
	matcher, err := fp.calibrate(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		errCh <- fmt.Errorf("baseline calibration: %w", err)
		return
	}
	if err := matcher.applyConfig(s.cfg); err != nil {
		errCh <- err
		return
	}
	s.matcher = matcher

	// Prepare task queue (unbuffered so workers pull directly; recursion and
	// top-level tasks share the same bounded pipeline).
	s.queue = make(chan scanTask)

	// Start the bounded worker pool.
	var workerWg sync.WaitGroup
	for i := 0; i < int(s.cfg.Concurrency); i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			s.workerLoop(ctx, out)
		}()
	}

	// Scan the top-level wordlist in its own goroutine. It enqueues tasks
	// into the same queue the workers drain.
	topDone := make(chan struct{})
	go func() {
		defer close(topDone)
		s.scanWordlist(ctx, errCh)
	}()

	// Wait for top-level feeding to finish, then for the pending counter to
	// drop to zero (recursion included) before closing the queue.
	<-topDone
	for {
		if p := s.pending.Load(); p <= 0 {
			break
		}
		select {
		case <-ctx.Done():
			goto shutdown
		case <-time.After(pollInterval):
		}
	}

shutdown:
	close(s.queue)
	workerWg.Wait()
}

// scanWordlist streams words, expands them into path candidates, and enqueues
// them. It respects context cancellation.
func (s *Scanner) scanWordlist(ctx context.Context, errCh chan<- error) {
	words, werrs, err := s.selector.LoadStream(ctx, s.cfg.WordlistOpts)
	if err != nil {
		s.sendErr(errCh, fmt.Errorf("%w: %v", ErrWordlist, err))
		return
	}

	// Drain wordlist errors in the background.
	go func() {
		for werr := range werrs {
			if ctx.Err() != nil {
				return
			}
			s.sendErr(errCh, fmt.Errorf("%w: %v", ErrWordlist, werr))
		}
	}()

	for word := range words {
		if ctx.Err() != nil {
			return
		}
		for _, path := range expandWord(s.basePath, word, s.cfg.Extensions) {
			if !s.enqueue(ctx, path, 0) {
				return
			}
		}
	}
}

// workerLoop consumes tasks from the queue until it is closed or the context
// is cancelled. It decrements the pending counter after each task so the
// orchestrator can detect when all work (including recursion) is done.
func (s *Scanner) workerLoop(ctx context.Context, out chan<- Finding) {
	for task := range s.queue {
		s.probe(ctx, task, out)
		s.pending.Add(-1)
	}
}

// probe performs a single request for a task and, if it is a valid finding,
// emits it and schedules recursion as appropriate.
func (s *Scanner) probe(ctx context.Context, task scanTask, out chan<- Finding) {
	fullURL := joinURL(s.baseURL, task.path)

	resp, err := s.fetch(ctx, fullURL)
	s.cnt.requests.Add(1)
	if err != nil {
		s.cnt.errs.Add(1)
		return
	}

	if resp == nil {
		return
	}

	body := resp.BodyString()
	if !s.matcher.Decide(resp, body) {
		return
	}

	finding := analyzeFinding(fullURL, resp, body, task.depth)
	s.cnt.findings.Add(1)

	select {
	case out <- finding:
	case <-ctx.Done():
		return
	}

	// Recursion.
	if s.cfg.Recursion && task.depth < s.cfg.MaxDepth && isDirectoryFinding(finding) {
		child := task.path
		if !hasTrailingSlash(child) {
			child += "/"
		}
		if !s.isBlacklisted(child) {
			s.enqueue(ctx, child, task.depth+1)
		}
	}
}

// fetch performs one request with rate limiting and auto-backoff on 429 and
// repeated 5xx responses.
func (s *Scanner) fetch(ctx context.Context, fullURL string) (*httpclient.Response, error) {
	if s.limiter != nil {
		if err := s.limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}

	resp, err := s.doRequest(ctx, fullURL)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == 429 {
		// Back off per Retry-After, then retry up to a few times.
		for attempt := 0; attempt < 3; attempt++ {
			if !s.sleepAfter429(ctx, resp) {
				return resp, nil
			}
			r2, err2 := s.doRequest(ctx, fullURL)
			if err2 != nil {
				return nil, err2
			}
			resp = r2
			if resp.StatusCode != 429 {
				break
			}
		}
		return resp, nil
	}

	if isServerError(resp.StatusCode) {
		s.noteServerError()
	}

	return resp, nil
}

// doRequest is a thin wrapper around the httpclient GET.
func (s *Scanner) doRequest(ctx context.Context, fullURL string) (*httpclient.Response, error) {
	return s.client.Get(ctx, fullURL, s.headers)
}

// noteServerError counts consecutive 5xx responses and, past the threshold,
// briefly throttles the scan.
func (s *Scanner) noteServerError() {
	n := s.serverErr.Add(1)
	if n >= maxConsecutive5xx {
		s.serverErr.Store(0)
		_ = sleepCtx(s.runCtx, concurrencyCooldown)
	}
}

// sleepAfter429 sleeps based on a Retry-After header (or a default), halting
// on context cancellation. Returns false if cancelled.
func (s *Scanner) sleepAfter429(ctx context.Context, resp *httpclient.Response) bool {
	ra := resp.HeaderGet("Retry-After")
	if ra == "" {
		return sleepCtx(ctx, 1*time.Second)
	}

	var d time.Duration
	if secs, err := time.ParseDuration(ra + "s"); err == nil {
		d = secs
	} else if n, err := fmt.Sscanf(ra, "%d", new(int)); err == nil {
		_ = n
		var v int
		_, _ = fmt.Sscanf(ra, "%d", &v)
		d = time.Duration(v) * time.Second
	} else {
		d = 1 * time.Second
	}
	if d > retryAfterCap {
		d = retryAfterCap
	}
	return sleepCtx(ctx, d)
}

// sleepCtx sleeps for d or until ctx is cancelled. Returns false on cancel.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// enqueue adds a task to the queue, deduping by URL. Returns false if the
// context is cancelled. It is safe for concurrent use.
func (s *Scanner) enqueue(ctx context.Context, path string, depth int) bool {
	fullURL := joinURL(s.baseURL, path)
	if _, loaded := s.seen.LoadOrStore(fullURL, struct{}{}); loaded {
		return true
	}
	s.pending.Add(1)
	select {
	case s.queue <- scanTask{path: path, depth: depth}:
		return true
	case <-ctx.Done():
		s.pending.Add(-1)
		return false
	}
}

// isBlacklisted reports whether recursion into a path should be skipped.
func (s *Scanner) isBlacklisted(path string) bool {
	lower := strings.ToLower(strings.TrimSuffix(path, "/"))
	for _, b := range s.cfg.RecursionBlacklist {
		b = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(b), "/"))
		if b == "" {
			continue
		}
		if strings.HasPrefix(lower, b) {
			return true
		}
	}
	return false
}

// sendErr forwards an error to the error channel if not cancelled and not
// full.
func (s *Scanner) sendErr(errCh chan<- error, err error) {
	if err == nil {
		return
	}
	select {
	case errCh <- err:
	default:
	}
}

// ---- response analysis ----

// analyzeFinding builds a rich Finding from a response.
func analyzeFinding(fullURL string, resp *httpclient.Response, body string, depth int) Finding {
	return Finding{
		URL:           fullURL,
		StatusCode:    resp.StatusCode,
		ContentLength: int64(len(resp.Body)),
		Duration:      resp.Duration,
		ContentType:   resp.HeaderGet("Content-Type"),
		RedirectTo:    resp.HeaderGet("Location"),
		Title:         extractTitle(body),
		Words:         len(strings.Fields(body)),
		Lines:         countLines(resp.Body),
		Depth:         depth,
	}
}

// extractTitle extracts the content of the first <title> tag in HTML.
func extractTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title")
	if start == -1 {
		return ""
	}
	gt := strings.Index(body[start:], ">")
	if gt == -1 {
		return ""
	}
	contentStart := start + gt + 1
	end := strings.Index(lower[contentStart:], "</title")
	if end == -1 {
		return strings.TrimSpace(body[contentStart:])
	}
	return strings.TrimSpace(body[contentStart : contentStart+end])
}

// isServerError reports whether a status code is a 5xx.
func isServerError(status int) bool {
	return status >= 500 && status <= 599
}

// isDirectoryFinding reports whether a finding looks like a directory worth
// recursing into.
func isDirectoryFinding(f Finding) bool {
	switch f.StatusCode {
	case 200, 201, 301, 302, 307, 308, 401, 403:
		return true
	}
	return false
}

// hasTrailingSlash reports whether a path ends with "/".
func hasTrailingSlash(path string) bool {
	return strings.HasSuffix(path, "/")
}

// ---- word/extension expansion ----

// expandWord converts a wordlist entry into one or more path candidates,
// handling leading/trailing slashes and extensions. Directory hints (trailing
// "/") get no extension expansion.
func expandWord(basePath, word string, extensions []string) []string {
	word = strings.TrimSpace(word)
	if word == "" {
		return nil
	}
	word = strings.TrimPrefix(word, "/")

	if strings.HasSuffix(word, "/") {
		// Directory hint: no extension expansion.
		return []string{basePath + word}
	}

	paths := []string{basePath + word}
	for _, ext := range extensions {
		ext = strings.TrimPrefix(strings.TrimSpace(ext), ".")
		if ext == "" {
			continue
		}
		paths = append(paths, basePath+word+"."+ext)
	}
	return paths
}

// ---- URL helpers ----

// splitBase decomposes a target into its origin and a base path ending with
// "/".
func splitBase(target string) (string, string) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", ""
	}
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return "", ""
	}
	base := u.Path
	if base != "" && !strings.HasSuffix(base, "/") {
		base += "/"
	}
	if base == "" {
		base = "/"
	}
	return u.Scheme + "://" + u.Host, base
}

// joinURL combines an origin and a path, ensuring a single "/" between them.
func joinURL(origin, path string) string {
	return origin + "/" + strings.TrimPrefix(path, "/")
}

// buildHeaders merges configured headers and cookies into a request header
// map, adding a User-Agent if configured and none is already set.
func buildHeaders(cfg Config) map[string]string {
	h := make(map[string]string)
	for k, v := range cfg.Headers {
		h[k] = v
	}
	if len(cfg.Cookies) > 0 {
		var sb strings.Builder
		first := true
		for k, v := range cfg.Cookies {
			if !first {
				sb.WriteString("; ")
			}
			first = false
			sb.WriteString(k)
			sb.WriteString("=")
			sb.WriteString(v)
		}
		h["Cookie"] = sb.String()
	}
	if cfg.UserAgent != "" {
		if _, ok := h["User-Agent"]; !ok {
			h["User-Agent"] = cfg.UserAgent
		}
	}
	return h
}

// applyDefaults fills in defaults for zero-valued Config fields.
func applyDefaults(cfg Config) Config {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = DefaultConcurrency
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MaxDepth < 0 {
		cfg.MaxDepth = 0
	}
	if cfg.WordlistOpts.Category == "" {
		cfg.WordlistOpts.Category = wordlists.CategoryDirectory
	}
	if cfg.WordlistOpts.Size == "" {
		cfg.WordlistOpts.Size = wordlists.SizeMedium
	}
	if cfg.Headers == nil {
		cfg.Headers = make(map[string]string)
	}
	return cfg
}
