package fuzz

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/0xseif-code/vexor/internal/httpclient"
	"github.com/0xseif-code/vexor/internal/wordlists"
)

// MaximumComboLimit is the safety threshold for pre-start confirmation.
const MaximumComboLimit = 1_000_000

// Config controls a fuzzing run.
type Config struct {
	// Request
	Method      string
	URL         string
	Headers     map[string]string
	Cookies     map[string]string
	Body        string
	ContentType string

	// Wordlists
	DefaultWordlist wordlists.Options
	MarkerWordlists map[string]wordlists.Options // key = marker name (e.g. "FUZZ1")

	// Concurrency & rate
	Threads   int
	RateLimit int
	Delay     time.Duration
	Timeout   time.Duration

	// Filters (all optional)
	MatchStatus  []int
	FilterStatus []int
	MatchSize    []int64
	FilterSize   []int64
	MatchWords   []Range
	FilterWords  []Range
	MatchLines   []Range
	FilterLines  []Range
	MatchRegex   string
	FilterRegex  string
	MatchTime    string
	FilterTime   string

	// Behavior
	FollowRedirects bool
	MaxBodySize     int64
	Proxy           string

	// ConfirmExceeding, when true, allows the scan to proceed even if the
	// estimated request count exceeds MaximumComboLimit.
	ConfirmExceeding bool
}

// Defaults for the fuzzer.
const (
	DefaultThreads      = 40
	DefaultMaxBodySize  = 10 * 1024 * 1024 // 10MB
	DefaultFuzzCategory = wordlists.CategoryFuzz
	DefaultFuzzSize     = wordlists.SizeParameters
)

// combo is a single payload combination for one request.
type combo struct {
	payload map[string]string
}

// Result is a single fuzz response that passed filters.
type Result struct {
	Payload       map[string]string
	URL           string
	StatusCode    int
	ContentLength int64
	Words         int
	Lines         int
	Duration      time.Duration
	RedirectTo    string
	ContentType   string
	Matched       bool
	MatchReason   string
}

// Stats tracks cumulative fuzzing metrics.
type Stats struct {
	Hits      int64
	Checked   int64
	Total     int64
	Errors    int64
	StartedAt time.Time
	Duration  time.Duration
	Completed bool
}

// Fuzzer coordinates a fuzzing run across multiple markers.
type Fuzzer struct {
	cfg      Config
	client   *httpclient.Client
	selector *wordlists.Selector

	method  string
	body    string
	bKind   bodyKind
	headers map[string]string

	markers    []string
	markerList map[string][]string // marker -> payloads
	total      int64

	controller *rateController
	analyzer   *analyzer

	// stats
	mu      sync.Mutex
	hits    int64
	checked int64
	errs    int64
	started time.Time
	done    bool
}

// New constructs a Fuzzer from config, validating and normalizing inputs.
func New(cfg Config, httpClient *httpclient.Client, wlSelector *wordlists.Selector) *Fuzzer {
	cfg = applyFuzzDefaults(cfg)
	return &Fuzzer{
		cfg:      cfg,
		client:   httpClient,
		selector: wlSelector,
		method:   methodOrDefault(cfg.Method),
		body:     cfg.Body,
		bKind:    detectBodyKind(cfg.Body, cfg.ContentType),
		started:  time.Now(),
	}
}

// Stats returns a snapshot of current metrics.
func (f *Fuzzer) Stats() Stats {
	f.mu.Lock()
	defer f.mu.Unlock()
	return Stats{
		Hits:      f.hits,
		Checked:   f.checked,
		Total:     f.total,
		Errors:    f.errs,
		StartedAt: f.started,
		Duration:  time.Since(f.started),
		Completed: f.done,
	}
}

// Run executes the fuzz. It validates inputs, resolves wordlists, checks the
// combinatorics estimate, then streams payload combinations through a bounded
// worker pool. Returns a result channel and an error channel, both closed at
// completion or cancellation.
func (f *Fuzzer) Run(ctx context.Context) (<-chan Result, <-chan error) {
	out := make(chan Result)
	errCh := make(chan error, 1)

	go f.run(ctx, out, errCh)
	return out, errCh
}

func (f *Fuzzer) run(ctx context.Context, out chan<- Result, errCh chan<- error) {
	defer close(out)
	defer close(errCh)
	defer func() { f.mu.Lock(); f.done = true; f.mu.Unlock() }()

	// Input validation.
	if f.cfg.URL == "" {
		errCh <- ErrNoURL
		return
	}
	if f.client == nil {
		errCh <- ErrNoClient
		return
	}
	if f.selector == nil {
		errCh <- ErrNoSelector
		return
	}

	// Determine markers from URL + headers + cookies + body.
	markers := f.discoverMarkers()
	if len(markers) == 0 {
		errCh <- ErrNoMarkers
		return
	}
	f.markers = markers

	// Build request headers (with cookie merging) and injector.
	f.headers = (&payloadInjector{rawURL: f.cfg.URL, rawBody: f.body, bodyType: f.bKind}).buildRequestHeaders(f.cfg)
	injector := &payloadInjector{
		rawURL:   f.cfg.URL,
		rawBody:  f.body,
		bodyType: f.bKind,
		markers:  markers,
	}

	// Resolve wordlists per marker.
	if err := f.resolveWordlists(ctx); err != nil {
		errCh <- err
		return
	}
	f.computeTotal()

	// Combinatorics safety check.
	if f.total > MaximumComboLimit && !f.cfg.ConfirmExceeding {
		errCh <- fmt.Errorf("%w: %d combinations", ErrCombinatorics, f.total)
		return
	}

	// Baseline capture (mandatory for smart analysis).
	f.controller = newRateController(f.cfg)
	capture := newBaselineCapture(f.cfg, injector, f.client, f.controller)
	baseline, err := capture.Capture(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		errCh <- fmt.Errorf("baseline capture: %w", err)
		return
	}
	an, err := newAnalyzer(f.cfg, baseline)
	if err != nil {
		errCh <- err
		return
	}
	f.analyzer = an

	// Generate combinations into a task stream.
	taskCh := make(chan combo)
	var genWg sync.WaitGroup
	genWg.Add(1)
	go func() {
		defer genWg.Done()
		f.generate(ctx, taskCh)
	}()

	// Bounded worker pool.
	var workerWg sync.WaitGroup
	threads := f.cfg.Threads
	if threads <= 0 {
		threads = DefaultThreads
	}
	for i := 0; i < threads; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for c := range taskCh {
				f.process(ctx, injector, c.payload, out)
			}
		}()
	}

	genWg.Wait()
	close(taskCh)
	workerWg.Wait()
}

// discoverMarkers collects distinct FUZZ markers from URL, headers, cookies
// and body.
func (f *Fuzzer) discoverMarkers() []string {
	seen := map[string]bool{}
	var list []string
	add := func(s string) {
		for _, m := range extractMarkers(s) {
			if !seen[m] {
				seen[m] = true
				list = append(list, m)
			}
		}
	}
	add(f.cfg.URL)
	for _, v := range f.cfg.Headers {
		add(v)
	}
	for _, v := range f.cfg.Cookies {
		add(v)
	}
	add(f.body)
	return list
}

// resolveWordlists loads a payload list for each marker.
func (f *Fuzzer) resolveWordlists(ctx context.Context) error {
	f.markerList = make(map[string][]string, len(f.markers))
	for _, m := range f.markers {
		opts := f.wordlistForMarker(m)
		words, err := f.selector.Load(ctx, opts)
		if err != nil {
			return fmt.Errorf("load wordlist for marker %s: %w", m, err)
		}
		f.markerList[m] = words
	}
	return nil
}

// wordlistForMarker returns the Options to use for a marker, preferring a
// per-marker override and falling back to the default wordlist.
func (f *Fuzzer) wordlistForMarker(m string) wordlists.Options {
	if opts, ok := f.cfg.MarkerWordlists[m]; ok {
		return opts
	}
	return f.cfg.DefaultWordlist
}

// computeTotal sets f.total to the product of marker list sizes.
func (f *Fuzzer) computeTotal() {
	total := int64(1)
	for _, m := range f.markers {
		total *= int64(len(f.markerList[m]))
	}
	f.total = total
}

// generate emits every cartesian combination of marker payloads. If there is
// a single marker it iterates that list; with multiple markers it walks the
// cross-product via an index counter (never materializing all combinations in
// memory).
func (f *Fuzzer) generate(ctx context.Context, taskCh chan<- combo) {
	if len(f.markers) == 1 {
		m := f.markers[0]
		for _, v := range f.markerList[m] {
			select {
			case taskCh <- combo{payload: map[string]string{m: v}}:
			case <-ctx.Done():
				return
			}
		}
		return
	}

	sizes := make([]int, len(f.markers))
	for i, m := range f.markers {
		sizes[i] = len(f.markerList[m])
	}
	indices := make([]int, len(f.markers))

	done := false
	for !done {
		payload := make(map[string]string, len(f.markers))
		for i, m := range f.markers {
			payload[m] = f.markerList[m][indices[i]]
		}
		select {
		case taskCh <- combo{payload: payload}:
		case <-ctx.Done():
			return
		}

		// Increment the odometer.
		for i := len(indices) - 1; i >= 0; i-- {
			indices[i]++
			if indices[i] < sizes[i] {
				break
			}
			indices[i] = 0
			if i == 0 {
				done = true
			}
		}
	}
}

// process sends a single combination and analyzes the response.
func (f *Fuzzer) process(ctx context.Context, injector *payloadInjector, payload map[string]string, out chan<- Result) {
	if f.controller != nil {
		if err := f.controller.wait(ctx); err != nil {
			f.recordErr()
			return
		}
	}

	req := injector.render(payload)

	resp, err := f.client.Do(ctx, f.method, req.url, req.body, f.headers)
	if err != nil {
		f.recordErr()
		if ctx.Err() == nil && f.controller != nil {
			// Transient failure: treat as a generic throttle signal lightly.
			f.controller.noteResponse(0, "")
		}
		return
	}
	f.recordChecked()

	if f.controller != nil {
		f.controller.noteResponse(resp.StatusCode, resp.HeaderGet("Retry-After"))
	}

	matched, reason := f.analyzer.Analyze(resp, req.url)
	if !matched {
		return
	}

	res := Result{
		Payload:       payload,
		URL:           req.url,
		StatusCode:    resp.StatusCode,
		ContentLength: int64(len(resp.Body)),
		Words:         wordCount(resp.Body),
		Lines:         lineCount(resp.Body),
		Duration:      resp.Duration,
		RedirectTo:    resp.HeaderGet("Location"),
		ContentType:   resp.HeaderGet("Content-Type"),
		Matched:       true,
		MatchReason:   reason,
	}
	f.recordHit()

	select {
	case out <- res:
	case <-ctx.Done():
	}
}

func (f *Fuzzer) recordHit()     { f.mu.Lock(); f.hits++; f.mu.Unlock() }
func (f *Fuzzer) recordChecked() { f.mu.Lock(); f.checked++; f.mu.Unlock() }
func (f *Fuzzer) recordErr()     { f.mu.Lock(); f.errs++; f.mu.Unlock() }

// applyFuzzDefaults fills in defaults for zero-valued Config fields.
func applyFuzzDefaults(cfg Config) Config {
	if cfg.Threads <= 0 {
		cfg.Threads = DefaultThreads
	}
	if cfg.MaxBodySize <= 0 {
		cfg.MaxBodySize = DefaultMaxBodySize
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Headers == nil {
		cfg.Headers = make(map[string]string)
	}
	if cfg.Cookies == nil {
		cfg.Cookies = make(map[string]string)
	}
	if cfg.MarkerWordlists == nil {
		cfg.MarkerWordlists = make(map[string]wordlists.Options)
	}
	if cfg.DefaultWordlist.Category == "" {
		cfg.DefaultWordlist.Category = DefaultFuzzCategory
	}
	if cfg.DefaultWordlist.Size == "" {
		cfg.DefaultWordlist.Size = DefaultFuzzSize
	}
	return cfg
}

// detectBodyKind determines the body encoding context for marker escaping.
func detectBodyKind(body, contentType string) bodyKind {
	if strings.TrimSpace(body) == "" {
		return bodyNone
	}
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return bodyJSON
	}
	if contentType != "" {
		lower := strings.ToLower(contentType)
		if strings.Contains(lower, "json") {
			return bodyJSON
		}
		if strings.Contains(lower, "x-www-form-urlencoded") {
			return bodyForm
		}
	}
	return bodyRaw
}
