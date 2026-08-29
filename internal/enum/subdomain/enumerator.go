package subdomain

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/0xseif-code/vexor/internal/httpclient"
	"github.com/0xseif-code/vexor/internal/wordlists"
)

// Default configuration values.
const (
	DefaultConcurrency = 100
	DefaultTimeout     = 3 * time.Second
	DefaultRetries     = 2
)

// DefaultResolvers are the public DNS servers used when none are configured.
var DefaultResolvers = []string{
	"8.8.8.8:53",
	"1.1.1.1:53",
	"9.9.9.9:53",
}

var (
	// ErrNoDomain indicates the target domain is empty or invalid.
	ErrNoDomain = errors.New("no domain specified")

	// ErrWordlist indicates the wordlist could not be loaded.
	ErrWordlist = errors.New("wordlist error")
)

// Config controls the behaviour of a subdomain enumeration run.
type Config struct {
	Domain       string
	Resolvers    []string
	Concurrency  int
	Timeout      time.Duration
	Retries      int
	ActiveOnly   bool
	PassiveOnly  bool
	WordlistOpts wordlists.Options

	// FilterPrivate, when true, drops subdomains that only resolve to
	// loopback/private addresses. Optional; defaults to false.
	FilterPrivate bool
}

// Result is a single discovered subdomain.
type Result struct {
	Subdomain string
	IPs       []string
	Source    string // "dns" or "crtsh"
	CNAME     string // if any
}

// Stats tracks cumulative enumeration metrics.
type Stats struct {
	Found      int
	FromDNS    int
	FromCRTSH  int
	Checked    int64
	TotalWords int64
	Queries    int64
	StartedAt  time.Time
	Duration   time.Duration
	ActiveErr  error
	PassiveErr error
}

// Enumerator coordinates active DNS brute-force and passive crt.sh
// enumeration, merging results into a single deduplicated stream.
type Enumerator struct {
	cfg        Config
	httpClient *httpclient.Client
	selector   *wordlists.Selector
	domain     string
	engine     *dnsEngine

	mu    sync.Mutex
	seen  map[string]bool // lowercased full subdomain -> seen
	stats Stats
}

// New constructs an Enumerator, applying defaults and normalizing the domain.
func New(cfg Config, httpClient *httpclient.Client, wlSelector *wordlists.Selector) *Enumerator {
	cfg = applyDefaults(cfg)
	return &Enumerator{
		cfg:        cfg,
		httpClient: httpClient,
		selector:   wlSelector,
		domain:     cleanDomain(cfg.Domain),
		seen:       make(map[string]bool),
		stats: Stats{
			TotalWords: -1, // unknown until stream resolves word count
			StartedAt:  time.Now(),
		},
	}
}

// CleanDomain returns the normalized base domain after construction.
func (e *Enumerator) CleanDomain() string {
	return e.domain
}

// Stats returns a snapshot of the current enumeration metrics.
func (e *Enumerator) Stats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.stats
	s.Duration = time.Since(s.StartedAt)
	if e.engine != nil {
		s.Checked = e.engine.QueryCount()
		s.Queries = e.engine.QueryCount()
	}
	return s
}

// Run executes the enumeration. It returns a channel of discovered
// subdomains and a channel of non-fatal errors. Both channels are always
// closed when the operation completes or is cancelled. The caller should
// range over the results channel; once it closes, the scan is finished.
func (e *Enumerator) Run(ctx context.Context) (<-chan Result, <-chan error) {
	out := make(chan Result)
	errCh := make(chan error, 1)

	if e.domain == "" {
		go func() {
			defer close(out)
			defer close(errCh)
			errCh <- ErrNoDomain
		}()
		return out, errCh
	}

	engine, err := newDNSEngine(e.cfg)
	if err != nil {
		go func() {
			defer close(out)
			defer close(errCh)
			errCh <- fmt.Errorf("init dns engine: %w", err)
		}()
		return out, errCh
	}
	e.engine = engine

	go e.run(ctx, out, errCh)
	return out, errCh
}

// run is the internal orchestrator goroutine. It launches the active and
// passive phases concurrently and merges their results.
func (e *Enumerator) run(ctx context.Context, out chan<- Result, errCh chan<- error) {
	defer close(out)
	defer close(errCh)

	var wg sync.WaitGroup

	// Active DNS phase.
	if !e.cfg.PassiveOnly {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.runActive(ctx, out)
		}()
	}

	// Passive crt.sh phase.
	if !e.cfg.ActiveOnly {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.runCRTSH(ctx, out)
		}()
	}

	// Wait for both phases to complete, then finalize stats.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}

	e.mu.Lock()
	e.stats.Duration = time.Since(e.stats.StartedAt)
	e.mu.Unlock()
}

// runActive performs the DNS brute-force phase.
func (e *Enumerator) runActive(ctx context.Context, out chan<- Result) {
	// Wildcard detection must run before streaming results so that
	// filtering is in effect.
	if err := e.engine.detectWildcard(ctx); err != nil {
		if ctx.Err() == nil {
			e.setActiveErr(fmt.Errorf("wildcard detection: %w", err))
		}
	}

	if e.selector == nil {
		e.setActiveErr(errors.New("wordlist selector not configured"))
		return
	}

	words, werrs, err := e.selector.LoadStream(ctx, e.cfg.WordlistOpts)
	if err != nil {
		e.setActiveErr(fmt.Errorf("%w: %v", ErrWordlist, err))
		return
	}

	// Wrap the word stream so we can count words as they flow into the DNS
	// engine, without loading the full list into memory.
	counted := make(chan string, 64)
	go func() {
		defer close(counted)
		var total int64
		defer func() {
			e.mu.Lock()
			e.stats.TotalWords = total
			e.mu.Unlock()
		}()
		for {
			select {
			case w, ok := <-words:
				if !ok {
					return
				}
				total++
				select {
				case counted <- w:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Drain wordlist error channel in the background.
	go func() {
		for werr := range werrs {
			if ctx.Err() != nil {
				return
			}
			e.setActiveErr(fmt.Errorf("%w: %v", ErrWordlist, werr))
		}
	}()

	// Run the DNS engine against the counted stream. It blocks until all
	// words are exhausted and workers finish. Results are routed through a
	// dispatcher that performs central dedup via emit before reaching out.
	engineOut := make(chan Result)
	dispatchDone := make(chan struct{})
	go func() {
		defer close(dispatchDone)
		for r := range engineOut {
			e.emit(r.Subdomain, r.IPs, r.Source, r.CNAME, out)
		}
	}()

	e.engine.runActive(ctx, counted, e.domain, engineOut)
	<-dispatchDone
}

// runCRTSH performs the passive crt.sh phase. Failures are logged via the
// error channel but never abort the overall scan.
func (e *Enumerator) runCRTSH(ctx context.Context, out chan<- Result) {
	if e.httpClient == nil {
		e.setPassiveErr(errors.New("http client not configured"))
		return
	}

	c := newCRTSHClient(e.httpClient, e.domain)
	names, err := c.Query(ctx)
	if err != nil {
		if ctx.Err() == nil {
			e.setPassiveErr(err)
		}
		return
	}

	for _, host := range names {
		if ctx.Err() != nil {
			return
		}
		// crt.sh returns full hostnames. Keep only those that are proper
		// subdomains of the target (skip the bare domain itself and any
		// unrelated hosts).
		if !isSubdomainOf(host, e.domain) {
			continue
		}
		e.emit(host, nil, "crtsh", "", out)
	}
}

// isSubdomainOf reports whether name is a subdomain strictly below base
// (i.e. name ends with "."+base and is longer than base). This is
// case-insensitive.
func isSubdomainOf(name, base string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	base = strings.ToLower(strings.TrimSuffix(base, "."))
	if name == base {
		return false
	}
	return strings.HasSuffix(name, "."+base)
}

// emit adds a found subdomain to a central deduplicated store and, if new,
// forwards it to the output channel. The source of the first sighting wins.
func (e *Enumerator) emit(subdomain string, ips []string, source, cname string, out chan<- Result) {
	key := normalizeSubdomain(subdomain)

	e.mu.Lock()
	if e.seen[key] {
		e.mu.Unlock()
		return
	}
	e.seen[key] = true
	e.stats.Found++
	if source == "dns" {
		e.stats.FromDNS++
	} else if source == "crtsh" {
		e.stats.FromCRTSH++
	}
	res := Result{
		Subdomain: key,
		IPs:       ips,
		Source:    source,
		CNAME:     cname,
	}
	e.mu.Unlock()

	out <- res
}

// setActiveErr records the active phase failure if none is recorded yet.
func (e *Enumerator) setActiveErr(err error) {
	e.mu.Lock()
	if e.stats.ActiveErr == nil {
		e.stats.ActiveErr = err
	}
	e.mu.Unlock()
}

// setPassiveErr records the passive phase failure if none is recorded yet.
func (e *Enumerator) setPassiveErr(err error) {
	e.mu.Lock()
	if e.stats.PassiveErr == nil {
		e.stats.PassiveErr = err
	}
	e.mu.Unlock()
}

// applyDefaults fills in default values for any zero Config fields.
func applyDefaults(cfg Config) Config {
	if len(cfg.Resolvers) == 0 {
		cfg.Resolvers = DefaultResolvers
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = DefaultConcurrency
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Retries < 0 {
		cfg.Retries = 0
	} else if cfg.Retries == 0 {
		cfg.Retries = DefaultRetries
	}
	if cfg.WordlistOpts.Category == "" {
		cfg.WordlistOpts.Category = wordlists.CategorySubdomain
	}
	if cfg.WordlistOpts.Size == "" {
		cfg.WordlistOpts.Size = wordlists.SizeMedium
	}
	return cfg
}

// cleanDomain normalizes the target domain by stripping protocol, path, port,
// and trailing slashes. If a subdomain is present it is kept as-is.
func cleanDomain(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	// Strip protocol if present.
	if idx := strings.Index(raw, "://"); idx != -1 {
		raw = raw[idx+3:]
	}

	// Strip path/query/fragment.
	if idx := strings.IndexAny(raw, "/?#"); idx != -1 {
		raw = raw[:idx]
	}

	// Strip port if present.
	if h, p, err := splitHostPort(raw); err == nil && p != "" {
		_ = p
		raw = h
	}

	raw = strings.TrimSuffix(raw, ".")
	raw = strings.ToLower(raw)

	// Validate it could be a hostname.
	u, err := url.Parse("http://" + raw)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return raw
}

// splitHostPort splits host:port only when a numeric port is present.
func splitHostPort(hostport string) (string, string, error) {
	host := hostport
	port := ""

	// Only split when there's a colon that's not the last char and the part
	// after it is numeric.
	if i := strings.LastIndex(hostport, ":"); i > 0 && i < len(hostport)-1 {
		candidate := hostport[i+1:]
		if allDigits(candidate) {
			host = hostport[:i]
			port = candidate
		}
	}
	if port == "" {
		return host, "", fmt.Errorf("no port")
	}
	return host, port, nil
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}
