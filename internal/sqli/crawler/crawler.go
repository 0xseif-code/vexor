// Package crawler finds potential SQLi targets: it walks a site's HTML,
// pulls links and forms, and reports URLs with testable parameters.
package crawler

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0xseif-code/vexor/internal/httpclient"
)

// Config controls crawler behaviour.
type Config struct {
	StartURL        string
	MaxDepth        int  // default 2
	SameDomainOnly  bool // default true
	IgnoreRobots    bool // default false
	RateLimit       int  // max requests/sec; 0 = unlimited
	UserAgent       string
	Cookies         map[string]string
	ExcludePatterns []string // regex patterns of paths to skip
}

// Discovery is one discovered candidate injection point.
type Discovery struct {
	URL        string
	Method     string            // GET or POST
	Parameters []string          // param names found
	FormFields map[string]string // for POST forms (name -> value)
	Depth      int
}

// Stats aggregates crawl counters.
type Stats struct {
	PagesSeen   int64
	LinksFound  int64
	Discoveries int64
	Errors      int64
	Visited     int64
}

// maxPaginations caps how many pages from the same param-less path pattern are
// followed, preventing infinite ?page=1,2,3,... loops.
const maxPaginations = 50

// pageJob is a unit of crawl work.
type pageJob struct {
	url   string
	depth int
}

// Crawler walks a site starting from a seed URL.
type Crawler struct {
	cfg    Config
	client *httpclient.Client

	seedHost string

	visited   map[string]bool
	visitedMu sync.Mutex

	discovered map[string]bool
	discMu     sync.Mutex

	patternCount map[string]int
	patternMu    sync.Mutex

	rateTicker *time.Ticker

	stats struct {
		pagesSeen   atomic.Int64
		linksFound  atomic.Int64
		discoveries atomic.Int64
		errors      atomic.Int64
		visited     atomic.Int64
	}
}

// New builds a Crawler with defaults applied.
func New(cfg Config, client *httpclient.Client) *Crawler {
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 2
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = httpclient.DefaultUserAgent
	}
	c := &Crawler{
		cfg:          cfg,
		client:       client,
		visited:      map[string]bool{},
		discovered:   map[string]bool{},
		patternCount: map[string]int{},
	}
	if cfg.RateLimit > 0 {
		c.rateTicker = time.NewTicker(time.Second / time.Duration(cfg.RateLimit))
	}
	return c
}

// Stop releases the rate ticker.
func (c *Crawler) Stop() {
	if c.rateTicker != nil {
		c.rateTicker.Stop()
	}
}

// Run crawls the site, streaming discoveries and errors on two channels that
// are closed when the crawl completes. Stop is called automatically.
func (c *Crawler) Run(ctx context.Context) (<-chan Discovery, <-chan error) {
	discCh := make(chan Discovery, 64)
	errCh := make(chan error, 16)
	go c.run(ctx, discCh, errCh)
	return discCh, errCh
}

func (c *Crawler) run(ctx context.Context, discCh chan<- Discovery, errCh chan<- error) {
	defer close(discCh)
	defer close(errCh)
	defer c.Stop()

	seed, err := url.Parse(c.cfg.StartURL)
	if err != nil {
		select {
		case errCh <- fmt.Errorf("crawl start URL: %w", err):
		case <-ctx.Done():
		}
		return
	}
	c.seedHost = strings.ToLower(seed.Host)

	// Respect robots.txt unless disabled.
	if !c.cfg.IgnoreRobots {
		disallowed, rerr := c.loadRobots(ctx, seed)
		if rerr == nil && len(disallowed) > 0 {
			if robotsDisallowsAll(disallowed) {
				select {
				case errCh <- fmt.Errorf("robots.txt disallows entire site; use --ignore-robots to continue"):
				case <-ctx.Done():
				}
				return
			}
			select {
			case errCh <- fmt.Errorf("robots.txt lists %d disallowed path(s); respecting them", len(disallowed)):
			default:
			}
		} else if rerr != nil {
			select {
			case errCh <- fmt.Errorf("robots.txt: %v", rerr):
			default:
			}
		}
	}

	// Breadth-first working queue of pages to fetch.
	work := []pageJob{}
	c.enqueueBFS(&work, seed.String(), 0)

	for len(work) > 0 && ctx.Err() == nil {
		if c.rateTicker != nil {
			select {
			case <-c.rateTicker.C:
			case <-ctx.Done():
				return
			}
		}
		current := work[0]
		work = work[1:]
		children := c.crawlPage(ctx, current.url, current.depth, discCh, errCh)
		for _, ch := range children {
			c.enqueueBFS(&work, ch.url, ch.depth)
		}
	}
}

// enqueueBFS adds a page to the worklist if it has not been visited and the
// pagination pattern has not exceeded its cap.
func (c *Crawler) enqueueBFS(work *[]pageJob, u string, depth int) {
	if !c.markVisited(u) {
		return
	}
	if depth > c.cfg.MaxDepth {
		return
	}
	key := paramLessKey(u)
	c.patternMu.Lock()
	if c.patternCount[key] >= maxPaginations {
		c.patternMu.Unlock()
		return
	}
	c.patternCount[key]++
	c.patternMu.Unlock()
	*work = append(*work, pageJob{url: u, depth: depth})
}

func (c *Crawler) markVisited(u string) bool {
	c.visitedMu.Lock()
	defer c.visitedMu.Unlock()
	if c.visited[u] {
		return false
	}
	c.visited[u] = true
	return true
}

func (c *Crawler) loadRobots(ctx context.Context, seed *url.URL) ([]string, error) {
	robotsURL := seed.Scheme + "://" + seed.Host + "/robots.txt"
	resp, err := c.get(ctx, robotsURL)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.StatusCode != 200 {
		return nil, nil
	}
	disallowed := parseRobots(resp.BodyString())
	return disallowed, nil
}

func robotsDisallowsAll(disallowed []string) bool {
	for _, d := range disallowed {
		if strings.TrimSpace(d) == "/" {
			return true
		}
	}
	return false
}

// get issues a GET with the configured cookies and headers.
func (c *Crawler) get(ctx context.Context, target string) (*httpclient.Response, error) {
	headers := map[string]string{}
	if len(c.cfg.Cookies) > 0 {
		var sb strings.Builder
		first := true
		for k, v := range c.cfg.Cookies {
			if !first {
				sb.WriteString("; ")
			}
			sb.WriteString(k)
			sb.WriteString("=")
			sb.WriteString(v)
			first = false
		}
		headers["Cookie"] = sb.String()
	}
	return c.client.Get(ctx, target, headers)
}

// crawlPage fetches one page, extracts links/forms, streams discoveries, and
// returns child pages to queue. A single page failure never kills the crawl;
// its error is streamed as non-fatal.
func (c *Crawler) crawlPage(ctx context.Context, pageURL string, depth int, discCh chan<- Discovery, errCh chan<- error) []pageJob {
	c.stats.visited.Add(1)
	var children []pageJob

	resp, err := c.get(ctx, pageURL)
	if err != nil {
		c.stats.errors.Add(1)
		if ctx.Err() == nil {
			select {
			case errCh <- fmt.Errorf("crawl %s: %v", pageURL, err):
			default:
			}
		}
		return children
	}
	c.stats.pagesSeen.Add(1)

	// Only parse HTML-ish content.
	ct := strings.ToLower(resp.HeaderGet("Content-Type"))
	if ct != "" && !strings.Contains(ct, "html") && !strings.Contains(ct, "xhtml") {
		return children
	}

	base, err := url.Parse(pageURL)
	if err != nil {
		return children
	}

	links, forms := extractPage(resp.Body, pageURL)

	nextDepth := depth + 1

	// Report GET discoveries from query-parameter links.
	for _, l := range links {
		c.stats.linksFound.Add(1)
		abs := resolveURL(base, l)
		if abs == "" || !c.sameDomain(abs) || c.excluded(abs) {
			continue
		}
		if nextDepth <= c.cfg.MaxDepth {
			children = append(children, pageJob{url: abs, depth: nextDepth})
		}
		u, err := url.Parse(abs)
		if err == nil && u.RawQuery != "" {
			params := collectParams(u.RawQuery)
			if len(params) > 0 && c.reportDiscovery(abs, params) {
				c.stats.discoveries.Add(1)
				select {
				case discCh <- Discovery{URL: abs, Method: "GET", Parameters: params, Depth: depth}:
				case <-ctx.Done():
					return children
				}
			}
		}
	}

	// Report POST discoveries from forms.
	for _, f := range forms {
		c.stats.linksFound.Add(1)
		target := f.action
		if target == "" {
			target = base.Path
			if target == "" {
				target = "/"
			}
		}
		abs := resolveURL(base, target)
		if abs == "" || !c.sameDomain(abs) || c.excluded(abs) {
			continue
		}
		fields := f.fields
		if len(fields) == 0 {
			continue
		}
		keys := fieldKeys(fields)
		if c.reportDiscovery(abs, keys) {
			c.stats.discoveries.Add(1)
			select {
			case discCh <- Discovery{URL: abs, Method: "POST", FormFields: fields, Parameters: keys, Depth: depth}:
			case <-ctx.Done():
				return children
			}
		}
	}
	return children
}

func fieldKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func (c *Crawler) reportDiscovery(abs string, params []string) bool {
	c.discMu.Lock()
	defer c.discMu.Unlock()
	key := abs + "|" + strings.Join(params, ",")
	if c.discovered[key] {
		return false
	}
	c.discovered[key] = true
	return true
}

func paramLessKey(u string) string {
	if idx := strings.IndexByte(u, '?'); idx >= 0 {
		return u[:idx]
	}
	return u
}

func collectParams(rawQuery string) []string {
	var out []string
	for _, pair := range strings.Split(rawQuery, "&") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) > 0 && kv[0] != "" {
			out = append(out, kv[0])
		}
	}
	return out
}

// resolveURL resolves a (possibly relative) URL reference against base.
func resolveURL(base *url.URL, ref string) string {
	target, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(target)
	if resolved == nil {
		return ""
	}
	resolved.Fragment = ""
	return resolved.String()
}

func (c *Crawler) sameDomain(u string) bool {
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}
	if !c.cfg.SameDomainOnly {
		return true
	}
	return strings.EqualFold(parsed.Host, c.seedHost)
}

func (c *Crawler) excluded(u string) bool {
	for _, pat := range c.cfg.ExcludePatterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			continue
		}
		if re.MatchString(u) {
			return true
		}
	}
	return false
}

// Stats returns a point-in-time snapshot of crawl counters.
func (c *Crawler) Stats() Stats {
	return Stats{
		PagesSeen:   c.stats.pagesSeen.Load(),
		LinksFound:  c.stats.linksFound.Load(),
		Discoveries: c.stats.discoveries.Load(),
		Errors:      c.stats.errors.Load(),
		Visited:     c.stats.visited.Load(),
	}
}
