package subdomain

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	defaultResolverPort = "53"
	// wildcardProbeCount is how many random non-existent names we resolve at
	// startup to fingerprint a wildcard DNS record.
	wildcardProbeCount = 4
)

var (
	// ErrDNSQueryFailed is wrapped by the DNS engine when a single query
	// ultimately fails after retries.
	ErrDNSQueryFailed = errors.New("dns query failed")

	// ErrNoResolvers is returned when the resolver list is empty.
	ErrNoResolvers = errors.New("no DNS resolvers configured")
)

// dnsEngine runs concurrent DNS brute-force lookups over a bounded worker
// pool with wildcard detection, resolver rotation, and retries.
type dnsEngine struct {
	domain      string
	resolvers   []string
	concurrency int
	timeout     time.Duration
	retries     int
	rand        *rand.Rand
	randMu      sync.Mutex

	// wildcard detection
	probeMu    sync.Mutex
	wildcards  map[string]struct{} // set of wildcard IPs to filter
	resolvedIP map[string]struct{} // cache of probe-resolved IPs for shared-IP detection
	probed     bool

	client *dns.Client

	// filterOutPrivate controls dropping loopback/private IP results.
	filterOutPrivate bool

	// metrics
	queries *atomic.Int64

	// rate limiting backoff state (used to detect server throttling)
	throttleMu     sync.Mutex
	throttledUntil time.Time
}

// newDNSEngine builds a dnsEngine. It validates and normalizes the resolver
// list, constructing a dns.Client used for all queries. The client is shared
// across workers (miekg/dns Client is safe for concurrent use).
func newDNSEngine(cfg Config) (*dnsEngine, error) {
	resolvers := normalizeResolvers(cfg.Resolvers)
	if len(resolvers) == 0 {
		return nil, ErrNoResolvers
	}

	seed := time.Now().UnixNano()
	client := &dns.Client{
		Timeout: cfg.Timeout,
		Net:     "udp",
	}

	return &dnsEngine{
		domain:           cfg.Domain,
		resolvers:        resolvers,
		concurrency:      cfg.Concurrency,
		timeout:          cfg.Timeout,
		retries:          cfg.Retries,
		rand:             rand.New(rand.NewSource(seed)),
		wildcards:        make(map[string]struct{}),
		resolvedIP:       make(map[string]struct{}),
		client:           client,
		filterOutPrivate: cfg.FilterPrivate,
		queries:          &atomic.Int64{},
	}, nil
}

// QueryCount returns the number of DNS queries issued so far (for stats).
func (e *dnsEngine) QueryCount() int64 {
	return e.queries.Load()
}

// detectWildcard probes random subdomains of the base domain to fingerprint
// wildcard DNS records. It must be called once before streaming. After it
// completes, the wildcard IP set is used to filter brute-force results.
func (e *dnsEngine) detectWildcard(ctx context.Context) error {
	e.probeMu.Lock()
	defer e.probeMu.Unlock()
	if e.probed {
		return nil
	}
	e.probed = true

	var (
		wildIPs  = make(map[string]struct{})
		seenIPs  = make(map[string]int)
		firstRes *resolveResult
	)

	for i := 0; i < wildcardProbeCount; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		name := fmt.Sprintf("vexor-wildcard-probe-%d-%d.%s", i, time.Now().UnixNano(), e.domain)
		res, err := e.resolve(ctx, name, false, 0)
		if err != nil {
			// A failed probe simply means no wildcard answer for this name.
			continue
		}
		if firstRes == nil {
			firstRes = res
		}
		for _, ip := range res.IPs {
			seenIPs[ip]++
			e.resolvedIP[ip] = struct{}{}
		}
		if res.CNAME != "" {
			// Wildcard CNAMEs are also strong indicators.
			for _, ip := range res.IPs {
				wildIPs[ip] = struct{}{}
			}
		}
	}

	// A wildcard is confirmed when multiple random names (>= 2) resolved to
	// the SAME IP, or when there was a CNAME (single CNAME wildcard). We keep
	// it conservative: require at least two agreeing responses OR a CNAME.
	if firstRes != nil && firstRes.CNAME != "" {
		for _, ip := range firstRes.IPs {
			wildIPs[ip] = struct{}{}
		}
	} else {
		for ip, count := range seenIPs {
			if count >= 2 {
				wildIPs[ip] = struct{}{}
			}
		}
	}

	e.wildcards = wildIPs
	return nil
}

// isWildcardIP reports whether an IP is a known wildcard address.
func (e *dnsEngine) isWildcardIP(ip string) bool {
	e.probeMu.Lock()
	defer e.probeMu.Unlock()
	_, ok := e.wildcards[ip]
	return ok
}

// resolveResult holds the outcome of a successful DNS resolution.
type resolveResult struct {
	IPs   []string
	CNAME string
}

// resolve queries one full name, rotating resolvers on error and retrying
// truncated responses over TCP. filterWildcard drops wildcard IPs;
// retryBudget caps total attempts (0 means the engine default).
func (e *dnsEngine) resolve(ctx context.Context, fullName string, filterWildcard bool, retryBudget int) (*resolveResult, error) {
	if retryBudget <= 0 {
		retryBudget = e.retries + 1
	}

	startIdx := e.randomResolverIndex()

	for attempt := 0; attempt < retryBudget; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		if e.isThrottled() && attempt > 0 {
			if err := e.waitThrottle(ctx); err != nil {
				return nil, err
			}
		}

		resolver := e.resolvers[(startIdx+attempt)%len(e.resolvers)]
		res, truncated, err := e.queryOnce(ctx, fullName, resolver)

		switch {
		case err != nil:
			// Timeout/network error: try next resolver.
			e.maybeDetectThrottle(err)
			continue
		case truncated:
			// Retry this same name over TCP against the same resolver.
			tcpRes, tcpErr := e.queryOnceTCP(ctx, fullName, resolver)
			if tcpErr != nil {
				continue
			}
			res = tcpRes
		}

		if filterWildcard {
			filtered := res.IPs[:0]
			for _, ip := range res.IPs {
				if e.isWildcardIP(ip) {
					continue
				}
				filtered = append(filtered, ip)
			}
			res.IPs = filtered
		}

		if e.filterOutPrivate {
			filtered := res.IPs[:0]
			for _, ip := range res.IPs {
				if isPrivateOrLoopback(ip) {
					continue
				}
				filtered = append(filtered, ip)
			}
			res.IPs = filtered
		}

		if len(res.IPs) == 0 {
			// Resolved to only wildcard/private IPs: treat as not found.
			return nil, ErrDNSQueryFailed
		}

		return res, nil
	}

	return nil, ErrDNSQueryFailed
}

// queryOnce performs a single UDP lookup with miekg/dns and returns the
// resolved result plus whether the response was truncated (indicating a TCP
// retry is needed).
func (e *dnsEngine) queryOnce(ctx context.Context, fullName string, resolver string) (*resolveResult, bool, error) {
	e.queries.Add(1)

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fullName), dns.TypeA)
	m.RecursionDesired = true

	r, rtt, err := e.client.ExchangeContext(ctx, m, resolver)
	e.trackRTT(rtt)
	if err != nil {
		return nil, false, err
	}

	return e.parseResponse(fullName, r), r.Truncated, nil
}

// queryOnceTCP performs a TCP lookup, used as fallback for truncated UDP
// responses.
func (e *dnsEngine) queryOnceTCP(ctx context.Context, fullName string, resolver string) (*resolveResult, error) {
	e.queries.Add(1)

	tcpClient := &dns.Client{Timeout: e.timeout, Net: "tcp"}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fullName), dns.TypeA)
	m.RecursionDesired = true

	r, rtt, err := tcpClient.ExchangeContext(ctx, m, resolver)
	e.trackRTT(rtt)
	if err != nil {
		return nil, err
	}
	return e.parseResponse(fullName, r), nil
}

// parseResponse extracts the A records (and CNAME chain target) from a DNS
// reply, correctly handling NXDOMAIN/SERVFAIL/REFUSED and only following the
// first relevant CNAME for reporting.
func (e *dnsEngine) parseResponse(fullName string, r *dns.Msg) *resolveResult {
	res := &resolveResult{}

	if r == nil {
		return res
	}
	if r.Rcode != dns.RcodeSuccess {
		return res
	}

	cnameTarget := ""
	for _, ans := range r.Answer {
		switch v := ans.(type) {
		case *dns.A:
			res.IPs = append(res.IPs, v.A.String())
		case *dns.AAAA:
			res.IPs = append(res.IPs, v.AAAA.String())
		case *dns.CNAME:
			if cnameTarget == "" {
				cnameTarget = strings.TrimSuffix(v.Target, ".")
			}
		}
	}

	if cnameTarget != "" {
		res.CNAME = cnameTarget
	}
	return res
}

// isThrottled reports whether the engine is currently in a rate-limit backoff
// window.
func (e *dnsEngine) isThrottled() bool {
	e.throttleMu.Lock()
	defer e.throttleMu.Unlock()
	return time.Now().Before(e.throttledUntil)
}

// maybeDetectThrottle inspects a query error and, if it looks like rate
// limiting (e.g. i/o timeout bursts), schedules a short backoff.
func (e *dnsEngine) maybeDetectThrottle(err error) {
	if err == nil {
		return
	}
	var netErr net.Error
	if errors.Is(err, ErrDNSQueryFailed) || errors.As(err, &netErr) {
		// Don't hammer a throttling resolver; impose a brief cooldown.
		now := time.Now()
		e.throttleMu.Lock()
		if now.After(e.throttledUntil) {
			e.throttledUntil = now.Add(200 * time.Millisecond)
		}
		e.throttleMu.Unlock()
	}
}

// waitThrottle sleeps until the backoff window expires or the context is
// cancelled.
func (e *dnsEngine) waitThrottle(ctx context.Context) error {
	e.throttleMu.Lock()
	until := e.throttledUntil
	e.throttleMu.Unlock()

	if until.IsZero() || time.Now().After(until) {
		return nil
	}
	sleep := time.Until(until)
	timer := time.NewTimer(sleep)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// randomResolverIndex returns a random starting resolver index for rotation.
func (e *dnsEngine) randomResolverIndex() int {
	e.randMu.Lock()
	defer e.randMu.Unlock()
	return e.rand.Intn(len(e.resolvers))
}

// trackRTT reserved for latency metrics.
func (e *dnsEngine) trackRTT(_ time.Duration) {}

// runActive feeds a bounded worker pool from the word stream and writes
// resolved names to out, closing it when all work is done.
func (e *dnsEngine) runActive(ctx context.Context, words <-chan string, baseDomain string, out chan<- Result) {
	work := make(chan string)
	var wg sync.WaitGroup

	for i := 0; i < e.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for fullName := range work {
				if ctx.Err() != nil {
					return
				}
				res, err := e.resolve(ctx, fullName, true, 0)
				if err != nil {
					continue
				}
				select {
				case out <- Result{
					Subdomain: fullName,
					IPs:       res.IPs,
					Source:    "dns",
					CNAME:     res.CNAME,
				}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Feed the workers. Stop reading words once the context is cancelled or
	// the stream closes.
feedLoop:
	for word := range words {
		label := normalizeSubdomain(word)
		if !validSubdomainName(label) {
			continue
		}
		fullName := label + "." + baseDomain
		select {
		case work <- fullName:
		case <-ctx.Done():
			break feedLoop
		}
	}

	close(work)
	wg.Wait()
	close(out)
}

// normalizeResolvers validates and normalizes resolver addresses, appending
// the default DNS port where absent. It returns nil if the input is empty or
// all entries are invalid.
func normalizeResolvers(resolvers []string) []string {
	if len(resolvers) == 0 {
		return nil
	}
	out := make([]string, 0, len(resolvers))
	for _, r := range resolvers {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(r); err != nil {
			// No port specified: assume the DNS port.
			r = net.JoinHostPort(r, defaultResolverPort)
		}
		out = append(out, r)
	}
	return out
}

// validSubdomainName reports whether a single label is acceptable for DNS
// brute force. It permits letters, digits, hyphens and underscores (some
// real-world hosts use underscores), and rejects empty/oversized labels.
func validSubdomainName(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

// normalizeSubdomain lowercases and trims whitespace from a prospective
// subdomain label (or full name).
func normalizeSubdomain(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// isWildcardEntry reports whether a crt.sh name_value entry is a wildcard
// like `*.example.com` (leading `*.`).
func isWildcardEntry(name string) bool {
	return strings.HasPrefix(strings.TrimSpace(name), "*.")
}

// isPrivateOrLoopback reports whether ip is within a private, link-local, or
// loopback range.
func isPrivateOrLoopback(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback() ||
		parsed.IsPrivate() ||
		parsed.IsLinkLocalUnicast() ||
		parsed.IsLinkLocalMulticast() ||
		parsed.IsUnspecified() ||
		parsed.IsMulticast()
}
