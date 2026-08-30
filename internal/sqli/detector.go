// Package sqli is Vexor's SQL injection engine: enumerate injection points,
// fingerprint the backend, run the detection techniques, stream findings.
package sqli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0xseif-code/vexor/internal/httpclient"
	"github.com/0xseif-code/vexor/internal/sqli/common"
	"github.com/0xseif-code/vexor/internal/sqli/dbms"
	"github.com/0xseif-code/vexor/internal/sqli/injection"
	"github.com/0xseif-code/vexor/internal/sqli/tamper"
	"github.com/0xseif-code/vexor/internal/sqli/techniques"
	"github.com/0xseif-code/vexor/internal/sqli/ui"
)

// InjectionPoint is re-exported for callers that render requests themselves.
type InjectionPoint = injection.InjectionPoint

// ErrNoTarget is returned when neither URL nor raw request file is set.
var ErrNoTarget = errors.New("no target: set URL or RawRequestFile")

// Config configures one scan.
type Config struct {
	URL            string
	RawRequestFile string
	TLS            bool
	Method         string
	Headers        map[string]string
	Cookies        map[string]string
	Body           string
	ContentType    string
	TestParameter  string
	SkipParameter  []string
	Level          int
	Risk           int
	Techniques     []string
	ForceDBMS      string
	OOBDomain      string
	Threads        int
	Delay          time.Duration
	Sleep          time.Duration
	Timeout        time.Duration
	Retries        int
	Proxy          string
	Progress       io.Writer
	// Fast switches the engine into minimal-probe mode: single-sample
	// baselines, no confirmation re-probes, error/union techniques tried
	// first. Intended for quick triage on LAN targets.
	Fast bool
	// Batch disables interactive prompts: every user decision (DBMS filter,
	// WAF tampering, parameter narrowing) resolves to its default. Useful for
	// scripting and CI. When false, prompts still fall back to defaults when
	// stdin is not a terminal.
	Batch bool
}

// Detection is a confirmed SQL injection finding at one point.
type Detection struct {
	Point      InjectionPoint
	Technique  string
	DBMS       string
	Payload    string
	Evidence   string
	Confidence int
}

// Stats aggregates scan counters.
type Stats struct {
	Requests  int64
	Errors    int64
	Points    int
	Findings  int64
	DBMS      string
	StartedAt time.Time
	Elapsed   time.Duration
}

// Detector runs a scan. Construct with New and drive with Run.
type Detector struct {
	cfg      Config
	client   *httpclient.Client
	meter    *common.Meter
	progress func(format string, args ...any)
	findings atomic.Int64
	scanned  atomic.Int64
	startMut sync.Mutex
	startAt  time.Time

	// filterDB, when set, narrows the payload sets to one backend only. It is
	// locked in by the DBMS filter prompt (or batch default).
	filterDB    string
	filterAsked atomic.Bool

	// skipRemaining stops the scan from picking up further untested injection
	// points once the user opts to keep testing only the current parameter.
	skipRemaining  atomic.Bool
	heuristicAsked atomic.Bool

	// wafAsked guards the one-shot WAF tamper prompt; tamperChain holds the
	// recommended chain (if accepted) applied to confirmed payloads.
	wafAsked   atomic.Bool
	tamperChain *tamper.Chain
}

// New builds a Detector with defaults applied.
func New(cfg Config, httpClient *httpclient.Client) *Detector {
	if cfg.Level < 1 {
		cfg.Level = 1
	}
	if cfg.Risk < 1 {
		cfg.Risk = 1
	}
	if cfg.Threads < 1 {
		cfg.Threads = 10
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 8 * time.Second
	}
	if cfg.Progress == nil {
		cfg.Progress = io.Discard
	}
	// Propagate the caller's batch preference to the shared prompt engine so
	// every sqli subsystem (detection and enumeration) honours it.
	ui.SetBatch(cfg.Batch)
	d := &Detector{
		cfg:      cfg,
		client:   httpClient,
		meter:    &common.Meter{},
		progress: func(format string, args ...any) { fmt.Fprintf(cfg.Progress, format+"\n", args...) },
	}
	return d
}

// requestSource turns the config into a request the injection package can
// slice into points.
func (d *Detector) requestSource() (injection.RequestSource, error) {
	if d.cfg.RawRequestFile != "" {
		data, err := os.ReadFile(d.cfg.RawRequestFile)
		if err != nil {
			return injection.RequestSource{}, fmt.Errorf("read raw request: %w", err)
		}
		rr, err := injection.ParseRaw(data, d.cfg.TLS)
		if err != nil {
			return injection.RequestSource{}, err
		}
		abs := rr.AbsoluteURL(d.cfg.TLS)
		if abs == rr.Target {
			return injection.RequestSource{}, errors.New("raw request is missing a Host header")
		}
		return injection.RequestSource{Method: rr.Method, URL: abs, Headers: rr.Headers, Body: rr.Body}, nil
	}

	if d.cfg.URL == "" {
		return injection.RequestSource{}, ErrNoTarget
	}
	method := d.cfg.Method
	if method == "" {
		method = "GET"
	}
	var headers []injection.Header
	keys := make([]string, 0, len(d.cfg.Headers))
	for k := range d.cfg.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		headers = append(headers, injection.Header{Key: k, Value: d.cfg.Headers[k]})
	}
	if d.cfg.ContentType != "" {
		headers = append(headers, injection.Header{Key: "Content-Type", Value: d.cfg.ContentType})
	}
	if len(d.cfg.Cookies) > 0 {
		var sb strings.Builder
		cookieKeys := make([]string, 0, len(d.cfg.Cookies))
		for k := range d.cfg.Cookies {
			cookieKeys = append(cookieKeys, k)
		}
		sort.Strings(cookieKeys)
		for i, k := range cookieKeys {
			if i > 0 {
				sb.WriteString("; ")
			}
			sb.WriteString(k)
			sb.WriteString("=")
			sb.WriteString(d.cfg.Cookies[k])
		}
		headers = append(headers, injection.Header{Key: "Cookie", Value: sb.String()})
	}
	return injection.RequestSource{
		Method:  method,
		URL:     d.cfg.URL,
		Headers: headers,
		Body:    []byte(d.cfg.Body),
	}, nil
}

// optionsFor mirrors the cfg into the injection enumeration options.
func (d *Detector) optionsFor() injection.Options {
	return injection.Options{
		Level:         d.cfg.Level,
		TestParameter: d.cfg.TestParameter,
		SkipParameter: d.cfg.SkipParameter,
	}
}

func (d *Detector) sleepSeconds() string {
	s := d.cfg.Sleep
	if s < time.Second {
		s = 5 * time.Second
	}
	return fmt.Sprintf("%d", int(s.Seconds()))
}

// Run scans until ctx is done or the target is exhausted. Findings stream on
// the first channel; non-fatal problems on the second. Both are closed when
// the scan completes.
func (d *Detector) Run(ctx context.Context) (<-chan Detection, <-chan error) {
	det := make(chan Detection, 64)
	errCh := make(chan error, 8)
	go d.run(ctx, det, errCh)
	return det, errCh
}

func (d *Detector) run(ctx context.Context, det chan<- Detection, errCh chan<- error) {
	defer close(det)
	defer close(errCh)
	d.startMut.Lock()
	if d.startAt.IsZero() {
		d.startAt = time.Now()
	}
	d.startMut.Unlock()

	src, err := d.requestSource()
	if err != nil {
		select {
		case errCh <- err:
		case <-ctx.Done():
		}
		return
	}

	points, err := injection.Enumerate(src, d.optionsFor())
	if err != nil {
		select {
		case errCh <- err:
		case <-ctx.Done():
		}
		return
	}

	d.progress("scanning %s (%d injection point%s)", src.URL, len(points), plural(len(points)))

	// backend fingerprinting happens once, on the first point. It is cheap
	// (error-signature pokes only); the confirmed technique carries the DBMS
	// name when fingerprinting cannot.
	db := d.resolveDBMS(ctx, points[0])

	throttle := common.NewThrottle(d.cfg.Delay)
	runnerCfg := techniques.Config{
		Throttle:  throttle,
		Timeout:   d.cfg.Timeout,
		Risk:      d.cfg.Risk,
		Delay:     d.sleepSeconds(),
		OOBDomain: d.cfg.OOBDomain,
		Meter:     d.meter,
		Fast:      d.cfg.Fast,
		Parallel:  d.cfg.Threads,
	}

	stopRate := d.startRateReporter(ctx)
	defer stopRate()

	jobs := make(chan *InjectionPoint)
	var wg sync.WaitGroup
	workers := d.cfg.Threads
	if workers > len(points) {
		workers = len(points)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pt := range jobs {
				d.scanPoint(ctx, pt, db, runnersConfig{runnerCfg, throttle}, det, errCh)
			}
		}()
	}
	for _, pt := range points {
		// If the user asked to keep testing only the first flagged parameter,
		// stop scheduling the rest.
		if d.skipRemaining.Load() {
			break
		}
		select {
		case jobs <- pt:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()
}

type runnersConfig struct {
	techniques.Config
	throttle common.Throttle
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func (d *Detector) resolveDBMS(ctx context.Context, pt *InjectionPoint) string {
	if forced := d.cfg.ForceDBMS; forced != "" {
		name := dbms.NormalizeName(forced)
		if p := dbms.Get(name); p != nil {
			d.progress("forcing backend: %s", p.Name)
			return p.Name
		}
		d.progress("warn: unknown --dbms %q, scanning without backend assumptions", forced)
		return dbms.Generic
	}
	fp := &dbms.Fingerprinter{
		Client:   d.client,
		Throttle: common.NewThrottle(d.cfg.Delay),
		Timeout:  d.cfg.Timeout,
		Meter:    d.meter,
		Point:    pt,
	}
	name, err := fp.Run(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return dbms.Generic
		}
		d.progress("fingerprinting incomplete (%v), continuing as %s", err, dbms.Generic)
		return dbms.Generic
	}
	if name != dbms.Generic {
		d.progress("backend identified: %s", name)
	}
	// Ask whether to restrict payload sets to this one backend. In batch mode
	// (or non-TTY) this defaults to yes, which matches the fingerprint-oriented
	// behaviour of the engine.
	if name != dbms.Generic && d.filterAsked.CompareAndSwap(false, true) {
		if ui.AskYesNo(fmt.Sprintf("Back-end DBMS is %s. Do you want to skip test payloads for other DBMSes?", name), true) {
			d.filterDB = name
		}
	}
	return name
}

func (d *Detector) scanPoint(ctx context.Context, pt *InjectionPoint, db string, rc runnersConfig, det chan<- Detection, errCh chan<- error) {
	if ctx.Err() != nil {
		return
	}
	maxSamples := 4
	if d.cfg.Fast {
		maxSamples = 1
	}
	base, err := common.CaptureBaselineN(ctx, d.client, rc.throttle, pt.RenderBase(), d.cfg.Timeout, d.meter, maxSamples)
	if err != nil {
		select {
		case errCh <- fmt.Errorf("point %s (%s): %w", pt.Location, pt.Name, err):
		case <-ctx.Done():
		}
		return
	}
	d.progress("point: %s (%s)  baseline=%s stable=%t", pt.Location, pt.Name, base.Median.Round(time.Millisecond), base.Stable)
	d.scanned.Add(1)
	if !base.Stable {
		d.progress("  warning: unstable baseline (avg similarity %.2f), increasing retries", base.AvgSim)
	}

	// WAF / IPS prompt: a blocked baseline (e.g. 403) during capture implies a
	// filtering proxy stands between us and the backend. Offer to load the
	// recommended tamper chain. One prompt per scan.
	if !d.wafAsked.Load() && base.Sig != nil && isBlockStatus(base.Sig.Status) {
		if d.wafAsked.CompareAndSwap(false, true) {
			if ui.AskYesNo("WAF/IPS protection detected. Do you want to automatically apply recommended tamper scripts?", true) {
				if names := tamper.SuggestForWAF(""); len(names) > 0 {
					if chain, err := tamper.NewChain(names); err == nil && chain.Len() > 0 {
						d.tamperChain = chain
						d.progress("  applying recommended tamper chain: %s", strings.Join(chain.Names(), ", "))
					}
				}
			}
		}
	}

	// Heuristic confirmation prompt: when a cheap quote probe diverges sharply
	// from the baseline, flag the parameter and offer to keep testing only it.
	if !d.heuristicAsked.Load() && d.heuristicSignal(ctx, base, pt, rc) {
		if d.heuristicAsked.CompareAndSwap(false, true) {
			if ui.AskYesNo(fmt.Sprintf("Heuristic test shows parameter '%s' might be vulnerable. Do you want to keep testing only this parameter?", pt.Name), true) {
				d.skipRemaining.Store(true)
				d.progress("  keeping only parameter %q (others skipped at user request)", pt.Name)
			}
		}
	}

	psets := d.payloadSets(db)
	runner := &techniques.Runner{
		Client: d.client,
		Cfg:    rc.Config,
		Point:  pt,
		Base:   base,
	}

	for _, name := range d.techniqueOrder() {
		if ctx.Err() != nil {
			return
		}
		res := d.dispatch(ctx, runner, name, psets)
		if res == nil {
			continue
		}
		d.findings.Add(1)
		payload := res.Payload
		if d.tamperChain != nil && payload != "" {
			payload = d.tamperChain.Apply(payload)
		}
		select {
		case det <- Detection{
			Point:      *pt,
			Technique:  res.Technique,
			DBMS:       res.DB,
			Payload:    payload,
			Evidence:   res.Evidence,
			Confidence: res.Confidence,
		}:
		case <-ctx.Done():
			return
		}
		d.progress("  [+] %s technique seems to be usable (confidence: %d%%) on %s", res.Technique, res.Confidence, pt.Location)
		return
	}
}

func (d *Detector) payloadSets(db string) []*dbms.Payloads {
	// A DBMS filter arrived at interactively (or by batch default) takes
	// precedence, narrowing the scan to that single backend for every point.
	if d.filterDB != "" {
		if p := dbms.Get(d.filterDB); p != nil {
			return []*dbms.Payloads{p}
		}
	}
	if db != "" && db != dbms.Generic {
		if p := dbms.Get(db); p != nil {
			return []*dbms.Payloads{p}
		}
	}
	return dbms.All()
}

// heuristicSignal performs a cheap single-quote probe against the injection
// point and reports whether the response diverged sharply from the baseline.
// A strong divergence means the application interpreted the marker specially
// (error page, 500, reflection), a classic pre-detection heuristic signal.
func (d *Detector) heuristicSignal(ctx context.Context, base *common.Baseline, pt *InjectionPoint, rc runnersConfig) bool {
	if base == nil || base.Sig == nil {
		return false
	}
	probe := pt.Render(`'`)
	if probe == nil {
		return false
	}
	resp, err := common.Do(ctx, d.client, rc.throttle, probe.Method, probe.URL, probe.Body, probe.Headers, d.cfg.Timeout, d.meter)
	if err != nil {
		return false
	}
	sim := common.Sim(base.Sig, common.SigOf(resp))
	return sim < 0.60
}

// isBlockStatus reports whether an HTTP status is a typical WAF/IPS block
// signature (403 Forbidden and friends).
func isBlockStatus(status int) bool {
	switch status {
	case 403, 406, 418, 423, 429, 451, 501:
		return true
	}
	return false
}

// techniqueOrder returns the enabled technique names in execution order.
func (d *Detector) techniqueOrder() []string {
	order := []string{
		techniques.TechBoolean,
		techniques.TechError,
		techniques.TechUnion,
		techniques.TechInline,
		techniques.TechTime,
		techniques.TechStacked,
		techniques.TechOOB,
	}
	if len(d.cfg.Techniques) == 0 {
		return order
	}
	set := map[string]bool{}
	for _, t := range d.cfg.Techniques {
		set[strings.ToLower(strings.TrimSpace(t))] = true
	}
	var out []string
	for _, t := range order {
		if set[strings.ToLower(t)] {
			out = append(out, t)
		}
	}
	return out
}

func (d *Detector) dispatch(ctx context.Context, r *techniques.Runner, name string, psets []*dbms.Payloads) *techniques.Result {
	switch name {
	case techniques.TechBoolean:
		return r.Boolean(ctx, psets)
	case techniques.TechError:
		return r.Error(ctx, psets)
	case techniques.TechUnion:
		return r.Union(ctx, psets)
	case techniques.TechInline:
		return r.Inline(ctx, psets)
	case techniques.TechTime:
		return r.Time(ctx, psets)
	case techniques.TechStacked:
		return r.Stacked(ctx, psets)
	case techniques.TechOOB:
		return r.OOB(ctx, psets)
	}
	return nil
}

// Meter returns the shared request meter so exploitation phases can keep
// accumulating request/error counts and report a single run-wide req/s figure.
func (d *Detector) Meter() *common.Meter { return d.meter }

// startRateReporter prints a live req/s line to the progress stream every 2s
// until the returned stop function runs. It is purely informational and never
// blocks the scan.
func (d *Detector) startRateReporter(ctx context.Context) func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				el := time.Since(d.startAt)
				reqs := d.meter.Requests.Load()
				if reqs == 0 {
					continue
				}
				rps := float64(reqs) / el.Seconds()
				d.progress("  rate: %d req in %s (%.1f req/s) phase=detect", reqs, humanDurShort(el), rps)
			case <-ctx.Done():
				return
			}
		}
	}()
	return func() { close(done) }
}

func humanDurShort(d time.Duration) string {
	return d.Round(time.Millisecond).String()
}

// Stats returns a point-in-time snapshot of the scan.
func (d *Detector) Stats() Stats {
	d.startMut.Lock()
	startAt := d.startAt
	d.startMut.Unlock()
	var elapsed time.Duration
	if !startAt.IsZero() {
		elapsed = time.Since(startAt)
	}
	return Stats{
		Requests:  d.meter.Requests.Load(),
		Errors:    d.meter.Errors.Load(),
		Points:    int(d.scanned.Load()),
		Findings:  d.findings.Load(),
		StartedAt: startAt,
		Elapsed:   elapsed,
	}
}
