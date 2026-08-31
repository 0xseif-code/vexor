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
	"github.com/0xseif-code/vexor/internal/sqli/payloads"
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

	// continueAsked guards the one-shot "do you want to keep testing the other
	// parameters" prompt shown after the first confirmed vulnerable parameter.
	continueAsked atomic.Bool

	// wafAsked guards the one-shot WAF tamper prompt; tamperChain holds the
	// recommended chain (if accepted) applied to confirmed payloads.
	wafAsked    atomic.Bool
	tamperChain *tamper.Chain

	// matrixWork records the first payload-matrix vector that confirmed, so
	// subsequent enumeration/dump phases can reuse the working injection
	// structure without re-scanning.
	matrixWork atomic.Pointer[matrixHit]
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

		// After the first confirmed vulnerable parameter, ask whether to keep
		// testing the remaining parameters (if any). Answering no (or hitting
		// Enter) skips the rest and lets the caller proceed straight to
		// enumeration/dump. Batch mode defaults to no, as does any non-TTY
		// stdin, mirroring sqlmap's --batch behaviour of moving to exploitation.
		if d.continueAsked.CompareAndSwap(false, true) && !d.skipRemaining.Load() {
			if !ui.AskYesNo(fmt.Sprintf("GET parameter %q is vulnerable. Do you want to keep testing the others (if any)?", pt.Name), false) {
				d.skipRemaining.Store(true)
				d.progress("  keeping only the confirmed parameter %q; remaining parameters skipped", pt.Name)
			}
		}
		return
	}

	// The standard techniques found nothing. Fall through to the exhaustive,
	// version-aware payload matrix engine, which generates wrapped probes
	// across every DBMS version branch (level 1 = high-probability subset,
	// level 3 = full matrix). Logs every tested payload with a descriptive
	// title and returns the first confirmed injection.
	if ctx.Err() != nil {
		return
	}
	res := d.runMatrixEngine(ctx, pt, runner, db)
	if res == nil {
		return
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
	d.progress("  [matrix] %s technique usable (confidence: %d%%) on %s", res.Technique, res.Confidence, pt.Location)
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

// ---------------------------------------------------------------------------
// Version-Aware Payload Matrix Engine
// ---------------------------------------------------------------------------

// MatrixResult is a single confirmed injection produced by the payload-matrix
// probe loop. It augments techniques.Result with the descriptive matrix title
// so callers can name the exact vector that fired.
type MatrixResult struct {
	techniques.Result
	Title string
}

// matrixHits is a stored working-payload structure for enumeration/dump reuse.
// The detector records the first confirmed vector so downstream phases can
// re-render extraction payloads without re-scanning.
type matrixHit struct {
	Title    string
	Payload  payloads.Payload
	Rendered string
	DBMS     string
}

// runMatrixEngine drives the version-aware payload matrix against the injection
// point. It selects the eligible vectors (by --dbms, --risk and --level),
// expands each through the wrapper engine, and logs EVERY tested probe with its
// timestamp and descriptive title.
//
//	[HH:MM:SS] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE clause (EXTRACTVALUE)'
//	[HH:MM:SS] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind - WHERE clause (SLEEP)'
//
// On the first confirmed injection it logs the hit, records the working payload
// structure for subsequent enumeration/dump, and returns immediately.
func (d *Detector) runMatrixEngine(ctx context.Context, pt *injection.InjectionPoint, r *techniques.Runner, db string) *techniques.Result {
	opt := payloads.SelectOptions{Level: d.cfg.Level, Risk: d.cfg.Risk}
	if db != "" && db != dbms.Generic {
		opt.DBMS = db
	}
	if d.filterDB != "" {
		opt.DBMS = d.filterDB
	}
	selected := payloads.Select(opt)
	if len(selected) == 0 {
		return nil
	}

	level := d.cfg.Level
	if level < 1 {
		level = 1
	}
	delay := d.sleepSeconds()
	m := payloads.DefaultMacro()
	m.Orig = pt.Value
	m.Seconds = delay
	m.Query = "VERSION()"

	// Pre-compute the total probe budget for a progress line (and to satisfy
	// the "level 1 ~15-20 probes, level 3 >100 probes" sizing contract).
	budget := 0
	for _, p := range selected {
		budget += payloads.ExpandCount(p, level, m)
	}
	d.progress("  matrix engine: %d vectors selected (risk<=%d, level=%d) -> ~%d probes", len(selected), d.cfg.Risk, level, budget)

	tested := 0
	for _, p := range selected {
		if ctx.Err() != nil {
			return nil
		}
		for _, rendered := range payloads.Expand(p, level, m) {
			if ctx.Err() != nil {
				return nil
			}
			tested++

			// Verbose per-probe log with descriptive title (timestamped by
			// the shared logger), matching sqlmap's probe-stream format.
			ui.Info("testing '%s'", rendered.Source.Title)

			res := d.testMatrixRendered(ctx, pt, r, rendered, db)
			if res != nil {
				d.recordMatrixHit(matrixHit{
					Title:    rendered.Source.Title,
					Payload:  rendered.Source,
					Rendered: rendered.Rendered,
					DBMS:     res.DB,
				})
				ui.Info("[+] %s parameter %q is '%s' injectable", pt.Type, pt.Name, rendered.Source.Title)
				d.progress("  [+] matrix hit: %s technique on %s (probe %d/%d)", rendered.Source.Technique, pt.Location, tested, budget)
				return res
			}
		}
	}

	d.progress("  matrix engine complete: %d probes, no injection found", tested)
	return nil
}

// testMatrixRendered sends a single expanded probe and detects a confirmation
// using technique-specific logic. The DB name preference (from OOB / error
// signatures) is honored when a match reports one.
func (d *Detector) testMatrixRendered(ctx context.Context, pt *injection.InjectionPoint, r *techniques.Runner, rp payloads.RenderedPayload, db string) *techniques.Result {
	payload := rp.Rendered
	switch rp.Source.Technique {
	case payloads.TechBoolean, payloads.TechInline:
		return d.testMatrixBool(ctx, pt, r, rp, db)
	case payloads.TechError:
		return d.testMatrixError(ctx, pt, r, rp, db)
	case payloads.TechTime:
		return d.testMatrixTime(ctx, pt, r, payload, db)
	case payloads.TechStacked:
		return d.testMatrixStacked(ctx, pt, r, payload, db)
	case payloads.TechUnion:
		return d.testMatrixUnion(ctx, pt, r, payload, db)
	case payloads.TechOOB:
		return d.testMatrixOOB(ctx, pt, r, rp, db)
	}
	return nil
}

// testMatrixBool renders both the true probe and a negated false variant built
// from the rendered probe's boolean atom (AND 1=1 -> AND 1=2) and checks for the
// classic signature divergence. Confirmations require the true probe to
// reproduce the baseline while the false probe diverges.
func (d *Detector) testMatrixBool(ctx context.Context, pt *injection.InjectionPoint, r *techniques.Runner, rp payloads.RenderedPayload, db string) *techniques.Result {
	falsePayload := flipRendered(rp.Rendered)
	if falsePayload == rp.Rendered {
		return nil
	}
	rrTrue := pt.Render(rp.Rendered)
	rrFalse := pt.Render(falsePayload)
	if rrTrue == nil || rrFalse == nil {
		return nil
	}

	n := r.SampleCount()
	ts, ok1 := r.SampleN(ctx, rrTrue, n)
	fs, ok2 := r.SampleN(ctx, rrFalse, n)
	if !ok1 || !ok2 {
		return nil
	}

	tAvg := avgSamples(ts)
	fAvg := avgSamples(fs)
	diff := tAvg - fAvg
	if tAvg >= 0.78 && diff >= 0.18 && fAvg <= 0.85 {
		conf := 85
		if diff >= 0.35 {
			conf += 5
		}
		return &techniques.Result{
			Technique:  string(rp.Source.Technique),
			DB:         db,
			Payload:    rp.Rendered,
			Evidence:   fmt.Sprintf("matrix %s: true %.2f vs false %.2f", rp.Source.Technique, tAvg, fAvg),
			Confidence: conf,
		}
	}
	return nil
}

// testMatrixError sends the probe and matches the response against known DBMS
// error signatures.
func (d *Detector) testMatrixError(ctx context.Context, pt *injection.InjectionPoint, r *techniques.Runner, rp payloads.RenderedPayload, db string) *techniques.Result {
	rr := pt.Render(rp.Rendered)
	if rr == nil {
		return nil
	}
	resp, err := common.Do(ctx, r.Client, r.Cfg.Throttle, rr.Method, rr.URL, rr.Body, rr.Headers, r.Cfg.Timeout, r.Cfg.Meter)
	if err != nil {
		return nil
	}
	if name, ev := dbms.MatchError(resp.Body); ev != "" {
		const maxEv = 100
		if len(ev) > maxEv {
			ev = ev[:maxEv]
		}
		return &techniques.Result{
			Technique:  techniques.TechError,
			DB:         name,
			Payload:    rp.Rendered,
			Evidence:   "DBMS error signature: " + ev,
			Confidence: 90,
		}
	}
	return nil
}

// testMatrixTime sends the probe three times and confirms a consistent latency
// lift over the baseline.
func (d *Detector) testMatrixTime(ctx context.Context, pt *injection.InjectionPoint, r *techniques.Runner, payload string, db string) *techniques.Result {
	delta, ok := r.RobustDelay(ctx, payload)
	if !ok {
		return nil
	}
	conf := 90
	if delta >= 4*time.Second {
		conf = 95
	}
	return &techniques.Result{
		Technique:  techniques.TechTime,
		DB:         db,
		Payload:    payload,
		Evidence:   fmt.Sprintf("matrix time-based: +%s vs baseline", delta.Round(time.Millisecond)),
		Confidence: conf,
	}
}

// testMatrixStacked sends a stacked-query probe and confirms time-wise.
func (d *Detector) testMatrixStacked(ctx context.Context, pt *injection.InjectionPoint, r *techniques.Runner, payload string, db string) *techniques.Result {
	delta, ok := r.RobustDelay(ctx, payload)
	if !ok {
		return nil
	}
	return &techniques.Result{
		Technique:  techniques.TechStacked,
		DB:         db,
		Payload:    payload,
		Evidence:   fmt.Sprintf("stacked statement executed (secondary statement delayed +%s)", delta.Round(time.Millisecond)),
		Confidence: 88,
	}
}

// testMatrixUnion renders the probe and checks the response signature against
// the baseline for UNION-based reflection.
func (d *Detector) testMatrixUnion(ctx context.Context, pt *injection.InjectionPoint, r *techniques.Runner, payload string, db string) *techniques.Result {
	rr := pt.Render(payload)
	if rr == nil {
		return nil
	}
	s, ok := r.Once(ctx, rr)
	if !ok {
		return nil
	}
	if s.Sim >= 0.85 {
		return &techniques.Result{
			Technique:  techniques.TechUnion,
			DB:         db,
			Payload:    payload,
			Evidence:   "UNION accepted (response matches baseline layout)",
			Confidence: 60,
		}
	}
	return nil
}

// testMatrixOOB dispatches the OOB probe (external confirmation on --oob-domain).
func (d *Detector) testMatrixOOB(ctx context.Context, pt *injection.InjectionPoint, r *techniques.Runner, rp payloads.RenderedPayload, db string) *techniques.Result {
	if d.cfg.OOBDomain == "" {
		return nil
	}
	rr := pt.Render(rp.Rendered)
	if rr == nil {
		return nil
	}
	if _, ok := r.Once(ctx, rr); !ok {
		return nil
	}
	return &techniques.Result{
		Technique:  techniques.TechOOB,
		DB:         db,
		Payload:    rp.Rendered,
		Evidence:   "OOB payload dispatched; confirm the callback on " + d.cfg.OOBDomain,
		Confidence: 60,
	}
}

// recordMatrixHit stores the working payload structure so enumeration/dump can
// reuse the confirmed vector without re-scanning. Keeps only the first hit.
func (d *Detector) recordMatrixHit(h matrixHit) {
	if d.matrixWork.Load() != nil {
		return
	}
	d.matrixWork.Store(&h)
}

// avgSamples averages the baseline-similarity of a probe sample set.
func avgSamples(samples []techniques.Sample) float64 {
	if len(samples) == 0 {
		return 0
	}
	var sum float64
	for _, s := range samples {
		sum += s.Sim
	}
	return sum / float64(len(samples))
}

// flipRendered negates the boolean atom embedded in an already-rendered probe
// (1=1 -> 1=2, '1'='1 -> '1'='2, 'a'='a -> 'a'='b, <=>1 -> <=>2, ...) so the
// boolean technique can compare a true probe against a false one built from the
// exact same wrapper. It returns the input unchanged when no flippable atom is
// present (the caller then skips boolean evaluation).
func flipRendered(rendered string) string {
	replacements := []struct{ from, to string }{
		{"1=1", "1=2"},
		{"'1'='1'", "'1'='2'"},
		{"'1'='1", "'1'='2"},
		{"'a'='a'", "'a'='b'"},
		{"'a'='a", "'a'='b"},
		{"<=>1", "<=>2"},
		{"BETWEEN 1 AND 1", "BETWEEN 2 AND 1"},
		{"sqlite_version()=sqlite_version()", "sqlite_version()!=sqlite_version()"},
	}
	for _, r := range replacements {
		if idx := strings.Index(rendered, r.from); idx >= 0 {
			return rendered[:idx] + r.to + rendered[idx+len(r.from):]
		}
	}
	return rendered
}
