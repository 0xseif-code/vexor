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
	"github.com/0xseif-code/vexor/internal/sqli/techniques"
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
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Progress == nil {
		cfg.Progress = io.Discard
	}
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

	// backend fingerprinting happens once, on the first point.
	db := d.resolveDBMS(ctx, points[0])

	throttle := common.NewThrottle(d.cfg.Delay)
	runnerCfg := techniques.Config{
		Throttle:  throttle,
		Timeout:   d.cfg.Timeout,
		Risk:      d.cfg.Risk,
		Delay:     d.sleepSeconds(),
		OOBDomain: d.cfg.OOBDomain,
		Meter:     d.meter,
	}

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
	d.progress("backend identified: %s", name)
	return name
}

func (d *Detector) scanPoint(ctx context.Context, pt *InjectionPoint, db string, rc runnersConfig, det chan<- Detection, errCh chan<- error) {
	if ctx.Err() != nil {
		return
	}
	base, err := common.CaptureBaseline(ctx, d.client, rc.throttle, pt.RenderBase(), d.cfg.Timeout, d.meter)
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
		select {
		case det <- Detection{
			Point:      *pt,
			Technique:  res.Technique,
			DBMS:       res.DB,
			Payload:    res.Payload,
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
	if db != "" && db != dbms.Generic {
		if p := dbms.Get(db); p != nil {
			return []*dbms.Payloads{p}
		}
	}
	return dbms.All()
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
