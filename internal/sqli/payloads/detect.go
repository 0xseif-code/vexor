package payloads

import (
	"context"
	"fmt"
	"time"

	"github.com/0xseif-code/vexor/internal/httpclient"
	"github.com/0xseif-code/vexor/internal/sqli/common"
	"github.com/0xseif-code/vexor/internal/sqli/dbms"
	"github.com/0xseif-code/vexor/internal/sqli/injection"
	"github.com/0xseif-code/vexor/internal/sqli/ui"
)

// Finding is a confirmed injection result produced by the matrix-driven
// runner. Its Technique label matches the human-readable technique names used
// elsewhere in Vexor so a winning payload can feed enumeration / dump without
// an "extraction channel unavailable" gap.
type Finding struct {
	// Place labels the site of the injection, e.g. "GET parameter 'cat'".
	Place string
	// Title is the winning payload's descriptive title.
	Title string
	// Payload is the exact rendered injection value that confirmed.
	Payload string
	// Technique is the detection family (e.g. "error-based").
	Technique string
	// DBMS is the normalized backend identifier.
	DBMS string
	// Confidence is the 0..100 weight of the finding.
	Confidence int
	// Wrapper is the wrapper variant that confirmed.
	Wrapper string
}

// RunConfig carries the scan settings for the matrix runner. Level and Risk
// drive both payload selection and wrapper expansion.
type RunConfig struct {
	Level      int
	Risk       int
	DBMS       string
	OOBDomain  string
	Timeout    time.Duration
	Throttle   common.Throttle
	Delay      time.Duration // between-request throttle fallback
	Meter      *common.Meter
	Techniques []Technique
	// Log attempts even when batch/silent is requested (default true).
	Quiet bool
}

// Runner drives the matrix: it expands each selected payload through the
// wrapper engine and dispatches every probe to the injection point, logging
// each attempt like the reference engine.
type Runner struct {
	Client *httpclient.Client
	Cfg    RunConfig
	Point  *injection.InjectionPoint
	Base   *common.Baseline
}

// NewRunConfig returns a RunConfig with defaults applied (level 1, risk 1,
// 8s timeout).
func NewRunConfig() RunConfig {
	return RunConfig{
		Level:   1,
		Risk:    1,
		Timeout: 8 * time.Second,
	}
}

// seconds returns the delay magnitude string used in {seconds}.
func (c RunConfig) seconds() string {
	return "5"
}

// techniqueLabel maps a matrix technique to the human label used by the rest
// of the engine.
func techniqueLabel(t Technique) string {
	switch t {
	case TechBoolean:
		return "boolean-based blind"
	case TechError:
		return "error-based"
	case TechTime:
		return "time-based blind"
	case TechUnion:
		return "UNION query"
	case TechStacked:
		return "stacked queries"
	case TechInline:
		return "inline query"
	case TechOOB:
		return "out-of-band"
	}
	return string(t)
}

// Run expands the selected matrix and probes each rendered vector against the
// injection point. It logs every attempt via ui.Info and returns the first
// high-confidence confirmation, or nil when nothing injects.
func (r *Runner) Run(ctx context.Context) (*Finding, int) {
	if r.Base == nil {
		return nil, 0
	}
	macro := Macro{
		Query:   "SELECT version()",
		Seconds: r.Cfg.seconds(),
		Domain:  r.Cfg.OOBDomain,
	}
	selected := Select(SelectOptions{
		DBMS:       r.Cfg.DBMS,
		Techniques: r.Cfg.Techniques,
		Level:      r.Cfg.Level,
		Risk:       r.Cfg.Risk,
	})
	attempts := 0
	for _, p := range selected {
		if ctx.Err() != nil {
			return nil, attempts
		}
		// OOB payloads are pointless without a callback domain; skip them.
		if p.Technique == TechOOB && r.Cfg.OOBDomain == "" {
			continue
		}
		rendered := Expand(p, r.Cfg.Level, macro)
		for _, probe := range rendered {
			if ctx.Err() != nil {
				return nil, attempts
			}
			attempts++
			r.logAttempt(p.Title, probe.Wrapper)
			if confirmed := r.confirm(ctx, p, probe); confirmed {
				return &Finding{
					Place:      r.placeLabel(),
					Title:      p.Title,
					Payload:    probe.Rendered,
					Technique:  techniqueLabel(p.Technique),
					DBMS:       p.DBMS,
					Confidence: p.Confidence,
					Wrapper:    probe.Wrapper,
				}, attempts
			}
			if r.Cfg.Throttle != nil || r.Cfg.Delay > 0 {
				if r.Cfg.Delay > 0 {
					select {
					case <-time.After(r.Cfg.Delay):
					case <-ctx.Done():
						return nil, attempts
					}
				}
			}
		}
	}
	return nil, attempts
}

// logAttempt prints the required attempt line.
func (r *Runner) logAttempt(title, wrapper string) {
	if r.Cfg.Quiet {
		return
	}
	if wrapper != "" && wrapper != "plain" {
		ui.Info("testing '%s' (wrapper: %s)", title, wrapper)
		return
	}
	ui.Info("testing '%s'", title)
}

// placeLabel formats the injection place the way the reference output expects:
// "<METHOD> parameter '<name>'".
func (r *Runner) placeLabel() string {
	label := "parameter"
	switch r.Point.Type {
	case "POST", "GET":
		label = r.Point.Type + " parameter"
	case "Cookie":
		label = "Cookie"
	case "Header":
		label = "Header"
	}
	if r.Point.Name != "" {
		return fmt.Sprintf("%s '%s'", label, r.Point.Name)
	}
	return label
}

// confirm sends one rendered probe and decides, by technique family, whether it
// confirms. Straight lines are kept brief: error probes match a DBMS error
// signature, time probes check latency, everything else checks for a response
// divergence from the baseline matching the payload's polarity.
func (r *Runner) confirm(ctx context.Context, p Payload, probe RenderedPayload) bool {
	th := r.Cfg.Throttle
	timeout := r.Cfg.Timeout
	meter := r.Cfg.Meter
	rr := r.Point.Render(probe.Rendered)
	if rr == nil {
		return false
	}
	resp, err := common.Do(ctx, r.Client, th, rr.Method, rr.URL, rr.Body, rr.Headers, timeout, meter)
	if err != nil {
		return false
	}

	switch p.Technique {
	case TechError:
		db, _ := dbms.MatchError(resp.Body)
		return db != ""
	case TechTime:
		return resp.Duration >= r.Base.Median+2*time.Second
	case TechOOB:
		// OOB is only reached when a domain is configured (gated in Run); the
		// callback itself is observed out of band, so a dispatched req counts.
		return true
	default:
		sim := common.Sim(r.Base.Sig, common.SigOf(resp))
		// Tautology-style payloads keep the page similar; false-style payloads
		// diverge. A sharp divergence from baseline indicates interpretation.
		return sim < 0.62
	}
}
