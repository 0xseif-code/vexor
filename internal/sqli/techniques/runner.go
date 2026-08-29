// Package techniques implements the seven sqlmap-equivalent detection
// techniques. Each method takes the candidate payload sets and returns the
// first confirmation it finds, or nil.
package techniques

import (
	"context"
	"fmt"
	"time"

	"github.com/0xseif-code/vexor/internal/httpclient"
	"github.com/0xseif-code/vexor/internal/sqli/common"
	"github.com/0xseif-code/vexor/internal/sqli/dbms"
	"github.com/0xseif-code/vexor/internal/sqli/injection"
)

// Technique names.
const (
	TechBoolean = "boolean-based blind"
	TechTime    = "time-based blind"
	TechError   = "error-based"
	TechUnion   = "UNION query"
	TechStacked = "stacked queries"
	TechInline  = "inline query"
	TechOOB     = "out-of-band"
)

// Config carries scan-wide settings used by every technique.
type Config struct {
	Throttle  common.Throttle
	Timeout   time.Duration
	Risk      int    // 1..3
	Delay     string // sleep magnitude in seconds, e.g. "5"
	OOBDomain string // external domain for OOB payloads
	Meter     *common.Meter
}

// Runner executes the techniques against a single injection point.
type Runner struct {
	Client *httpclient.Client
	Cfg    Config
	Point  *injection.InjectionPoint
	Base   *common.Baseline
}

// Result is one confirmed finding from a technique.
type Result struct {
	Technique  string
	DB         string
	Payload    string
	Evidence   string
	Confidence int
}

type sample struct {
	sim  float64
	dur  time.Duration
	body []byte
}

func (r *Runner) once(ctx context.Context, rr *injection.RenderedRequest) (sample, bool) {
	if rr == nil {
		return sample{}, false
	}
	resp, err := common.Do(ctx, r.Client, r.Cfg.Throttle, rr.Method, rr.URL, rr.Body, rr.Headers, r.Cfg.Timeout, r.Cfg.Meter)
	if err != nil {
		return sample{}, false
	}
	sim := 1.0
	body := []byte(nil)
	if r.Base != nil && r.Base.Sig != nil {
		sim = common.Sim(r.Base.Sig, common.SigOf(resp))
	}
	if len(resp.Body) > 0 {
		body = resp.Body
	}
	return sample{sim: sim, dur: resp.Duration, body: body}, true
}

// sampleN takes n samples of the same rendering.
// n = 1 for stable baselines, more when the target response jitters.
func (r *Runner) sampleN(ctx context.Context, rr *injection.RenderedRequest, n int) ([]sample, bool) {
	if n < 1 {
		n = 1
	}
	out := make([]sample, 0, n)
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			return out, false
		}
		s, ok := r.once(ctx, rr)
		if !ok {
			return out, false
		}
		out = append(out, s)
	}
	return out, true
}

// sampleCount picks the number of probes per value based on baseline stability.
func (r *Runner) sampleCount() int {
	if r.Base == nil || r.Base.Stable {
		return 1
	}
	return 3
}

func avgSim(sims []float64) float64 {
	if len(sims) == 0 {
		return 0
	}
	var sum float64
	for _, v := range sims {
		sum += v
	}
	return sum / float64(len(sims))
}

func medianDur(samples []sample) time.Duration {
	durs := make([]time.Duration, 0, len(samples))
	for _, s := range samples {
		durs = append(durs, s.dur)
	}
	return common.MedianDuration(durs)
}

// boolCheck evaluates a set of true/false expression pairs against the
// baseline. A pair whose "true" side reproduces the baseline while the "false"
// side diverges marks the point as injectable.
func (r *Runner) boolCheck(ctx context.Context, pairs []dbms.BoolPair, technique string, confidence int) *Result {
	if len(pairs) == 0 {
		return nil
	}
	n := r.sampleCount()
	orig := r.Point.Value
	for _, pr := range pairs {
		if ctx.Err() != nil {
			return nil
		}
		trueVal := dbms.ExpandOrig(pr.True, orig)
		falseVal := dbms.ExpandOrig(pr.False, orig)
		ts, ok1 := r.sampleN(ctx, r.Point.Render(trueVal), n)
		fs, ok2 := r.sampleN(ctx, r.Point.Render(falseVal), n)
		if !ok1 || !ok2 {
			continue
		}
		var tSims, fSims []float64
		for _, s := range ts {
			tSims = append(tSims, s.sim)
		}
		for _, s := range fs {
			fSims = append(fSims, s.sim)
		}
		t := avgSim(tSims)
		f := avgSim(fSims)
		diff := t - f
		if t >= 0.78 && diff >= 0.18 && f <= 0.85 {
			if diff >= 0.35 {
				confidence += 5
			}
			return &Result{
				Technique:  technique,
				Payload:    trueVal,
				Evidence:   fmt.Sprintf("signature similarity: true %.2f vs false %.2f", t, f),
				Confidence: confidence,
			}
		}
	}
	return nil
}
