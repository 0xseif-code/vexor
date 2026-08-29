package techniques

import (
	"context"
	"fmt"
	"time"

	"github.com/0xseif-code/vexor/internal/sqli/dbms"
)

// minTimeDelta is the minimum median latency lift that counts as a time-based
// confirmation (vs baseline).
const minTimeDelta = 2000 * time.Millisecond

// robustDelay evaluates 3 samples of one payload and reports the median delay
// over the baseline, requiring at least two samples well above it.
func (r *Runner) robustDelay(ctx context.Context, payload string) (time.Duration, bool) {
	rr := r.Point.Render(payload)
	samples, ok := r.sampleN(ctx, rr, 3)
	if !ok {
		return 0, false
	}
	med := medianDur(samples)
	base := time.Duration(0)
	if r.Base != nil {
		base = r.Base.Median
	}
	delta := med - base
	if delta < minTimeDelta {
		return delta, false
	}
	below := 0
	for _, s := range samples {
		if s.dur < base+minTimeDelta {
			below++
		}
	}
	return delta, below <= 1
}

// Time fires sleep-based payloads and watches for a consistent delay.
func (r *Runner) Time(ctx context.Context, psets []*dbms.Payloads) *Result {
	delay := r.Cfg.Delay
	if delay == "" {
		delay = "5"
	}
	for _, p := range psets {
		for _, tpl := range p.Time {
			if tpl.Risk > r.Cfg.Risk {
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			payload := dbms.Expand(tpl.Payload, dbms.Macros{Orig: r.Point.Value, Delay: delay})
			delta, ok := r.robustDelay(ctx, payload)
			if ok {
				conf := 90
				if delta >= minTimeDelta*2 {
					conf = 95
				}
				return &Result{
					Technique:  TechTime,
					DB:         p.Name,
					Payload:    payload,
					Evidence:   fmt.Sprintf("median response +%s vs baseline %s (3 samples)", delta.Round(time.Millisecond), r.baseStr()),
					Confidence: conf,
				}
			}
		}
	}
	return nil
}

func (r *Runner) baseStr() string {
	if r.Base == nil {
		return "0s"
	}
	return r.Base.Median.Round(time.Millisecond).String()
}
