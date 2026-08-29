package techniques

import (
	"context"

	"github.com/0xseif-code/vexor/internal/sqli/dbms"
)

// Stacked fires a second statement (only supported by some DBMS) and confirms
// it time-wise, mirroring the Time technique's statistical rigour.
func (r *Runner) Stacked(ctx context.Context, psets []*dbms.Payloads) *Result {
	if r.Cfg.Risk < 2 {
		return nil
	}
	delay := r.Cfg.Delay
	if delay == "" {
		delay = "5"
	}
	for _, p := range psets {
		if !dbms.Stackable(p) {
			continue
		}
		for _, tpl := range p.Stacked {
			if tpl.Risk > r.Cfg.Risk {
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			payload := dbms.Expand(tpl.Payload, dbms.Macros{Orig: r.Point.Value, Delay: delay})
			if _, ok := r.robustDelay(ctx, payload); ok {
				return &Result{
					Technique:  TechStacked,
					DB:         p.Name,
					Payload:    payload,
					Evidence:   "stacked statement executed (secondary statement delayed the response)",
					Confidence: 88,
				}
			}
		}
	}
	return nil
}
