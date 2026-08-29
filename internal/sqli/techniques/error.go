package techniques

import (
	"context"

	"github.com/0xseif-code/vexor/internal/sqli/dbms"
)

// Error confirms when a payload provokes a verbose, recognisable DBMS error in
// the response. Unbalanced quotes are probed first because they work across
// every backend, then the DB-specific error functions are tried.
func (r *Runner) Error(ctx context.Context, psets []*dbms.Payloads) *Result {
	if db, ev := r.matchVerbose(ctx, r.Point.Value+"'"); db != "" {
		return r.errorResult(ev, db, r.Point.Value+"'")
	}
	if db, ev := r.matchVerbose(ctx, r.Point.Value+`"`); db != "" {
		return r.errorResult(ev, db, r.Point.Value+`"`)
	}
	for _, p := range psets {
		for _, tpl := range p.Error {
			if ctx.Err() != nil {
				return nil
			}
			payload := dbms.ExpandOrig(tpl, r.Point.Value)
			if db, ev := r.matchVerbose(ctx, payload); db != "" {
				return r.errorResult(ev, db, payload)
			}
		}
	}
	return nil
}

func (r *Runner) matchVerbose(ctx context.Context, payload string) (string, string) {
	s, ok := r.once(ctx, r.Point.Render(payload))
	if !ok || len(s.body) == 0 {
		return "", ""
	}
	db, ev := dbms.MatchError(s.body)
	if ev != "" {
		const maxEv = 100
		if len(ev) > maxEv {
			ev = ev[:maxEv]
		}
	}
	return db, ev
}

func (r *Runner) errorResult(evidence, db, payload string) *Result {
	return &Result{
		Technique:  TechError,
		DB:         db,
		Payload:    payload,
		Evidence:   "DBMS error signature: " + evidence,
		Confidence: 90,
	}
}
