package techniques

import (
	"context"
	"sync"

	"github.com/0xseif-code/vexor/internal/sqli/dbms"
)

// Error confirms when a payload provokes a verbose, recognisable DBMS error in
// the response. Unbalanced quotes are probed first because they work across
// every backend, then the DB-specific error functions are tried.
//
// All candidates run concurrently (bounded by Config.Parallel) and the first
// payload in deterministic order that produces a recognisable DBMS error wins.
func (r *Runner) Error(ctx context.Context, psets []*dbms.Payloads) *Result {
	candidates := make([]string, 0, 2+len(psets))
	candidates = append(candidates, r.Point.Value+"'", r.Point.Value+`"`)
	for _, p := range psets {
		for _, tpl := range p.Error {
			if ctx.Err() != nil {
				return nil
			}
			candidates = append(candidates, dbms.ExpandOrig(tpl, r.Point.Value))
		}
	}
	db, ev, payload := r.firstErrorMatch(ctx, candidates)
	if db == "" {
		return nil
	}
	return r.errorResult(ev, db, payload)
}

// firstErrorMatch fans the candidates out across up to Config.Parallel workers
// and returns the first (by original index) whose response carries a known
// DBMS error signature.
func (r *Runner) firstErrorMatch(ctx context.Context, payloads []string) (db, ev, payload string) {
	if len(payloads) == 0 {
		return "", "", ""
	}
	workers := r.Cfg.Parallel
	if workers < 1 {
		workers = 1
	}
	if workers > len(payloads) {
		workers = len(payloads)
	}
	matches := make([]struct{ db, ev string }, len(payloads))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if ctx.Err() != nil {
					continue
				}
				mdb, mev := r.matchVerbose(ctx, payloads[idx])
				if mev != "" {
					matches[idx].db, matches[idx].ev = mdb, mev
				}
			}
		}()
	}
	for i := range payloads {
		select {
		case jobs <- i:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return "", "", ""
		}
	}
	close(jobs)
	wg.Wait()
	for i, m := range matches {
		if m.db != "" {
			return m.db, m.ev, payloads[i]
		}
	}
	return "", "", ""
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