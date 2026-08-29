package techniques

import (
	"context"

	"github.com/0xseif-code/vexor/internal/sqli/dbms"
)

// Boolean confirms blinds via AND 1=1 vs AND 1=2 divergence from the baseline.
func (r *Runner) Boolean(ctx context.Context, psets []*dbms.Payloads) *Result {
	for _, p := range psets {
		res := r.boolCheck(ctx, p.Boolean, TechBoolean, 85)
		if res != nil {
			res.DB = p.Name
			return res
		}
	}
	return nil
}

// Inline confirms subquery-embedded boolean expressions. It is conceptually a
// boolean check whose expressions ride inside a SELECT.
func (r *Runner) Inline(ctx context.Context, psets []*dbms.Payloads) *Result {
	for _, p := range psets {
		if len(p.Inline) == 0 {
			continue
		}
		res := r.boolCheck(ctx, p.Inline, TechInline, 80)
		if res != nil {
			res.DB = p.Name
			return res
		}
	}
	return nil
}
