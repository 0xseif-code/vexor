package payloads

import (
	"sort"
	"strings"
)

// SelectOptions controls which payloads the selector returns.
type SelectOptions struct {
	// DBMS selects a single backend; empty or "*" selects every backend.
	DBMS string
	// Techniques is the set of technique families to include. Empty means all.
	Techniques []Technique
	// Level is the maximum payload Level to include (1..5).
	Level int
	// Risk is the maximum payload Risk to include (1..3).
	Risk int
}

// Select filters the payload matrix by DBMS, technique families, level and
// risk. It returns payloads ordered by technique then per declared confidence
// (descending) so high-value vectors run first within a family.
//
// Level and risk gating match sqlmap's semantics:
//   - level 1: only the highest-probability set is returned.
//   - higher levels unlock progressively less common vectors.
//   - risk 1: safe payloads only; risk 2 adds time/heavy; risk 3 adds
//     OR-based / stacked-aggressive / OOB vectors.
//
// The returned set is always filtered so that Select(level=1) is strictly
// smaller than Select(level=5) for the same DBMS/technique/risk.
func Select(opt SelectOptions) []Payload {
	if opt.Level < 1 {
		opt.Level = 1
	}
	if opt.Risk < 1 {
		opt.Risk = 1
	}

	db := Normalize(opt.DBMS)
	techSet := map[Technique]bool{}
	for _, t := range opt.Techniques {
		techSet[t] = true
	}
	allTech := len(techSet) == 0

	var out []Payload
	for _, p := range registry {
		if db != DBGeneric && p.DBMS != db {
			continue
		}
		if p.Level > opt.Level {
			continue
		}
		if p.Risk > opt.Risk {
			continue
		}
		if !allTech && !techSet[p.Technique] {
			continue
		}
		out = append(out, p)
	}

	// Deterministic ordering: technique, then confidence descending, then ID.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Technique != out[j].Technique {
			return techRank(out[i].Technique) < techRank(out[j].Technique)
		}
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// techRank is the execution priority: error first, then boolean, union, time,
// stacked, inline, oob — mirroring the detection loop dispatch order.
func techRank(t Technique) int {
	switch t {
	case TechError:
		return 0
	case TechBoolean:
		return 1
	case TechUnion:
		return 2
	case TechTime:
		return 3
	case TechStacked:
		return 4
	case TechInline:
		return 5
	case TechOOB:
		return 6
	}
	return 7
}

// TechniqueSetString parses a comma/letter technique selector into the typed
// technique set accepted by SelectOptions. Accepts sqlmap-style letters
// (B/E/U/S/T/I/O) and full names.
func TechniqueSetString(s string) []Technique {
	set := map[Technique]bool{}
	for _, part := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '-'
	}) {
		tok := strings.ToLower(strings.TrimSpace(part))
		if tok == "*" || tok == "" {
			return nil
		}
		var tt Technique
		switch tok {
		case "b", "boolean", "boolean-based":
			tt = TechBoolean
		case "e", "error", "error-based":
			tt = TechError
		case "u", "union", "union-query":
			tt = TechUnion
		case "s", "stacked", "stacked-query":
			tt = TechStacked
		case "t", "time", "time-based":
			tt = TechTime
		case "i", "inline", "inline-query":
			tt = TechInline
		case "o", "q", "oob", "out-of-band":
			tt = TechOOB
		default:
			continue
		}
		set[tt] = true
	}
	out := make([]Technique, 0, len(set))
	for _, t := range AllTechniques {
		if set[t] {
			out = append(out, t)
		}
	}
	return out
}
