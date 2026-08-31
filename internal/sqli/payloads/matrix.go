package payloads

import (
	"sort"
	"strings"
)

// registry is the full set of registered payload templates, keyed by stable
// ID. Order of iteration is not relied upon; callers use Select / Count.
var registry = map[string]Payload{}

// MustRegister adds a payload to the matrix, panicking on duplicate IDs so a
// broken matrix fails loudly at init time (and in tests).
func MustRegister(p Payload) {
	if p.ID == "" {
		panic("payloads: empty ID")
	}
	if _, dup := registry[p.ID]; dup {
		panic("payloads: duplicate payload ID " + p.ID)
	}
	if strings.TrimSpace(p.Template) == "" {
		panic("payloads: empty template for " + p.ID)
	}
	registry[p.ID] = p
}

// Get returns the payload with the given ID, or the zero value when absent.
func Get(id string) Payload { return registry[id] }

// Has reports whether the matrix contains the given ID.
func Has(id string) bool { _, ok := registry[id]; return ok }

// Total returns the number of payload templates in the matrix.
func Total() int { return len(registry) }

// All returns a snapshot of every payload template in the matrix, ordered by
// DBMS then title for deterministic output.
func All() []Payload {
	out := make([]Payload, 0, len(registry))
	for _, p := range registry {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DBMS != out[j].DBMS {
			return out[i].DBMS < out[j].DBMS
		}
		return out[i].Title < out[j].Title
	})
	return out
}

// CountByDBMS returns the number of templates per canonical DBMS, including
// the generic cross-db bucket.
func CountByDBMS() map[string]int {
	counts := map[string]int{}
	for _, p := range registry {
		counts[p.DBMS]++
	}
	return counts
}

// CountByTechnique returns the number of templates per technique family.
func CountByTechnique() map[Technique]int {
	counts := map[Technique]int{}
	for _, p := range registry {
		counts[p.Technique]++
	}
	return counts
}

// MinTargets reports whether the per-DBMS minimum coverage is satisfied.
// It is used by the matrix test and can be surfaced in the CLI summary.
func MinTargets() map[string]struct {
	Have int
	Min  int
	OK   bool
} {
	targets := map[string]int{
		DBMySQL:    90,
		DBPostgres: 35,
		DBMSSQL:    35,
		DBOracle:   30,
		DBSQLite:   20,
		DBGeneric:  20,
	}
	counts := CountByDBMS()
	out := map[string]struct {
		Have int
		Min  int
		OK   bool
	}{}
	for db, min := range targets {
		have := counts[db]
		out[db] = struct {
			Have int
			Min  int
			OK   bool
		}{Have: have, Min: min, OK: have >= min}
	}
	return out
}
