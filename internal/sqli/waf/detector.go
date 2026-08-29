// Package waf identifies web application firewalls protecting a target using
// passive header/cookie fingerprints first, then minimal active probes only
// when passive signals are absent. It also recommends a tamper chain for the
// detected WAF.
package waf

import (
	"context"
	"fmt"
	"net/url"

	"github.com/0xseif-code/vexor/internal/httpclient"
)

// WAF describes a detected web application firewall.
type WAF struct {
	Name       string
	Vendor     string
	Confidence int      // 0-100
	Evidence   []string // what triggered detection
	Suggested  []string // recommended tamper chain
}

// Detector fingerprints a target for WAFs.
type Detector struct {
	client *httpclient.Client
}

// New builds a WAF detector around an http client.
func New(client *httpclient.Client) *Detector {
	return &Detector{client: client}
}

// Detect performs a best-effort WAF identification, returning the highest-
// confidence match or nil when none is found.
func (d *Detector) Detect(ctx context.Context, targetURL string) (*WAF, error) {
	wafs, err := d.DetectAll(ctx, targetURL)
	if err != nil {
		return nil, err
	}
	if len(wafs) == 0 {
		return nil, nil
	}
	best := wafs[0]
	for _, w := range wafs[1:] {
		if w.Confidence > best.Confidence {
			best = w
		}
	}
	return &best, nil
}

// DetectAll identifies all WAFs protecting the target (handles stacked WAFs)
// using passive fingerprinting and, only if no confident match is found, a
// minimal active probe.
func (d *Detector) DetectAll(ctx context.Context, targetURL string) ([]WAF, error) {
	normal, err := d.fetchNormal(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("waf detection: fetch target: %w", err)
	}

	results := []WAF{}
	lossless, ok := passiveMatch(normal)
	if ok && len(lossless) > 0 {
		results = append(results, lossless...)
		// If passive detection is confident, avoid unnecessary active probes
		// that might trigger a block.
		if confident(results) {
			return dedupe(results), nil
		}
	}

	// Active probe: only when passive results are weak or absent, and use a
	// minimal, low-signal probe to avoid tripping the WAF.
	probe, err := d.fetchProbe(ctx, targetURL)
	if err != nil {
		// Some WAFs refuse even the benign probe; fall back to any lossless
		// signal we already have.
		return dedupe(results), nil
	}

	active, ok := passiveMatch(probe)
	if ok {
		results = append(results, active...)
	}
	// Compare block behaviour between normal and probe responses.
	if block := compareResponses(normal, probe, results); block != nil {
		results = append(results, *block)
	}

	results = annotate(results)
	return dedupe(results), nil
}

func (d *Detector) fetchNormal(ctx context.Context, targetURL string) (*httpclient.Response, error) {
	u, err := withProbeParam(targetURL, prodParam)
	if err != nil {
		return nil, err
	}
	return d.client.Get(ctx, u, nil)
}

func (d *Detector) fetchProbe(ctx context.Context, targetURL string) (*httpclient.Response, error) {
	u, err := withProbeParam(targetURL, probeParam)
	if err != nil {
		return nil, err
	}
	return d.client.Get(ctx, u, nil)
}

// prodParam is the benign baseline probe (no exploit).
const prodParam = ""

var probeParam = "x=1;"

// withProbeParam injects a probe query parameter into the target URL without
// clobbering existing parameters.
func withProbeParam(targetURL string, param string) (string, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if param == "" {
		q.Set("x", "1")
	} else {
		q.Set("x", param)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func confident(results []WAF) bool {
	for _, r := range results {
		if r.Confidence >= 80 {
			return true
		}
	}
	return false
}

// annotate fills in the Suggested tamper chain for every detected WAF.
func annotate(results []WAF) []WAF {
	for i := range results {
		results[i].Suggested = SuggestedTamperChain(results[i].Name)
	}
	return results
}

func dedupe(results []WAF) []WAF {
	seen := map[string]bool{}
	var out []WAF
	for _, r := range results {
		if r.Name == "" || seen[r.Name] {
			continue
		}
		seen[r.Name] = true
		out = append(out, r)
	}
	return out
}
