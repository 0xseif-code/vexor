// Package common provides request plumbing shared by the SQLi detection
// engine: an HTTP throttle, a response signature / similarity metric, baseline
// capture and a concurrency-safe metrics meter.
package common

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"sync/atomic"
	"time"

	"github.com/0xseif-code/vexor/internal/httpclient"
	"github.com/0xseif-code/vexor/internal/sqli/injection"
)

var (
	// ErrUnreachable indicates the target could not be reached during baseline
	// capture.
	ErrUnreachable = errors.New("target unreachable during baseline capture")
)

// maxSigBytes caps the amount of the response body used for signatures so that
// huge responses do not stall the comparison math.
const maxSigBytes = 512 * 1024

var wordRe = regexp.MustCompile(`[A-Za-z0-9_]{2,}`)

// Meter counts requests and errors across a scan.
type Meter struct {
	Requests atomic.Int64
	Errors   atomic.Int64
}

// Sig is a compact, comparable fingerprint of an HTTP response.
type Sig struct {
	Status   int
	Len      int
	Duration time.Duration
	tokens   map[string]int
}

// SigOf builds a Sig from an HTTP response.
func SigOf(resp *httpclient.Response) *Sig {
	body := resp.Body
	if len(body) > maxSigBytes {
		body = body[:maxSigBytes]
	}
	tokens := make(map[string]int)
	for _, t := range wordRe.FindAll(body, -1) {
		tokens[string(t)]++
	}
	return &Sig{
		Status:   resp.StatusCode,
		Len:      len(body),
		Duration: resp.Duration,
		tokens:   tokens,
	}
}

// Sim returns a 0..1 similarity ratio between two response signatures. It is a
// weighted blend of a token-based Dice coefficient and a length ratio, with a
// penalty when the status codes differ. 1.0 means "identical", near zero means
// "completely different".
func Sim(a, b *Sig) float64 {
	if a == nil || b == nil {
		return 0
	}
	var commonN int
	for tok, ca := range a.tokens {
		if cb, ok := b.tokens[tok]; ok && cb > 0 {
			m := ca
			if cb < m {
				m = cb
			}
			commonN += m
		}
	}
	totalA, totalB := 0, 0
	for _, c := range a.tokens {
		totalA += c
	}
	for _, c := range b.tokens {
		totalB += c
	}
	dice := 1.0
	if totalA+totalB > 0 {
		dice = 2 * float64(commonN) / float64(totalA+totalB)
	}
	lenRatio := 1.0
	if a.Len+b.Len > 0 {
		if a.Len > b.Len {
			lenRatio = float64(b.Len) / float64(a.Len)
		} else {
			lenRatio = float64(a.Len) / float64(b.Len)
		}
	}
	sim := 0.7*dice + 0.3*lenRatio
	if a.Status != b.Status {
		sim *= 0.75
	}
	return sim
}

// Baseline captures the "normal" behaviour of an injection point: a canonical
// response signature, its stability across samples and the median latency.
type Baseline struct {
	Sig       *Sig
	Stable    bool
	Samples   int
	AvgSim    float64
	Median    time.Duration
	Durations []time.Duration
}

// CaptureBaseline issues several requests for the clean (non-injected) request
// and distills a stable baseline. It fails fast with ErrUnreachable when no
// request succeeds.
func CaptureBaseline(ctx context.Context, client *httpclient.Client, th Throttle, rr *injection.RenderedRequest, timeout time.Duration, meter *Meter) (*Baseline, error) {
	return CaptureBaselineN(ctx, client, th, rr, timeout, meter, 4)
}

// CaptureBaselineN is CaptureBaseline with an explicit cap on the number of
// probe requests. maxSamples <= 1 issues exactly one request and is used by
// --fast mode where the tiny stability win is not worth the extra round trips.
func CaptureBaselineN(ctx context.Context, client *httpclient.Client, th Throttle, rr *injection.RenderedRequest, timeout time.Duration, meter *Meter, maxSamples int) (*Baseline, error) {
	if maxSamples < 1 {
		maxSamples = 1
	}
	var sigs []*Sig
	for i := 0; i < maxSamples; i++ {
		resp, err := Do(ctx, client, th, rr.Method, rr.URL, rr.Body, rr.Headers, timeout, meter)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		sigs = append(sigs, SigOf(resp))
		if maxSamples > 1 && len(sigs) >= 2 && i >= 1 && Sim(sigs[len(sigs)-1], sigs[len(sigs)-2]) >= 0.90 {
			break
		}
	}
	if len(sigs) == 0 {
		return nil, ErrUnreachable
	}
	canonical := pickCanonical(sigs)
	var simSum float64
	for _, s := range sigs {
		if s != canonical {
			simSum += Sim(canonical, s)
		}
	}
	avgSim := 1.0
	if len(sigs) > 1 {
		avgSim = simSum / float64(len(sigs)-1)
	}
	var durs []time.Duration
	for _, s := range sigs {
		durs = append(durs, s.Duration)
	}
	return &Baseline{
		Sig:       canonical,
		Stable:    avgSim >= 0.90,
		Samples:   len(sigs),
		AvgSim:    avgSim,
		Median:    MedianDuration(durs),
		Durations: durs,
	}, nil
}

// pickCanonical returns the sample that is most similar to the others.
func pickCanonical(sigs []*Sig) *Sig {
	best, bestScore := 0, -1.0
	for i := range sigs {
		s := 0.0
		for j := range sigs {
			if j != i {
				s += Sim(sigs[i], sigs[j])
			}
		}
		if s > bestScore {
			bestScore = s
			best = i
		}
	}
	return sigs[best]
}

// MedianDuration returns the median of the given durations.
func MedianDuration(list []time.Duration) time.Duration {
	if len(list) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), list...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}
