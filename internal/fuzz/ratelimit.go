package fuzz

import (
	"context"
	"errors"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

var (
	// ErrTargetUnreachable indicates baseline capture could not reach the
	// target at startup.
	ErrTargetUnreachable = errors.New("target unreachable during baseline capture")

	// ErrNoURL indicates the request URL is empty.
	ErrNoURL = errors.New("no request URL configured")

	// ErrNoMarkers indicates no FUZZ marker was found in the request.
	ErrNoMarkers = errors.New("no FUZZ marker found in request")

	// ErrNoClient indicates the HTTP client was not provided.
	ErrNoClient = errors.New("http client not configured")

	// ErrNoSelector indicates the wordlist selector was not provided.
	ErrNoSelector = errors.New("wordlist selector not configured")

	// ErrCombinatorics indicates the estimated request count exceeds the
	// safety limit without confirmation.
	ErrCombinatorics = errors.New("estimated request count exceeds limit; set ConfirmExceeding to proceed")
)

const (
	defaultRetryAfterBackoff = 1 * time.Second
	maxRetryAfterCap         = 10 * time.Second
	consecutive5xxThreshold  = 5
	consecutive5xxCooldown   = 2 * time.Second
)

// rateController implements request rate limiting with adaptive backoff on
// 429 responses and auto-concurrency throttling on repeated 5xx responses.
//
// The "workers" field is advisory (the worker pool size is fixed); the
// controller's concurrency reduction is implemented as a temporary per-request
// sleep so the pool itself never needs to resize with side effects.
type rateController struct {
	limiter *rate.Limiter // nil when unlimited
	delay   time.Duration // per-worker delay

	mu            sync.Mutex
	throttleUntil time.Time // global pause until this time (429 backoff)
	serverErrs    int       // consecutive 5xx count
	serv5xxCooldn time.Time // next allowed 5xx throttle rearm

	retryAfterMax int
}

// newRateController builds a rate controller from config. When RateLimit and
// Delay are both zero, an unlimited controller is returned.
func newRateController(cfg Config) *rateController {
	rc := &rateController{delay: cfg.Delay}
	if cfg.RateLimit > 0 {
		// A burst slightly above the sustained rate smooths worker starts.
		burst := cfg.RateLimit
		if burst < 2 {
			burst = 2
		}
		rc.limiter = rate.NewLimiter(rate.Limit(cfg.RateLimit), burst)
	}
	if cfg.Timeout > 0 && int(cfg.Timeout/time.Second) < 10 {
		rc.retryAfterMax = 10
	} else {
		rc.retryAfterMax = int(maxRetryAfterCap / time.Second)
	}
	return rc
}

// wait blocks until the next request is permitted, respecting the limiter,
// per-worker delay, and any active backoff pause. It returns an error when
// the context is cancelled.
func (rc *rateController) wait(ctx context.Context) error {
	// Global backoff pause check.
	if rc.mu.Lock(); time.Now().Before(rc.throttleUntil) {
		until := rc.throttleUntil
		rc.mu.Unlock()
		if err := sleepUntil(ctx, until); err != nil {
			return err
		}
	} else {
		rc.mu.Unlock()
	}

	if rc.limiter != nil {
		if err := rc.limiter.Wait(ctx); err != nil {
			return err
		}
	}

	if rc.delay > 0 {
		if err := sleepCtxDuration(ctx, rc.delay); err != nil {
			return err
		}
	}
	return nil
}

// noteResponse feeds a response status back so the controller can adapt.
// status 429 schedules a backoff pause; repeated 5xx throttles briefly.
func (rc *rateController) noteResponse(status int, retryAfter string) {
	if status != 429 && !(status >= 500 && status <= 599) {
		// Success or non-throttling: reset consecutive-5xx counter only for
		// non-5xx (a 429 has its own handling).
		if status < 500 || status > 599 {
			rc.mu.Lock()
			rc.serverErrs = 0
			rc.mu.Unlock()
		}
		return
	}

	rc.mu.Lock()
	defer rc.mu.Unlock()

	if status == 429 {
		backoff := rc.backoffFromRetryAfter(retryAfter)
		now := time.Now()
		if now.Add(backoff).After(rc.throttleUntil) {
			rc.throttleUntil = now.Add(backoff)
		}
		return
	}

	// 5xx handling.
	rc.serverErrs++
	if rc.serverErrs >= consecutive5xxThreshold && time.Now().After(rc.serv5xxCooldn) {
		// Throttle the scan briefly so the target can recover.
		rc.serv5xxCooldn = time.Now().Add(consecutive5xxCooldown)
		if now := time.Now(); now.Add(backoffFrom5xx()).After(rc.throttleUntil) {
			rc.throttleUntil = now.Add(backoffFrom5xx())
		}
		rc.serverErrs = 0
	}
}

// backoffFromRetryAfter derives a pause duration from a Retry-After header.
func (rc *rateController) backoffFromRetryAfter(retryAfter string) time.Duration {
	d := parseRetryAfterSeconds(retryAfter)
	if d > maxRetryAfterCap {
		d = maxRetryAfterCap
	}
	return d
}

// backoffFrom5xx returns the default pause duration applied after repeated
// server errors.
func backoffFrom5xx() time.Duration {
	return consecutive5xxCooldown
}

// parseRetryAfterSeconds interprets a Retry-After header value (seconds or
// HTTP-date). Returns a best-effort duration.
func parseRetryAfterSeconds(v string) time.Duration {
	v = trimSpace(v)
	if v == "" {
		return defaultRetryAfterBackoff
	}
	// HTTP-date form: RFC1123.
	if t, err := time.Parse(time.RFC1123, v); err == nil {
		d := time.Until(t)
		if d < 0 {
			d = 0
		}
		return d
	}
	// Integer seconds.
	var secs int
	if _, err := scanInt(v, &secs); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return defaultRetryAfterBackoff
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

func scanInt(s string, out *int) (int, error) {
	n := 0
	started := false
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
		started = true
	}
	if !started {
		return 0, errors.New("not an integer")
	}
	*out = n
	return n, nil
}

// sleepUntil sleeps until the given time or until ctx is cancelled.
func sleepUntil(ctx context.Context, until time.Time) error {
	d := time.Until(until)
	if d <= 0 {
		return nil
	}
	return sleepCtxDuration(ctx, d)
}

// sleepCtxDuration sleeps for d or returns when ctx is cancelled.
func sleepCtxDuration(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
