package common

import (
	"context"
	"sync"
	"time"

	"github.com/0xseif-code/vexor/internal/httpclient"
)

// Throttle paces outbound requests: a configurable inter-request delay plus
// adaptive backoff when the target throttles us (429) or is failing (5xx).
type Throttle interface {
	// Wait blocks until the next request is allowed, honouring ctx.
	Wait(ctx context.Context) error
	// Note informs the throttle of a completed request's status so it can
	// adapt its pacing.
	Note(status int)
}

type throttle struct {
	mu       sync.Mutex
	delay    time.Duration
	cooldown time.Duration
	limit    time.Duration
	next     time.Time
}

// NewThrottle returns a Throttle that spaces requests by the configured delay.
// A zero delay still imposes a tiny floor so a target is never hammered in an
// uncontrolled loop.
func NewThrottle(delay time.Duration) Throttle {
	if delay <= 0 {
		delay = 50 * time.Millisecond
	}
	return &throttle{delay: delay, limit: 30 * time.Second}
}

func (t *throttle) Wait(ctx context.Context) error {
	t.mu.Lock()
	wait := time.Until(t.next)
	t.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *throttle) Note(status int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if status == 429 {
		t.cooldown += time.Second
		if t.cooldown > t.limit {
			t.cooldown = t.limit
		}
	} else if status >= 500 && status < 600 {
		if t.cooldown < time.Second {
			t.cooldown = time.Second
		}
	} else {
		// Decay the backoff once we see healthy responses.
		t.cooldown -= t.delay
		if t.cooldown < 0 {
			t.cooldown = 0
		}
	}

	if next := t.next.Add(t.delay + t.cooldown); next.After(t.next) {
		t.next = next
	}
}

// Do sends one request with the shared throttle/meter plumbing. A configured
// timeout is applied per-request on top of ctx. The target's status feeds back
// into the throttle so it can slow down under pressure.
func Do(ctx context.Context, client *httpclient.Client, th Throttle, method, url string, body []byte, headers map[string]string, timeout time.Duration, meter *Meter) (*httpclient.Response, error) {
	if err := th.Wait(ctx); err != nil {
		return nil, err
	}
	if meter != nil {
		meter.Requests.Add(1)
	}
	reqCtx, cancel := ctx, func() {}
	if timeout > 0 {
		reqCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	resp, err := client.Do(reqCtx, method, url, body, headers)
	cancel()
	if err != nil {
		if meter != nil {
			meter.Errors.Add(1)
		}
		return nil, err
	}
	if resp != nil {
		th.Note(resp.StatusCode)
	}
	return resp, nil
}
