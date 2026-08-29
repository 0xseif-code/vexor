package httpclient

import "time"

const DefaultUserAgent = "Vexor/1.0"

type ClientOptions struct {
	Timeout         time.Duration
	MaxRetries      int
	RetryDelay      time.Duration
	Concurrency     int
	TLSSkipVerify   bool
	FollowRedirects bool
	MaxRedirects    int
	Headers         map[string]string
	Cookies         map[string]string
	ProxyURL        string
	UserAgent       string
}

func DefaultOptions() ClientOptions {
	return ClientOptions{
		Timeout:         10 * time.Second,
		MaxRetries:      3,
		RetryDelay:      500 * time.Millisecond,
		Concurrency:     50,
		TLSSkipVerify:   true,
		FollowRedirects: true,
		MaxRedirects:    10,
		Headers:         make(map[string]string),
		Cookies:         make(map[string]string),
		UserAgent:       DefaultUserAgent,
	}
}

func (o *ClientOptions) fillDefaults() {
	d := DefaultOptions()
	if o.Timeout <= 0 {
		o.Timeout = d.Timeout
	}
	if o.MaxRetries < 0 {
		o.MaxRetries = d.MaxRetries
	}
	if o.RetryDelay <= 0 {
		o.RetryDelay = d.RetryDelay
	}
	if o.Concurrency <= 0 {
		o.Concurrency = d.Concurrency
	}
	if o.MaxRedirects < 1 {
		o.MaxRedirects = d.MaxRedirects
	}
	if o.UserAgent == "" {
		o.UserAgent = d.UserAgent
	}
	if o.Headers == nil {
		o.Headers = make(map[string]string)
	}
	if o.Cookies == nil {
		o.Cookies = make(map[string]string)
	}
}
