package httpclient

import (
	"bytes"
	"strings"
	"time"
)

type Response struct {
	StatusCode    int
	Headers       map[string]string
	Body          []byte
	ContentLength int64
	Duration      time.Duration
	URL           string
	Redirects     []string
}

func (r *Response) BodyString() string {
	return string(r.Body)
}

func (r *Response) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

func (r *Response) IsRedirect() bool {
	return r.StatusCode >= 300 && r.StatusCode < 400
}

func (r *Response) ContainsBody(s string) bool {
	return bytes.Contains(r.Body, []byte(s))
}

func (r *Response) HeaderGet(key string) string {
	if len(r.Headers) == 0 {
		return ""
	}
	for k, v := range r.Headers {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}
