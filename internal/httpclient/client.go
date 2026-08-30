package httpclient

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
	"golang.org/x/net/proxy"
)

const (
	maxBackoff      = 30 * time.Second
	maxIdleDuration = 30 * time.Second
	maxConnWait     = 30 * time.Second
	maxConnDuration = 30 * time.Minute

	// maxConnsPerHost caps persistent connections per upstream. Kept high so
	// the shared client can keep keep-alive connections warm across a wide
	// worker fan-out without re-dialing.
	maxConnsPerHost = 512
)

type Client struct {
	opts    ClientOptions
	client  *fasthttp.Client
	initErr error
}

func NewClient(opts ClientOptions) *Client {
	opts.fillDefaults()

	c := &Client{opts: opts}

	dial, err := buildDialFunc(opts.Timeout, opts.ProxyURL)
	if err != nil {
		c.initErr = err
	}

	c.client = &fasthttp.Client{
		Name:                      opts.UserAgent,
		Dial:                      dial,
		TLSConfig:                 insecureTLSConfig(opts.TLSSkipVerify),
		MaxConnsPerHost:           maxConnsPerHost,
		ReadTimeout:               opts.Timeout,
		WriteTimeout:              opts.Timeout,
		MaxConnWaitTimeout:        maxConnWait,
		MaxIdleConnDuration:       maxIdleDuration,
		MaxConnDuration:           maxConnDuration,
		MaxIdemponentCallAttempts: 1,
		DisablePathNormalizing:    true,
		NoDefaultUserAgentHeader:  true,
	}
	return c
}

func (c *Client) InitError() error {
	return c.initErr
}

func (c *Client) Do(ctx context.Context, method, target string, body []byte, headers map[string]string) (*Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.opts.Timeout)
		defer cancel()
	}
	if c.initErr != nil {
		return nil, c.initErr
	}
	return c.do(ctx, method, target, body, headers)
}

func (c *Client) Get(ctx context.Context, target string, headers map[string]string) (*Response, error) {
	return c.Do(ctx, fasthttp.MethodGet, target, nil, headers)
}

func (c *Client) Post(ctx context.Context, target string, body []byte, headers map[string]string) (*Response, error) {
	return c.Do(ctx, fasthttp.MethodPost, target, body, headers)
}

func (c *Client) Head(ctx context.Context, target string) (*Response, error) {
	return c.Do(ctx, fasthttp.MethodHead, target, nil, nil)
}

func (c *Client) Put(ctx context.Context, target string, body []byte, headers map[string]string) (*Response, error) {
	return c.Do(ctx, fasthttp.MethodPut, target, body, headers)
}

func (c *Client) Delete(ctx context.Context, target string, headers map[string]string) (*Response, error) {
	return c.Do(ctx, fasthttp.MethodDelete, target, nil, headers)
}

func (c *Client) Options(ctx context.Context, target string, headers map[string]string) (*Response, error) {
	return c.Do(ctx, fasthttp.MethodOptions, target, nil, headers)
}

func (c *Client) Stream(ctx context.Context, method, target string, body []byte, headers map[string]string, w io.Writer) (*Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.opts.Timeout)
		defer cancel()
	}
	if c.initErr != nil {
		return nil, c.initErr
	}
	return c.stream(ctx, method, target, body, headers, w)
}

func (c *Client) stream(ctx context.Context, method, target string, body []byte, headers map[string]string, w io.Writer) (*Response, error) {
	curMethod := method
	curURL := target
	curBody := body
	var redirects []string

	for hop := 0; ; hop++ {
		resp, written, err := c.streamHop(ctx, curMethod, curURL, curBody, headers, w)
		if err != nil {
			return nil, err
		}
		resp.Redirects = redirects

		location := resp.HeaderGet("Location")
		if !c.opts.FollowRedirects || hop >= c.opts.MaxRedirects || !isRedirectCode(resp.StatusCode) || location == "" || written > 0 {
			return resp, nil
		}

		nextURL, err := resolveRedirect(curURL, location)
		if err != nil {
			return resp, nil
		}

		curMethod = nextMethod(curMethod, resp.StatusCode)
		if !preserveBody(resp.StatusCode) {
			curBody = nil
		}
		curURL = nextURL
		redirects = append(redirects, nextURL)
	}
}

func (c *Client) streamHop(ctx context.Context, method, target string, body []byte, headers map[string]string, w io.Writer) (*Response, int64, error) {
	type hopResult struct {
		resp *Response
		n    int64
		err  error
	}

	done := make(chan hopResult, 1)
	go func() {
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		defer func() {
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
		}()

		c.buildRequest(req, method, target, body, headers)
		resp.StreamBody = true

		if err := c.client.Do(req, resp); err != nil {
			done <- hopResult{err: err}
			return
		}

		rd := &Response{
			StatusCode: resp.StatusCode(),
			Headers:    make(map[string]string, resp.Header.Len()),
			URL:        target,
		}
		resp.Header.VisitAll(func(k, v []byte) {
			rd.Headers[string(k)] = string(v)
		})
		if cl := resp.Header.ContentLength(); cl > 0 {
			rd.ContentLength = int64(cl)
		}

		abort := func(r hopResult) {
			_ = resp.CloseBodyStream()
			done <- r
		}

		stream := resp.BodyStream()
		if stream == nil {
			abort(hopResult{resp: rd})
			return
		}

		var (
			n   int64
			buf [32 * 1024]byte
		)
		for {
			if cerr := ctx.Err(); cerr != nil {
				abort(hopResult{resp: rd, err: cerr})
				return
			}
			nr, rerr := stream.Read(buf[:])
			if nr > 0 {
				if nw, werr := w.Write(buf[:nr]); werr != nil || nw != nr {
					if werr == nil {
						werr = io.ErrShortWrite
					}
					abort(hopResult{resp: rd, err: fmt.Errorf("write stream to destination: %w", werr)})
					return
				}
				n += int64(nr)
			}
			if rerr != nil {
				if rerr == io.EOF {
					abort(hopResult{resp: rd, n: n})
					return
				}
				abort(hopResult{resp: rd, err: fmt.Errorf("read response stream: %w", rerr)})
				return
			}
		}
	}()

	select {
	case r := <-done:
		return r.resp, r.n, r.err
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	}
}

func (c *Client) do(ctx context.Context, method, target string, body []byte, headers map[string]string) (*Response, error) {
	curMethod := method
	curURL := target
	curBody := body
	var redirects []string

	for hop := 0; ; hop++ {
		resp, err := c.doWithRetry(ctx, curMethod, curURL, curBody, headers)
		if err != nil {
			return nil, err
		}
		resp.Redirects = redirects

		location := resp.HeaderGet("Location")
		if !c.opts.FollowRedirects || hop >= c.opts.MaxRedirects || !isRedirectCode(resp.StatusCode) || location == "" {
			return resp, nil
		}

		nextURL, err := resolveRedirect(curURL, location)
		if err != nil {
			return resp, nil
		}

		curMethod = nextMethod(curMethod, resp.StatusCode)
		if !preserveBody(resp.StatusCode) {
			curBody = nil
		}
		curURL = nextURL
		redirects = append(redirects, nextURL)
	}
}

func (c *Client) doWithRetry(ctx context.Context, method, target string, body []byte, headers map[string]string) (*Response, error) {
	backoff := c.opts.RetryDelay
	var lastResp *Response
	var lastErr error

	for attempt := 0; ; attempt++ {
		lastResp, lastErr = c.exec(ctx, method, target, body, headers)

		if lastErr == nil && !isRetryableStatus(lastResp.StatusCode) {
			return lastResp, nil
		}

		if attempt >= c.opts.MaxRetries {
			return lastResp, lastErr
		}

		if lastErr != nil && !isRetryableErr(lastErr) {
			return nil, lastErr
		}

		if err := sleepCtx(ctx, backoff); err != nil {
			return lastResp, err
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (c *Client) exec(ctx context.Context, method, target string, body []byte, headers map[string]string) (*Response, error) {
	type attempt struct {
		resp *Response
		err  error
	}

	done := make(chan attempt, 1)
	go func() {
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		defer func() {
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
		}()

		c.buildRequest(req, method, target, body, headers)

		start := time.Now()
		if err := c.client.Do(req, resp); err != nil {
			done <- attempt{err: err}
			return
		}
		done <- attempt{resp: c.parseResponse(resp, start, target)}
	}()

	select {
	case a := <-done:
		return a.resp, a.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Client) buildRequest(req *fasthttp.Request, method, target string, body []byte, headers map[string]string) {
	req.Header.SetMethod(strings.ToUpper(method))
	req.SetRequestURI(target)

	if len(body) > 0 {
		req.SetBody(body)
	}

	merged := mergeHeaders(c.opts.Headers, headers)

	for key, value := range merged {
		switch strings.ToLower(key) {
		case "host":
			req.SetHost(value)
		case "cookie":
		default:
			req.Header.Set(key, value)
		}
	}

	if !hasHeader(merged, "user-agent") && c.opts.UserAgent != "" {
		req.Header.SetUserAgent(c.opts.UserAgent)
	}

	for key, value := range c.opts.Cookies {
		req.Header.SetCookie(key, value)
	}
	if cookieValue, ok := headerValue(merged, "cookie"); ok {
		setCookieHeader(req, cookieValue)
	}
}

func (c *Client) parseResponse(resp *fasthttp.Response, start time.Time, target string) *Response {
	rd := &Response{
		StatusCode: resp.StatusCode(),
		Headers:    make(map[string]string, resp.Header.Len()),
		Body:       make([]byte, len(resp.Body())),
		Duration:   time.Since(start),
		URL:        target,
	}
	copy(rd.Body, resp.Body())
	rd.ContentLength = int64(len(rd.Body))

	resp.Header.VisitAll(func(key, value []byte) {
		rd.Headers[string(key)] = string(value)
	})
	return rd
}

func mergeHeaders(base, overlay map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(overlay))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range overlay {
		out[k] = v
	}
	return out
}

func hasHeader(headers map[string]string, name string) bool {
	for k := range headers {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}

func headerValue(headers map[string]string, name string) (string, bool) {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

func setCookieHeader(req *fasthttp.Request, value string) {
	for _, part := range strings.Split(value, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			req.Header.SetCookie(kv[0], kv[1])
		}
	}
}

func isRedirectCode(code int) bool {
	switch code {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

func preserveBody(status int) bool {
	return status == 307 || status == 308
}

func nextMethod(method string, status int) string {
	if status == 307 || status == 308 {
		return method
	}
	if method == fasthttp.MethodGet || method == fasthttp.MethodHead {
		return method
	}
	return fasthttp.MethodGet
}

func resolveRedirect(base, location string) (string, error) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	resolved := baseURL.ResolveReference(ref)
	resolved.Fragment = ""
	return resolved.String(), nil
}

func isRetryableStatus(code int) bool {
	switch code {
	case 408, 425, 429:
		return true
	}
	return code >= 500 && code <= 599
}

func isRetryableErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, fasthttp.ErrTimeout) ||
		errors.Is(err, fasthttp.ErrConnectionClosed) ||
		errors.Is(err, fasthttp.ErrNoFreeConns) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func insecureTLSConfig(skipVerify bool) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: skipVerify,
		MinVersion:         tls.VersionTLS10,
	}
}

func buildDialFunc(timeout time.Duration, proxyURL string) (fasthttp.DialFunc, error) {
	if proxyURL == "" {
		return newDirectDial(timeout), nil
	}

	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("parse proxy URL: %w", err)
	}

	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return newHTTPConnectDialer(u, timeout)
	case "socks5", "socks5h":
		fwd := &fasthttp.TCPDialer{Concurrency: 4096}
		fwdDial := netDialerFunc(func(network, addr string) (net.Conn, error) {
			return fwd.Dial(addr)
		})
		pd, err := proxy.FromURL(u, fwdDial)
		if err != nil {
			return nil, fmt.Errorf("socks5 proxy: %w", err)
		}
		return func(addr string) (net.Conn, error) {
			return pd.Dial("tcp", addr)
		}, nil
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (supported: http, https, socks5)", u.Scheme)
	}
}

type netDialerFunc func(network, addr string) (net.Conn, error)

func (f netDialerFunc) Dial(network, addr string) (net.Conn, error) {
	return f(network, addr)
}

func newDirectDial(timeout time.Duration) fasthttp.DialFunc {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	d := &fasthttp.TCPDialer{Concurrency: 4096}
	return func(addr string) (net.Conn, error) {
		return d.DialTimeout(addr, timeout)
	}
}

func newHTTPConnectDialer(u *url.URL, timeout time.Duration) (fasthttp.DialFunc, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	proxyAddr := u.Host
	if u.Port() == "" {
		if strings.EqualFold(u.Scheme, "https") {
			proxyAddr = net.JoinHostPort(u.Hostname(), "443")
		} else {
			proxyAddr = net.JoinHostPort(u.Hostname(), "80")
		}
	}
	if proxyAddr == "" {
		return nil, fmt.Errorf("proxy URL missing host")
	}

	cd := &connectDialer{
		proxyAddr: proxyAddr,
		proxyTLS:  strings.EqualFold(u.Scheme, "https"),
		timeout:   timeout,
	}
	if u.User != nil {
		cd.username = u.User.Username()
		cd.password, _ = u.User.Password()
	}
	return cd.Dial, nil
}

type connectDialer struct {
	proxyAddr string
	proxyTLS  bool
	username  string
	password  string
	timeout   time.Duration
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (bc *bufferedConn) Read(p []byte) (int, error) {
	return bc.reader.Read(p)
}

func (cd *connectDialer) Dial(addr string) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: cd.timeout}).Dial("tcp", cd.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("connect to proxy: %w", err)
	}

	if cd.proxyTLS {
		tlsConn := tls.Client(conn, insecureTLSConfig(true))
		_ = conn.SetDeadline(time.Now().Add(cd.timeout))
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("proxy TLS handshake: %w", err)
		}
		conn = tlsConn
	}

	_ = conn.SetDeadline(time.Now().Add(cd.timeout))

	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if cd.username != "" {
		creds := base64.StdEncoding.EncodeToString([]byte(cd.username + ":" + cd.password))
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", creds)
	}
	b.WriteString("Proxy-Connection: keep-alive\r\n\r\n")

	if _, err := conn.Write([]byte(b.String())); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write CONNECT request: %w", err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read proxy response: %w", err)
	}
	fields := strings.Fields(statusLine)
	if len(fields) < 2 || fields[1] != "200" {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", strings.TrimSpace(statusLine))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			if err == io.EOF && strings.TrimSpace(line) == "" {
				break
			}
			conn.Close()
			return nil, fmt.Errorf("read proxy headers: %w", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	_ = conn.SetDeadline(time.Time{})

	return &bufferedConn{Conn: conn, reader: br}, nil
}
