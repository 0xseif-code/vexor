package httpclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/valyala/fasthttp"
)

func shutdownServer(t *testing.T, s *fasthttp.Server) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	_ = s.ShutdownWithContext(ctx)
}

func startServer(t *testing.T, handler fasthttp.RequestHandler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fasthttp.Server{Handler: handler}
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() { shutdownServer(t, s) })
	return "http://" + ln.Addr().String()
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func startTLSServer(t *testing.T, handler fasthttp.RequestHandler) string {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln := tls.NewListener(raw, &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}})
	s := &fasthttp.Server{Handler: handler}
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() { shutdownServer(t, s) })
	return "https://" + raw.Addr().String()
}

func TestGet(t *testing.T) {
	base := startServer(t, func(ctx *fasthttp.RequestCtx) {
		ctx.Response.SetStatusCode(200)
		ctx.Response.Header.Set("X-Test", "yes")
		ctx.Response.SetBodyString("hello world")
	})

	c := NewClient(DefaultOptions())
	resp, err := c.Get(context.Background(), base+"/foo?q=1", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := resp.BodyString(); got != "hello world" {
		t.Fatalf("body = %q", got)
	}
	if resp.ContentLength != int64(len("hello world")) {
		t.Fatalf("content length = %d", resp.ContentLength)
	}
	if got := resp.HeaderGet("x-test"); got != "yes" {
		t.Fatalf("X-Test header = %q", got)
	}
	if !resp.ContainsBody("hello") {
		t.Fatalf("body should contain hello")
	}
	if resp.Duration <= 0 {
		t.Fatalf("duration = %v", resp.Duration)
	}
}

func TestPostHeadersCookies(t *testing.T) {
	ch := make(chan [4]string, 1)
	base := startServer(t, func(ctx *fasthttp.RequestCtx) {
		ch <- [4]string{
			string(ctx.Method()),
			string(ctx.Request.Header.UserAgent()),
			string(ctx.Request.Header.Cookie("sid")),
			string(ctx.Request.Header.Peek("X-Custom")),
		}
		ctx.Response.SetBody(ctx.Request.Body())
	})

	opts := DefaultOptions()
	opts.Headers = map[string]string{"X-Custom": "default"}
	opts.Cookies = map[string]string{"sid": "abc123"}
	c := NewClient(opts)

	body := []byte("payload=1")
	resp, err := c.Post(context.Background(), base, body, map[string]string{"X-Custom": "override"})
	if err != nil {
		t.Fatalf("Post: %v", err)
	}

	got := <-ch
	if got[0] != "POST" {
		t.Fatalf("method = %q", got[0])
	}
	if got[1] != DefaultUserAgent {
		t.Fatalf("user agent = %q", got[1])
	}
	if got[2] != "abc123" {
		t.Fatalf("cookie = %q", got[2])
	}
	if got[3] != "override" {
		t.Fatalf("X-Custom = %q", got[3])
	}
	if resp.BodyString() != "payload=1" {
		t.Fatalf("body = %q", resp.BodyString())
	}
}

func TestCookieHeaderString(t *testing.T) {
	ch := make(chan [2]string, 1)
	base := startServer(t, func(ctx *fasthttp.RequestCtx) {
		ch <- [2]string{
			string(ctx.Request.Header.Cookie("a")),
			string(ctx.Request.Header.Cookie("b")),
		}
	})

	c := NewClient(DefaultOptions())
	if _, err := c.Get(context.Background(), base, map[string]string{"Cookie": "a=1; b=2"}); err != nil {
		t.Fatalf("Get: %v", err)
	}
	got := <-ch
	if got[0] != "1" || got[1] != "2" {
		t.Fatalf("cookies = %v", got)
	}
}

func TestRedirect(t *testing.T) {
	base := startServer(t, func(ctx *fasthttp.RequestCtx) {
		switch string(ctx.Path()) {
		case "/":
			ctx.Response.Header.Set("Location", "/final")
			ctx.Response.SetStatusCode(302)
		case "/final":
			ctx.Response.SetBodyString("final")
		default:
			ctx.Response.SetStatusCode(404)
		}
	})

	c := NewClient(DefaultOptions())
	resp, err := c.Get(context.Background(), base+"/", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if resp.BodyString() != "final" {
		t.Fatalf("body = %q", resp.BodyString())
	}
	if resp.URL != base+"/final" {
		t.Fatalf("url = %q", resp.URL)
	}
	if len(resp.Redirects) != 1 || resp.Redirects[0] != base+"/final" {
		t.Fatalf("redirects = %v", resp.Redirects)
	}
}

func TestRedirectDisabled(t *testing.T) {
	base := startServer(t, func(ctx *fasthttp.RequestCtx) {
		ctx.Response.Header.Set("Location", "/final")
		ctx.Response.SetStatusCode(302)
	})

	opts := DefaultOptions()
	opts.FollowRedirects = false
	c := NewClient(opts)

	resp, err := c.Get(context.Background(), base+"/", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.StatusCode != 302 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if len(resp.Redirects) != 0 {
		t.Fatalf("redirects = %v", resp.Redirects)
	}
	if resp.URL != base+"/" {
		t.Fatalf("url = %q", resp.URL)
	}
}

func TestMaxRedirects(t *testing.T) {
	base := startServer(t, func(ctx *fasthttp.RequestCtx) {
		ctx.Response.Header.Set("Location", string(ctx.Path())+"x")
		ctx.Response.SetStatusCode(302)
	})

	opts := DefaultOptions()
	opts.MaxRedirects = 2
	c := NewClient(opts)

	resp, err := c.Get(context.Background(), base+"/0", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.StatusCode != 302 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if len(resp.Redirects) != 2 {
		t.Fatalf("redirects = %v", resp.Redirects)
	}
}

func TestContextCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fasthttp.Server{
		Handler: func(_ *fasthttp.RequestCtx) {
			time.Sleep(3 * time.Second)
		},
	}
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() { shutdownServer(t, s) })
	base := "http://" + ln.Addr().String()

	c := NewClient(DefaultOptions())
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = c.Get(ctx, base, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("cancel took %v", elapsed)
	}
}

func TestTLSSkipVerify(t *testing.T) {
	base := startTLSServer(t, func(ctx *fasthttp.RequestCtx) {
		ctx.Response.SetBodyString("tls ok")
	})

	c := NewClient(DefaultOptions())
	resp, err := c.Get(context.Background(), base, nil)
	if err != nil {
		t.Fatalf("skip-verify Get: %v", err)
	}
	if resp.BodyString() != "tls ok" {
		t.Fatalf("body = %q", resp.BodyString())
	}

	strict := DefaultOptions()
	strict.TLSSkipVerify = false
	sc := NewClient(strict)
	if _, err := sc.Get(context.Background(), base, nil); err == nil {
		t.Fatal("expected certificate verification error")
	}
}

func TestRetryOnServerError(t *testing.T) {
	var calls atomic.Int32
	base := startServer(t, func(ctx *fasthttp.RequestCtx) {
		if calls.Add(1) < 3 {
			ctx.Response.SetStatusCode(500)
			return
		}
		ctx.Response.SetStatusCode(200)
		ctx.Response.SetBodyString("recovered")
	})

	opts := DefaultOptions()
	opts.MaxRetries = 2
	opts.RetryDelay = 10 * time.Millisecond
	c := NewClient(opts)

	resp, err := c.Get(context.Background(), base, nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if resp.BodyString() != "recovered" {
		t.Fatalf("body = %q", resp.BodyString())
	}
	if calls.Load() != 3 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestNoRetryWhenDisabled(t *testing.T) {
	var calls atomic.Int32
	base := startServer(t, func(ctx *fasthttp.RequestCtx) {
		calls.Add(1)
		ctx.Response.SetStatusCode(500)
	})

	opts := DefaultOptions()
	opts.MaxRetries = 0
	c := NewClient(opts)

	resp, err := c.Get(context.Background(), base, nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.StatusCode != 500 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestInvalidProxy(t *testing.T) {
	opts := DefaultOptions()
	opts.ProxyURL = "ftp://proxy.invalid"
	c := NewClient(opts)
	if c.InitError() == nil {
		t.Fatal("expected init error")
	}
	if _, err := c.Get(context.Background(), "http://example.com", nil); err == nil {
		t.Fatal("expected error from init failure")
	}
}

func TestStreamBody(t *testing.T) {
	const size = 1024 * 1024
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	orig := payload
	base := startServer(t, func(ctx *fasthttp.RequestCtx) {
		ctx.SetBodyStreamWriter(func(w *bufio.Writer) {
			for len(payload) > 0 {
				chunk := payload
				if len(chunk) > 64*1024 {
					chunk = chunk[:64*1024]
				}
				_, _ = w.Write(chunk)
				_ = w.Flush()
				payload = payload[len(chunk):]
			}
		})
	})

	c := NewClient(DefaultOptions())
	var got bytes.Buffer
	resp, err := c.Stream(context.Background(), fasthttp.MethodGet, base, nil, nil, &got)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !bytes.Equal(got.Bytes(), orig) {
		t.Fatalf("streamed body mismatch: got %d bytes want %d", got.Len(), len(orig))
	}
}

func TestStreamRedirect(t *testing.T) {
	base := startServer(t, func(ctx *fasthttp.RequestCtx) {
		switch string(ctx.Path()) {
		case "/":
			ctx.Response.Header.Set("Location", "/data")
			ctx.Response.SetStatusCode(302)
		case "/data":
			ctx.Response.SetBodyString("final-data")
		default:
			ctx.Response.SetStatusCode(404)
		}
	})

	c := NewClient(DefaultOptions())
	var got bytes.Buffer
	resp, err := c.Stream(context.Background(), fasthttp.MethodGet, base+"/", nil, nil, &got)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if got.String() != "final-data" {
		t.Fatalf("body = %q", got.String())
	}
	if resp.URL != base+"/data" {
		t.Fatalf("url = %q", resp.URL)
	}
	if len(resp.Redirects) != 1 || resp.Redirects[0] != base+"/data" {
		t.Fatalf("redirects = %v", resp.Redirects)
	}
}

func TestStreamContextCancel(t *testing.T) {
	base := startServer(t, func(ctx *fasthttp.RequestCtx) {
		ctx.SetBodyStreamWriter(func(w *bufio.Writer) {
			for i := 0; i < 20; i++ {
				_, _ = w.WriteString("chunk")
				_ = w.Flush()
				time.Sleep(200 * time.Millisecond)
			}
		})
	})

	c := NewClient(DefaultOptions())
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	var buf bytes.Buffer
	_, err := c.Stream(ctx, fasthttp.MethodGet, base, nil, nil, &buf)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("cancel took %v", elapsed)
	}
	if buf.Len() <= 0 {
		t.Fatal("expected some partial bytes")
	}
}

func TestStreamWriteError(t *testing.T) {
	base := startServer(t, func(ctx *fasthttp.RequestCtx) {
		ctx.SetBodyStreamWriter(func(w *bufio.Writer) {
			_, _ = w.WriteString("hello")
			_ = w.Flush()
		})
	})

	c := NewClient(DefaultOptions())
	_, err := c.Stream(context.Background(), fasthttp.MethodGet, base, nil, nil, errWriter{})
	if err == nil {
		t.Fatal("expected error")
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestConcurrency(t *testing.T) {
	var hits atomic.Int64
	base := startServer(t, func(ctx *fasthttp.RequestCtx) {
		hits.Add(1)
		ctx.Response.SetBodyString("ok")
	})

	opts := DefaultOptions()
	opts.Concurrency = 100
	c := NewClient(opts)

	const n = 200
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := c.Get(context.Background(), base, nil)
			if err != nil {
				errs <- fmt.Errorf("Get: %v", err)
				return
			}
			if !resp.IsSuccess() {
				errs <- fmt.Errorf("status = %d", resp.StatusCode)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if hits.Load() != n {
		t.Fatalf("hits = %d", hits.Load())
	}
}
