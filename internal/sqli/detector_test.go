package sqli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/0xseif-code/vexor/internal/httpclient"
)

// fakeSQLApp emulates a MySQL-ish backend that interpolates the id parameter
// into a WHERE clause. True conditions return the row page, false conditions
// return the empty-result page.
func fakeSQLApp(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	found := true
	switch {
	case strings.Contains(id, "1=2"), strings.Contains(id, "'1'='2"):
		found = false
	case strings.Contains(id, "1=1"), strings.Contains(id, "'1'='1"), strings.Contains(id, "XOR 1"), strings.Contains(id, "SOUNDS LIKE"), strings.Contains(id, "GLOB 'x'"):
		found = true
	}
	if found {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html><h1>Item</h1><p>socks 12.99</p><p>sku: 334455</p></html>")
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "<html><h1>No result</h1></html>")
}

func TestDetectorFindsBooleanMySQL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(fakeSQLApp))
	defer srv.Close()

	client := httpclient.NewClient(httpclient.ClientOptions{
		Timeout:         5 * time.Second,
		FollowRedirects: false,
	})
	cfg := Config{
		URL:      srv.URL + "/items?id=1",
		Level:    1,
		Risk:     1,
		Threads:  2,
		Progress: io.Discard,
	}
	d := New(cfg, client)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dets, errs := d.Run(ctx)
	var findings []Detection
	for det := range dets {
		findings = append(findings, det)
	}
	var errList []string
	for e := range errs {
		errList = append(errList, e.Error())
	}
	if len(errList) > 0 {
		t.Fatalf("unexpected errors: %v", errList)
	}
	if len(findings) == 0 {
		t.Fatal("no findings produced")
	}
	f := findings[0]
	if f.Technique == "" || f.Confidence < 50 {
		t.Fatalf("weak finding: %+v", f)
	}
	if f.Payload == "" {
		t.Fatal("finding has no payload")
	}
	t.Logf("finding: technique=%s dbms=%s confidence=%d payload=%q", f.Technique, f.DBMS, f.Confidence, f.Payload)
}

func TestDetectorRawRequestFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(fakeSQLApp))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	raw := "GET /items?id=1 HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	rawFile := t.TempDir() + "/req.txt"
	if err := writeFile(rawFile, raw); err != nil {
		t.Fatal(err)
	}

	client := httpclient.NewClient(httpclient.ClientOptions{
		Timeout:         5 * time.Second,
		FollowRedirects: false,
	})
	d := New(Config{
		RawRequestFile: rawFile,
		Level:          1,
		Risk:           1,
		Threads:        2,
		Progress:       io.Discard,
	}, client)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dets, _ := d.Run(ctx)
	var findings []Detection
	for det := range dets {
		findings = append(findings, det)
	}
	if len(findings) == 0 {
		t.Fatal("raw-request scan produced no findings")
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

func TestStatsAfterScan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(fakeSQLApp))
	defer srv.Close()
	client := httpclient.NewClient(httpclient.ClientOptions{Timeout: 5 * time.Second})
	d := New(Config{URL: srv.URL + "/items?id=1", Progress: io.Discard}, client)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dets, _ := d.Run(ctx)
	for range dets {
	}
	st := d.Stats()
	if st.Requests == 0 {
		t.Fatal("stats request counter empty")
	}
	if st.Findings == 0 {
		t.Fatal("stats findings counter zero")
	}
}
