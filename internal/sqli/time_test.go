package sqli

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/0xseif-code/vexor/internal/httpclient"
)

var sleepRe = regexp.MustCompile(`(?i)SLEEP\((\d+)\)`)

func slowSQLApp(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if m := sleepRe.FindStringSubmatch(id); m != nil {
		secs, _ := time.ParseDuration(m[1] + "s")
		time.Sleep(secs + 400*time.Millisecond)
	}
	w.WriteHeader(http.StatusOK)
	if id == "1" {
		io.WriteString(w, "<html>ok page</html>")
		return
	}
	io.WriteString(w, "<html>ok page</html>")
}

func TestDetectorTimeBased(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(slowSQLApp))
	defer srv.Close()

	client := httpclient.NewClient(httpclient.ClientOptions{
		Timeout:         30 * time.Second,
		FollowRedirects: false,
	})
	d := New(Config{
		URL:        srv.URL + "/items?id=1",
		Level:      1,
		Risk:       1,
		Threads:    2,
		Sleep:      2 * time.Second,
		Techniques: []string{"time-based blind"},
		Timeout:    30 * time.Second,
		Progress:   io.Discard,
	}, client)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dets, errs := d.Run(ctx)
	go func() {
		for range errs {
		}
	}()
	var findings []Detection
	for det := range dets {
		findings = append(findings, det)
	}
	if len(findings) == 0 {
		t.Fatal("time-based scan produced no findings")
	}
	f := findings[0]
	if f.Technique != "time-based blind" {
		t.Fatalf("technique = %q", f.Technique)
	}
	if f.Evidence == "" {
		t.Fatal("missing evidence")
	}
	t.Logf("time finding: dbms=%s conf=%d evidence=%s", f.DBMS, f.Confidence, f.Evidence)
}
