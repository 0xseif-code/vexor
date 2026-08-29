package directory

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xseif-code/vexor/internal/httpclient"
	"github.com/0xseif-code/vexor/internal/wordlists"
)

// writeWordlist writes a custom wordlist to a temp file and returns a
// Selector pointing at it via CustomPath, plus the physical path.
func writeWordlist(t *testing.T, dir string, words []string) (string, *wordlists.Selector) {
	t.Helper()
	path := filepath.Join(dir, "words.txt")
	if err := os.WriteFile(path, []byte(strings.Join(words, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	mgr, err := wordlists.NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	return path, wordlists.NewSelector(mgr)
}

// startTestServer returns a fake targeted server: /admin and /config return
// 200; everything else returns 404. The 404 body is a fixed soft-404 page.
func startTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	notFound := "<html><title>404 Not Found</title><body>Page not found.</body></html>"
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin", "/config":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(200)
			_, _ = w.Write([]byte("<html><title>Dashboard</title></html>"))
		default:
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(404)
			_, _ = w.Write([]byte(notFound))
		}
	})
	ts := httptest.NewServer(mux)
	return ts
}

func TestScannerFindsAndFiltersSoft404(t *testing.T) {
	ts := startTestServer(t)
	defer ts.Close()

	path, sel := writeWordlist(t, t.TempDir(), []string{"admin", "config", "nonexistent"})

	client := httpclient.NewClient(httpclient.DefaultOptions())
	cfg := Config{
		TargetURL:    ts.URL,
		Concurrency:  5,
		WordlistOpts: wordlists.Options{CustomPath: path},
	}
	sc := New(cfg, client, sel)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	findings, errs := sc.Run(ctx)

	var got []Finding
	for f := range findings {
		got = append(got, f)
	}
	for err := range errs {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	// "nonexistent" should be filtered out as a soft-404; admin/config found.
	if len(got) < 2 {
		t.Fatalf("expected >=2 findings, got %d: %+v", len(got), got)
	}
	found := map[string]bool{}
	for _, f := range got {
		found[f.URL] = true
	}
	if !found[ts.URL+"/admin"] || !found[ts.URL+"/config"] {
		t.Fatalf("missing admin/config; got %v", found)
	}
	if found[ts.URL+"/nonexistent"] {
		t.Fatalf("soft-404 'nonexistent' was not filtered out: %v", found)
	}
}

func TestCleanDomainExpansion(t *testing.T) {
	cases := []struct {
		word      string
		exts      []string
		wantFirst string
		wantCount int
	}{
		{"admin", nil, "/admin", 1},
		{"admin", []string{"php", "html"}, "/admin", 3},
		{"/admin", []string{"php"}, "/admin", 2},
		{"backup/", []string{"php"}, "/backup/", 1},
		{"admin.bak", []string{"php"}, "/admin.bak", 2},
	}
	for _, c := range cases {
		got := expandWord("/", c.word, c.exts)
		if len(got) != c.wantCount {
			t.Errorf("expandWord(%q) count = %d, want %d (got %v)", c.word, len(got), c.wantCount, got)
		}
		if len(got) > 0 && got[0] != c.wantFirst {
			t.Errorf("expandWord(%q)[0] = %q, want %q", c.word, got[0], c.wantFirst)
		}
	}
}

// TestScannerRecursion verifies that enabling recursion scans discovered
// directories without deadlocking on shutdown (regression for the pending
// counter / queue-close race).
func TestScannerRecursion(t *testing.T) {
	ts := startRecursiveServer(t)
	defer ts.Close()

	path, sel := writeWordlist(t, t.TempDir(), []string{"admin", "users"})

	client := httpclient.NewClient(httpclient.DefaultOptions())
	cfg := Config{
		TargetURL:    ts.URL,
		Concurrency:  5,
		Recursion:    true,
		MaxDepth:     2,
		WordlistOpts: wordlists.Options{CustomPath: path},
	}
	sc := New(cfg, client, sel)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	findings, _ := sc.Run(ctx)

	got := 0
	for range findings {
		got++
	}
	if got < 2 {
		t.Fatalf("expected >=2 findings with recursion, got %d", got)
	}
}

// startRecursiveServer returns a server with /admin (200) and /admin/users
// (200); everything else 404.
func startRecursiveServer(t *testing.T) *httptest.Server {
	t.Helper()
	notFound := "<html><title>404 Not Found</title></html>"
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin", "/admin/", "/admin/users", "/admin/users/", "/users", "/users/":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(200)
			_, _ = w.Write([]byte("<html><title>OK</title></html>"))
		default:
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(404)
			_, _ = w.Write([]byte(notFound))
		}
	})
	return httptest.NewServer(mux)
}
