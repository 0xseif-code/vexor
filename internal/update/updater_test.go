package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"v1.0.1":          "1.0.1",
		"V1.2.3":          "1.2.3",
		"1.0.1+meta":      "1.0.1",
		"v2.0.0-beta":     "2.0.0-beta",
		"  v1.0.0  ":      "1.0.0",
		"":                "",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSameVersion(t *testing.T) {
	if !SameVersion("v1.0.1", "1.0.1") {
		t.Error("v1.0.1 should equal 1.0.1")
	}
	if SameVersion("1.0.1", "1.0.2") {
		t.Error("1.0.1 must not equal 1.0.2")
	}
}

func TestCompare(t *testing.T) {
	pairs := []struct {
		a, b string
		want int
	}{
		{"v1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.2", -1},
		{"1.1.0", "1.0.9", 1},
		{"2.0.0", "1.9.9", 1},
		{"1.0.0", "1.0.0-beta", 1},   // release > pre-release
		{"1.0.0-beta", "1.0.0", -1},  // pre-release < release
		{"v1.0.0+abc", "1.0.0", 0},   // build metadata ignored
		{"1.0", "1.0.0", 0},          // missing part = zero
	}
	for _, p := range pairs {
		if got := Compare(p.a, p.b); got != p.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", p.a, p.b, got, p.want)
		}
	}
}

func checkClient(base string) Options {
	return Options{
		CurrentVersion: "1.0.0",
		Repo:           "0xseif-code/vexor",
		APIBase:        base,
		AssetBase:      base,
		Client:         http.DefaultClient,
	}
}

func TestCheckLatestRelease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/releases/latest") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"tag_name":"v1.1.0","name":"v1.1.0"}`))
	}))
	defer srv.Close()

	got, err := CheckLatest(context.Background(), checkClient(srv.URL))
	if err != nil {
		t.Fatalf("CheckLatest: %v", err)
	}
	if got != "v1.1.0" {
		t.Fatalf("CheckLatest = %q, want v1.1.0", got)
	}
}

func TestCheckLatestFallsBackToTags(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/releases/latest"):
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message":"Not Found"}`))
		case strings.Contains(r.URL.Path, "/tags"):
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[{"name":"v0.9.9"},{"name":"v0.9.8"}]`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	got, err := CheckLatest(context.Background(), checkClient(srv.URL))
	if err != nil {
		t.Fatalf("CheckLatest tags fallback: %v", err)
	}
	if got != "v0.9.9" {
		t.Fatalf("CheckLatest = %q, want v0.9.9", got)
	}
}

func TestRunUpToDateNoError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"tag_name":"v1.0.0"}`))
	}))
	defer srv.Close()

	opts := checkClient(srv.URL)
	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run (up to date): %v", err)
	}
	if res.Updated {
		t.Fatal("Run (up to date) reported an update")
	}
	if res.FromVersion != "1.0.0" || res.ToVersion != "1.0.0" {
		t.Fatalf("Run versions = %s -> %s", res.FromVersion, res.ToVersion)
	}
}