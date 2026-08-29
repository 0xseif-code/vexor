package wordlists

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/valyala/fasthttp"
)

func startTestServer(t *testing.T, handler fasthttp.RequestHandler) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	server := &fasthttp.Server{Handler: handler, DisableKeepalive: true}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.ShutdownWithContext(ctx)
	})

	return "http://" + ln.Addr().String()
}

func writeTestWordlist(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "words.txt")
	content := "# comment header\n\nadmin\nlogin\nadmin\n\napi\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	return path
}

func TestNewManager(t *testing.T) {
	dir := t.TempDir()
	m, err := newManager(dir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	for _, cat := range []Category{CategoryDirectory, CategorySubdomain, CategoryFuzz} {
		if st, err := os.Stat(filepath.Join(dir, string(cat))); err != nil || !st.IsDir() {
			t.Fatalf("expected cache dir for %s, got stat err=%v", cat, err)
		}
	}
	if _, err := os.Stat(m.metaPath()); err != nil {
		t.Fatalf("expected meta file: %v", err)
	}
	if m.CacheDir() != dir {
		t.Fatalf("CacheDir = %q, want %q", m.CacheDir(), dir)
	}
}

func TestGetSource(t *testing.T) {
	src, err := GetSource(CategoryDirectory, SizeMedium)
	if err != nil {
		t.Fatalf("GetSource: %v", err)
	}
	if src.Category != CategoryDirectory || src.Size != SizeMedium {
		t.Fatalf("unexpected source %+v", src)
	}

	if _, err := GetSource(Category("bogus"), SizeSmall); !errors.Is(err, ErrSourceNotFound) {
		t.Fatalf("expected ErrSourceNotFound, got %v", err)
	}
}

func TestListByCategoryAndAll(t *testing.T) {
	if got := len(ListByCategory(CategoryDirectory)); got != 3 {
		t.Fatalf("directory sources = %d, want 3", got)
	}
	if got := len(AllSources()); got != 12 {
		t.Fatalf("all sources = %d, want 12", got)
	}
}

func TestDownloadAndEnsure(t *testing.T) {
	base := startTestServer(t, func(ctx *fasthttp.RequestCtx) {
		ctx.SetContentType("text/plain")
		_, _ = ctx.WriteString("GET /test\nadmin\nlogin\n")
	})

	dir := t.TempDir()
	m, err := newManager(dir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	src := Source{Category: CategoryDirectory, Size: SizeSmall, Name: "test", URL: base}
	dest := m.cachedPath(src.Category, src.Size)
	ctx := context.Background()

	if m.IsCached(src.Category, src.Size) {
		t.Fatal("file should not be cached before download")
	}

	if err := m.download(ctx, src, dest); err != nil {
		t.Fatalf("download: %v", err)
	}

	if !m.IsCached(src.Category, src.Size) {
		t.Fatal("file should be cached after download")
	}

	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if !strings.Contains(string(data), "admin") {
		t.Fatalf("unexpected file content: %q", data)
	}

	path, err := m.Ensure(ctx, src.Category, src.Size)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if path != dest {
		t.Fatalf("Ensure path = %q, want %q", path, dest)
	}

	stats, err := m.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if len(stats) != 1 {
		t.Fatalf("stats = %d entries, want 1", len(stats))
	}
	if stats[0].Size != string(src.Size) || stats[0].Category != string(src.Category) {
		t.Fatalf("unexpected stat entry %+v", stats[0])
	}
	if stats[0].Bytes <= 0 || stats[0].SHA256 == "" {
		t.Fatalf("bad FileInfo %+v", stats[0])
	}
}

func writeTestTarGz(t *testing.T, memberName, content string) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)

	hdr := &tar.Header{
		Name: memberName,
		Mode: 0o644,
		Size: int64(len(content)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatalf("write tar content: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return buf.Bytes()
}

func TestDownloadTarGzExtraction(t *testing.T) {
	content := "password1\npassword2\nrockyou_test\n"
	archive := writeTestTarGz(t, "rockyou.txt", content)

	base := startTestServer(t, func(ctx *fasthttp.RequestCtx) {
		ctx.SetContentType("application/gzip")
		_, _ = ctx.Write(archive)
	})

	dir := t.TempDir()
	m, err := newManager(dir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	src := Source{Category: CategoryFuzz, Size: SizePasswordsLarge, Name: "rockyou", URL: base + "/rockyou.txt.tar.gz"}
	if !isTarGzURL(src.URL) {
		t.Fatal("expected isTarGzURL to be true for .tar.gz URL")
	}

	dest := filepath.Join(dir, string(src.Category), "rockyou.txt")
	if err := m.download(context.Background(), src, dest); err != nil {
		t.Fatalf("download archive: %v", err)
	}

	// The .txt must be cached, not the .tar.gz.
	if !m.IsCached(src.Category, src.Size) {
		t.Fatal("file should be cached after archive extraction")
	}
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(data) != content {
		t.Fatalf("extracted content = %q, want %q", data, content)
	}

	if _, err := os.Stat(dest + ".tar.gz"); !os.IsNotExist(err) {
		t.Fatalf("archive file must be removed, stat err=%v", err)
	}

	info, ok := m.meta.Files[m.metaKey(src.Category, src.Size)]
	if !ok {
		t.Fatal("meta entry missing after extraction")
	}
	if info.Bytes != int64(len(content)) {
		t.Fatalf("meta bytes = %d, want %d", info.Bytes, len(content))
	}
	if info.SHA256 == "" {
		t.Fatal("meta sha256 missing after extraction")
	}
}

func TestDownloadTarGzPrefersRockyou(t *testing.T) {
	// Build an archive containing both a generic .txt and rockyou.txt.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, m := range []struct{ name, content string }{
		{"other.txt", "other\n"},
		{"rockyou.txt", "rockyou_line\n"},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: m.name, Mode: 0o644, Size: int64(len(m.content))}); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := tw.Write([]byte(m.content)); err != nil {
			t.Fatalf("write content: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}

	base := startTestServer(t, func(ctx *fasthttp.RequestCtx) {
		_, _ = ctx.Write(buf.Bytes())
	})

	dir := t.TempDir()
	m, err := newManager(dir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	src := Source{Category: CategoryFuzz, Size: SizePasswordsLarge, Name: "rockyou", URL: base + "/rockyou.txt.tar.gz"}
	dest := filepath.Join(dir, string(src.Category), "rockyou.txt")
	if err := m.download(context.Background(), src, dest); err != nil {
		t.Fatalf("download archive: %v", err)
	}

	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(data) != "rockyou_line\n" {
		t.Fatalf("expected rockyou.txt content, got %q", data)
	}
}

func TestDownloadTarGzNoTxt(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(&tar.Header{Name: "readme.md", Mode: 0o644, Size: 4}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := tw.Write([]byte("data")); err != nil {
		t.Fatalf("write content: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}

	base := startTestServer(t, func(ctx *fasthttp.RequestCtx) {
		_, _ = ctx.Write(buf.Bytes())
	})

	dir := t.TempDir()
	m, err := newManager(dir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	src := Source{Category: CategoryFuzz, Size: SizePasswordsLarge, Name: "rockyou", URL: base + "/rockyou.txt.tar.gz"}
	dest := filepath.Join(dir, string(src.Category), "rockyou.txt")
	if err := m.download(context.Background(), src, dest); err == nil {
		t.Fatal("expected error when archive has no .txt member")
	}
}

func TestEnsureRedownloadsOnCorruption(t *testing.T) {
	base := startTestServer(t, func(ctx *fasthttp.RequestCtx) {
		_, _ = ctx.WriteString("ok\n")
	})

	dir := t.TempDir()
	m, err := newManager(dir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	src := Source{Category: CategorySubdomain, Size: SizeSmall, Name: "test", URL: base}
	if err := m.download(context.Background(), src, m.cachedPath(src.Category, src.Size)); err != nil {
		t.Fatalf("download: %v", err)
	}

	corrupt := m.cachedPath(src.Category, src.Size)
	if err := os.WriteFile(corrupt, []byte("tampered\n"), 0o644); err != nil {
		t.Fatalf("corrupt file: %v", err)
	}
	if m.IsCached(src.Category, src.Size) {
		t.Fatal("corrupted file must not be cached")
	}

	if _, err := m.Ensure(context.Background(), src.Category, src.Size); err != nil {
		t.Fatalf("Ensure after corruption: %v", err)
	}
	if !m.IsCached(src.Category, src.Size) {
		t.Fatal("file should be cached after re-download")
	}
}

func TestDownloadHTTPError(t *testing.T) {
	base := startTestServer(t, func(ctx *fasthttp.RequestCtx) {
		ctx.Error("Not Found", fasthttp.StatusNotFound)
	})

	dir := t.TempDir()
	m, err := newManager(dir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	src := Source{Category: CategoryDirectory, Size: SizeMedium, Name: "test", URL: base}
	if err := m.download(context.Background(), src, m.cachedPath(src.Category, src.Size)); err == nil {
		t.Fatal("expected download error for 404")
	}
	if m.IsCached(src.Category, src.Size) {
		t.Fatal("failed download must not be cached")
	}
	if _, err := os.Stat(m.cachedPath(src.Category, src.Size)); !os.IsNotExist(err) {
		t.Fatalf("dest file must not exist, stat err=%v", err)
	}
	if len(m.meta.Files) != 0 {
		t.Fatalf("meta must be empty, got %d entries", len(m.meta.Files))
	}
}

func TestRemove(t *testing.T) {
	base := startTestServer(t, func(ctx *fasthttp.RequestCtx) {
		_, _ = ctx.WriteString("admin\n")
	})

	dir := t.TempDir()
	m, err := newManager(dir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	src := Source{Category: CategoryFuzz, Size: SizeParameters, Name: "test", URL: base}
	if err := m.download(context.Background(), src, m.cachedPath(src.Category, src.Size)); err != nil {
		t.Fatalf("download: %v", err)
	}

	if err := m.Remove(src.Category, src.Size); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if m.IsCached(src.Category, src.Size) {
		t.Fatal("file should not be cached after Remove")
	}
	if _, err := os.Stat(m.cachedPath(src.Category, src.Size)); !os.IsNotExist(err) {
		t.Fatalf("file must be gone after Remove")
	}
}

func TestEnsureAllAndUpdate(t *testing.T) {
	base := startTestServer(t, func(ctx *fasthttp.RequestCtx) {
		_, _ = ctx.WriteString("word\n")
	})

	original := Registry
	Registry = []Source{
		{Category: CategoryDirectory, Size: SizeSmall, Name: "a", URL: base},
		{Category: CategorySubdomain, Size: SizeSmall, Name: "b", URL: base},
	}
	t.Cleanup(func() { Registry = original })

	dir := t.TempDir()
	m, err := newManager(dir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	if err := m.EnsureAll(context.Background()); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}
	stats, err := m.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if len(stats) != 2 {
		t.Fatalf("stats = %d entries, want 2", len(stats))
	}

	if err := m.EnsureAll(context.Background()); err != nil {
		t.Fatalf("EnsureAll second run: %v", err)
	}

	if err := m.Update(context.Background()); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if _, err := m.Ensure(context.Background(), Category("bogus"), SizeSmall); !errors.Is(err, ErrSourceNotFound) {
		t.Fatalf("expected ErrSourceNotFound for bogus category, got %v", err)
	}
}

func TestSelectorCustomPathValid(t *testing.T) {
	path := writeTestWordlist(t)
	m, err := newManager(filepath.Join(t.TempDir(), "cache"))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	s := NewSelector(m)

	resolved, err := s.Resolve(context.Background(), Options{CustomPath: path})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved != path {
		t.Fatalf("Resolve = %q, want %q", resolved, path)
	}

	words, err := s.Load(context.Background(), Options{CustomPath: path})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"admin", "login", "api"}
	if len(words) != len(want) {
		t.Fatalf("Load = %v, want %v", words, want)
	}
	for i := range want {
		if words[i] != want[i] {
			t.Fatalf("Load = %v, want %v", words, want)
		}
	}
}

func TestSelectorCustomPathInvalid(t *testing.T) {
	dir := t.TempDir()
	m, err := newManager(filepath.Join(t.TempDir(), "cache"))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	s := NewSelector(m)

	if _, err := s.Load(context.Background(), Options{CustomPath: filepath.Join(dir, "missing.txt")}); !errors.Is(err, ErrCustomPathInvalid) {
		t.Fatalf("expected ErrCustomPathInvalid, got %v", err)
	}

	if _, err := s.Load(context.Background(), Options{CustomPath: dir}); !errors.Is(err, ErrCustomPathInvalid) {
		t.Fatalf("expected ErrCustomPathInvalid for directory, got %v", err)
	}
}

func TestSelectorRegistryPath(t *testing.T) {
	base := startTestServer(t, func(ctx *fasthttp.RequestCtx) {
		_, _ = ctx.WriteString("admin\nlogin\nadmin\n")
	})

	original := Registry
	Registry = []Source{
		{Category: CategoryDirectory, Size: SizeSmall, Name: "test", URL: base},
	}
	t.Cleanup(func() { Registry = original })

	dir := t.TempDir()
	m, err := newManager(dir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	s := NewSelector(m)
	words, err := s.Load(context.Background(), Options{Category: CategoryDirectory, Size: SizeSmall})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"admin", "login"}
	if len(words) != len(want) || words[0] != want[0] || words[1] != want[1] {
		t.Fatalf("Load = %v, want %v", words, want)
	}
}

func TestSelectorDefaultsToMedium(t *testing.T) {
	base := startTestServer(t, func(ctx *fasthttp.RequestCtx) {
		_, _ = ctx.WriteString("admin\nlogin\n")
	})

	original := Registry
	Registry = []Source{
		{Category: CategoryDirectory, Size: SizeMedium, Name: "test", URL: base},
	}
	t.Cleanup(func() { Registry = original })

	dir := t.TempDir()
	m, err := newManager(dir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	s := NewSelector(m)
	words, err := s.Load(context.Background(), Options{Category: CategoryDirectory})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(words) != 2 {
		t.Fatalf("Load = %v, want 2 words", words)
	}
}

func TestSelectorLoadStream(t *testing.T) {
	path := writeTestWordlist(t)
	m, err := newManager(filepath.Join(t.TempDir(), "cache"))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	s := NewSelector(m)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	words, errs, err := s.LoadStream(ctx, Options{CustomPath: path})
	if err != nil {
		t.Fatalf("LoadStream: %v", err)
	}
	var got []string
	for w := range words {
		got = append(got, w)
	}
	if err := <-errs; err != nil {
		t.Fatalf("LoadStream error: %v", err)
	}

	want := []string{"admin", "login", "admin", "api"}
	if len(got) != len(want) {
		t.Fatalf("stream = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("stream = %v, want %v", got, want)
		}
	}
}

func TestSelectorLoadStreamCancel(t *testing.T) {
	path := writeTestWordlist(t)
	m, err := newManager(filepath.Join(t.TempDir(), "cache"))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	s := NewSelector(m)

	ctx, cancel := context.WithCancel(context.Background())
	words, errs, err := s.LoadStream(ctx, Options{CustomPath: path})
	if err != nil {
		t.Fatalf("LoadStream: %v", err)
	}
	<-words
	cancel()

	select {
	case <-errs:
	case <-time.After(3 * time.Second):
		t.Fatal("LoadStream did not stop after cancel")
	}
}
