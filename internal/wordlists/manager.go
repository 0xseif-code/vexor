package wordlists

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/0xseif-code/vexor/internal/httpclient"
)

var (
	ErrSourceNotFound    = errors.New("wordlist source not found in registry")
	ErrCustomPathInvalid = errors.New("custom wordlist path invalid or unreadable")
	ErrChecksumMismatch  = errors.New("downloaded file checksum mismatch")
	ErrCacheCorrupted    = errors.New("wordlist cache metadata corrupted")
)

type ProgressFunc func(bytesDownloaded, totalBytes int64)

type Metadata struct {
	Files map[string]FileInfo `json:"files"`
}

type FileInfo struct {
	Category     string    `json:"category"`
	Size         string    `json:"size"`
	Path         string    `json:"path"`
	Bytes        int64     `json:"bytes"`
	SHA256       string    `json:"sha256"`
	DownloadedAt time.Time `json:"downloaded_at"`
	SourceURL    string    `json:"source_url"`
}

const (
	metaFileName    = ".meta.json"
	downloadTimeout = 2 * time.Minute
	unknownTotal    = int64(-1)
)

type Manager struct {
	cacheDir           string
	meta               *Metadata
	mu                 sync.RWMutex
	progress           ProgressFunc
	client             *httpclient.Client
	maxDownloadRetries int
}

func NewManager() (*Manager, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home directory: %w", err)
	}
	return newManager(filepath.Join(home, ".vexor", "wordlists"))
}

func newManager(cacheDir string) (*Manager, error) {
	opts := httpclient.DefaultOptions()
	opts.Timeout = downloadTimeout

	m := &Manager{
		cacheDir:           cacheDir,
		meta:               &Metadata{Files: make(map[string]FileInfo)},
		client:             httpclient.NewClient(opts),
		maxDownloadRetries: 3,
	}

	for _, cat := range []Category{CategoryDirectory, CategorySubdomain, CategoryFuzz} {
		dir := filepath.Join(cacheDir, string(cat))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create wordlist cache directory %s: %w", dir, err)
		}
	}

	if err := m.loadMeta(); err != nil {
		return nil, err
	}
	if err := m.saveMeta(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) CacheDir() string {
	return m.cacheDir
}

func (m *Manager) SetProgressCallback(fn ProgressFunc) {
	m.mu.Lock()
	m.progress = fn
	m.mu.Unlock()
}

func (m *Manager) IsCached(cat Category, size Size) bool {
	key := m.metaKey(cat, size)

	m.mu.RLock()
	fi, ok := m.meta.Files[key]
	m.mu.RUnlock()
	if !ok {
		return false
	}

	if st, err := os.Stat(fi.Path); err != nil || st.IsDir() {
		return false
	}

	sum, err := sha256File(fi.Path)
	if err != nil {
		return false
	}
	return sum == fi.SHA256
}

func (m *Manager) Ensure(ctx context.Context, cat Category, size Size) (string, error) {
	if m.IsCached(cat, size) {
		return m.cachedPath(cat, size), nil
	}

	src, err := GetSource(cat, size)
	if err != nil {
		return "", err
	}

	dest := filepath.Join(m.cacheDir, string(cat), fileNameForSize(size))
	if err := m.downloadWithRetry(ctx, *src, dest); err != nil {
		return "", err
	}
	return dest, nil
}

func (m *Manager) EnsureAll(ctx context.Context) error {
	for _, src := range AllSources() {
		if m.IsCached(src.Category, src.Size) {
			continue
		}
		dest := filepath.Join(m.cacheDir, string(src.Category), fileNameForSize(src.Size))
		if err := m.downloadWithRetry(ctx, src, dest); err != nil {
			return fmt.Errorf("ensure %s/%s: %w", src.Category, src.Size, err)
		}
	}
	return nil
}

func (m *Manager) Update(ctx context.Context) error {
	for _, src := range AllSources() {
		dest := filepath.Join(m.cacheDir, string(src.Category), fileNameForSize(src.Size))
		if err := m.downloadWithRetry(ctx, src, dest); err != nil {
			return fmt.Errorf("update %s/%s: %w", src.Category, src.Size, err)
		}
	}
	return nil
}

func (m *Manager) Remove(cat Category, size Size) error {
	key := m.metaKey(cat, size)

	m.mu.Lock()
	fi, ok := m.meta.Files[key]
	if ok {
		delete(m.meta.Files, key)
	}
	m.mu.Unlock()

	if ok {
		if err := os.Remove(fi.Path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove wordlist file %s: %w", fi.Path, err)
		}
	}
	return m.saveMeta()
}

func (m *Manager) Stats() ([]FileInfo, error) {
	m.mu.RLock()
	out := make([]FileInfo, 0, len(m.meta.Files))
	for _, fi := range m.meta.Files {
		out = append(out, fi)
	}
	m.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Size < out[j].Size
	})
	return out, nil
}

func (m *Manager) downloadWithRetry(ctx context.Context, src Source, dest string) error {
	backoff := 500 * time.Millisecond
	var err error
	for attempt := 0; attempt < m.maxDownloadRetries; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(backoff)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return err
			}
			backoff *= 2
			if backoff > 5*time.Second {
				backoff = 5 * time.Second
			}
		}

		err = m.download(ctx, src, dest)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return err
		}
	}
	return err
}

// download fetches a source and places it at destPath. Sources served as a
// .tar.gz archive are downloaded and extracted so that only the inner .txt is
// cached. All writes are atomic: a temp file is written, synced, then renamed
// into place.
func (m *Manager) download(ctx context.Context, src Source, destPath string) error {
	if isTarGzURL(src.URL) {
		return m.downloadArchive(ctx, src, destPath)
	}
	return m.downloadDirect(ctx, src, destPath)
}

// downloadDirect fetches a plain .txt source directly into the cache.
func (m *Manager) downloadDirect(ctx context.Context, src Source, destPath string) error {
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".vexor-download-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp download file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	hasher := sha256.New()
	prog := &progressTracker{total: unknownTotal}
	m.mu.RLock()
	prog.fn = m.progress
	m.mu.RUnlock()

	dest := io.MultiWriter(tmp, hasher, prog)

	resp, err := m.client.Stream(ctx, "GET", src.URL, nil, nil, dest)
	if err != nil {
		_ = tmp.Close()
		return fmt.Errorf("download %s: %w", src.Name, err)
	}
	if resp.StatusCode != 200 {
		_ = tmp.Close()
		return fmt.Errorf("download %s: server returned status %d", src.Name, resp.StatusCode)
	}

	if resp.ContentLength > 0 {
		prog.setTotal(resp.ContentLength)
	} else {
		prog.setTotal(prog.n)
	}

	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync downloaded file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close downloaded file: %w", err)
	}

	sum := hex.EncodeToString(hasher.Sum(nil))

	if err := replaceFile(tmpName, destPath); err != nil {
		return fmt.Errorf("finalize download %s: %w", destPath, err)
	}

	return m.recordDownload(src, destPath, prog.n, sum)
}

// downloadArchive fetches a .tar.gz source, extracts the inner .txt into the
// cache, and removes the temporary archive. It streams the archive (never
// loading it fully into memory) and writes the extracted text atomically.
func (m *Manager) downloadArchive(ctx context.Context, src Source, destPath string) error {
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}

	// 1. Download the .tar.gz to a temporary file.
	arcTmp, err := os.CreateTemp(dir, ".vexor-archive-*.tgz")
	if err != nil {
		return fmt.Errorf("create temp archive file: %w", err)
	}
	arcName := arcTmp.Name()
	defer func() { _ = os.Remove(arcName) }()

	prog := &progressTracker{total: unknownTotal}
	m.mu.RLock()
	prog.fn = m.progress
	m.mu.RUnlock()

	resp, err := m.client.Stream(ctx, "GET", src.URL, nil, nil, arcTmp)
	if err != nil {
		_ = arcTmp.Close()
		return fmt.Errorf("download archive %s: %w", src.Name, err)
	}
	if resp.StatusCode != 200 {
		_ = arcTmp.Close()
		return fmt.Errorf("download archive %s: server returned status %d", src.Name, resp.StatusCode)
	}
	if resp.ContentLength > 0 {
		prog.setTotal(resp.ContentLength)
	} else {
		prog.setTotal(prog.n)
	}
	if err := arcTmp.Sync(); err != nil {
		_ = arcTmp.Close()
		return fmt.Errorf("sync archive file: %w", err)
	}
	if err := arcTmp.Close(); err != nil {
		return fmt.Errorf("close archive file: %w", err)
	}

	// 2. Extract the inner .txt to a temporary file (memory-safe streaming).
	extractedName, bytesWritten, sum, err := m.extractTarGzTxt(arcName, dir, src.Name)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(extractedName) }()

	// 3. Atomically move the extracted text into the cache.
	if err := replaceFile(extractedName, destPath); err != nil {
		return fmt.Errorf("finalize extracted file %s: %w", destPath, err)
	}

	// 4. Verify checksum and save metadata. The temp archive is removed by
	//    the deferred cleanup above.
	return m.recordDownload(src, destPath, bytesWritten, sum)
}

// extractTarGzTxt streams a gzip-compressed tar archive and writes the
// preferred .txt member (rockyou.txt if present, else the first .txt member)
// to a temp file in dir. It returns the temp file's path, the number of bytes
// extracted, and the SHA-256 of the extracted content.
func (m *Manager) extractTarGzTxt(arcPath, dir, name string) (string, int64, string, error) {
	member, err := chooseTxtMember(arcPath, name)
	if err != nil {
		return "", 0, "", err
	}

	selected, err := m.extractMember(arcPath, member, dir, name)
	if err != nil {
		return "", 0, "", err
	}
	return selected.fileName, selected.bytes, selected.sha256, nil
}

// chooseTxtMember opens the archive and returns the basename of the .txt
// member to extract, preferring one named exactly rockyou.txt and otherwise
// the first regular .txt file encountered.
func chooseTxtMember(arcPath, name string) (string, error) {
	f, err := os.Open(arcPath)
	if err != nil {
		return "", fmt.Errorf("open archive %s: %w", arcPath, err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("gzip reader %s: %w", name, err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var firstTxt string

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read tar archive %s: %w", name, err)
		}
		if hdr.Typeflag != tar.TypeReg || !strings.HasSuffix(hdr.Name, ".txt") {
			continue
		}
		if filepath.Base(hdr.Name) == "rockyou.txt" {
			return hdr.Name, nil
		}
		if firstTxt == "" {
			firstTxt = hdr.Name
		}
	}

	if firstTxt == "" {
		return "", fmt.Errorf("no .txt file found in archive %s", name)
	}
	return firstTxt, nil
}

// extractedFile holds the result of extracting a single archive member.
type extractedFile struct {
	fileName string
	bytes    int64
	sha256   string
}

// extractMember re-opens the archive and copies the named member to a temp
// file in dir, hashing while it streams.
func (m *Manager) extractMember(arcPath, memberName, dir, name string) (*extractedFile, error) {
	f, err := os.Open(arcPath)
	if err != nil {
		return nil, fmt.Errorf("open archive %s: %w", arcPath, err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("gzip reader %s: %w", name, err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var target *tar.Reader

scan:
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar archive %s: %w", name, err)
		}
		if hdr.Typeflag == tar.TypeReg && hdr.Name == memberName {
			target = tr
			break scan
		}
	}
	if target == nil {
		return nil, fmt.Errorf("member %s not found in archive %s", memberName, name)
	}

	out, err := os.CreateTemp(dir, ".vexor-extract-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("create extract temp file: %w", err)
	}
	outName := out.Name()

	hasher := sha256.New()
	prog := &progressTracker{total: unknownTotal}
	m.mu.RLock()
	prog.fn = m.progress
	m.mu.RUnlock()

	// Stream the member into the temp file while hashing and accounting
	// progress. This never loads the archive or its members into memory.
	n, copyErr := io.Copy(io.MultiWriter(out, hasher, prog), target)
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(outName)
		return nil, fmt.Errorf("extract member %s: %w", memberName, copyErr)
	}
	if syncErr != nil {
		_ = os.Remove(outName)
		return nil, fmt.Errorf("sync extracted member %s: %w", memberName, syncErr)
	}
	if closeErr != nil {
		_ = os.Remove(outName)
		return nil, fmt.Errorf("close extracted member %s: %w", memberName, closeErr)
	}

	prog.setTotal(n)
	return &extractedFile{
		fileName: outName,
		bytes:    n,
		sha256:   hex.EncodeToString(hasher.Sum(nil)),
	}, nil
}

// recordDownload verifies the checksum of an extracted/downloaded file at
// destPath and persists it to the metadata store.
func (m *Manager) recordDownload(src Source, destPath string, bytesWritten int64, sum string) error {
	if verified, err := sha256File(destPath); err != nil {
		return fmt.Errorf("verify downloaded file %s: %w", destPath, err)
	} else if verified != sum {
		_ = os.Remove(destPath)
		return fmt.Errorf("%w: %s", ErrChecksumMismatch, src.Name)
	}

	info := FileInfo{
		Category:     string(src.Category),
		Size:         string(src.Size),
		Path:         destPath,
		Bytes:        bytesWritten,
		SHA256:       sum,
		DownloadedAt: time.Now().UTC(),
		SourceURL:    src.URL,
	}

	m.mu.Lock()
	m.meta.Files[m.metaKey(src.Category, src.Size)] = info
	m.mu.Unlock()

	return m.saveMeta()
}

// isTarGzURL reports whether a source URL points to a .tar.gz archive.
func isTarGzURL(u string) bool {
	return strings.HasSuffix(strings.ToLower(u), ".tar.gz")
}

func (m *Manager) loadMeta() error {
	path := m.metaPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			m.mu.Lock()
			m.meta = &Metadata{Files: make(map[string]FileInfo)}
			m.mu.Unlock()
			return nil
		}
		return fmt.Errorf("read cache metadata %s: %w", path, err)
	}

	var meta Metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrCacheCorrupted, path, err)
	}
	if meta.Files == nil {
		meta.Files = make(map[string]FileInfo)
	}

	m.mu.Lock()
	m.meta = &meta
	m.mu.Unlock()
	return nil
}

func (m *Manager) saveMeta() error {
	m.mu.RLock()
	data, err := json.MarshalIndent(m.meta, "", "  ")
	m.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("marshal cache metadata: %w", err)
	}

	path := m.metaPath()
	if err := atomicWrite(path, data, 0o644); err != nil {
		return fmt.Errorf("write cache metadata %s: %w", path, err)
	}
	return nil
}

func (m *Manager) metaKey(cat Category, size Size) string {
	return string(cat) + ":" + string(size)
}

func (m *Manager) metaPath() string {
	return filepath.Join(m.cacheDir, metaFileName)
}

func (m *Manager) cachedPath(cat Category, size Size) string {
	return filepath.Join(m.cacheDir, string(cat), fileNameForSize(size))
}

func fileNameForSize(size Size) string {
	return string(size) + ".txt"
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".vexor-meta-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return replaceFile(tmpName, path)
}

func replaceFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(src, dst)
}

type progressTracker struct {
	fn    ProgressFunc
	n     int64
	total int64
}

func (p *progressTracker) Write(b []byte) (int, error) {
	p.n += int64(len(b))
	if p.fn != nil {
		p.fn(p.n, p.total)
	}
	return len(b), nil
}

func (p *progressTracker) setTotal(total int64) {
	p.total = total
	if p.fn != nil {
		p.fn(p.n, p.total)
	}
}
