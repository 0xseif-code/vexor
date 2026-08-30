// Package update implements self-update for the vexor binary. It checks the
// latest GitHub release for the repo and, when an update is available (or
// forced), replaces the running executable. Only the standard library is used
// so the module stays lightweight and buildable offline.
//
// Update strategies, tried in order until one succeeds:
//
//  1. go install github.com/0xseif-code/vexor/cmd/vexor@<tag>
//  2. GitHub release asset download for the current GOOS/GOARCH
//  3. git pull + go build inside a source clone (when located)
package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DefaultRepo is the upstream distribution source.
const DefaultRepo = "0xseif-code/vexor"

// DefaultAPIBase is the GitHub API root.
const DefaultAPIBase = "https://api.github.com"

// DefaultAssetBase is the GitHub download root for release assets.
const DefaultAssetBase = "https://github.com"

// Options tunes a check or update run.
type Options struct {
	// CurrentVersion is the local release version (as shown by `version`).
	CurrentVersion string
	// Repo overrides the GitHub owner/repo. Empty uses DefaultRepo.
	Repo string
	// APIBase overrides the GitHub API root (tests inject a fake server).
	APIBase string
	// AssetBase overrides the release download root (tests inject a fake server).
	AssetBase string
	// Client overrides the HTTP client used.
	Client *http.Client
	// Force reinstalls even when the latest version matches the local one.
	Force bool
	// Stdout receives progress lines; empty discards them.
	Stdout io.Writer
}

// Result describes the outcome of an update run.
type Result struct {
	Updated     bool
	FromVersion string
	ToVersion   string
	Method      string
	BinaryPath  string
}

// repo returns the effective owner/repo.
func (o *Options) repo() string {
	if strings.TrimSpace(o.Repo) == "" {
		return DefaultRepo
	}
	return strings.TrimSpace(o.Repo)
}

// apiBase returns the effective API root.
func (o *Options) apiBase() string {
	if o.APIBase != "" {
		return strings.TrimRight(o.APIBase, "/")
	}
	return DefaultAPIBase
}

// assetBase returns the effective download root.
func (o *Options) assetBase() string {
	if o.AssetBase != "" {
		return strings.TrimRight(o.AssetBase, "/")
	}
	return DefaultAssetBase
}

// client returns the effective HTTP client.
func (o *Options) client() *http.Client {
	if o.Client != nil {
		return o.Client
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// printf writes a progress line to the configured stream.
func (o *Options) printf(format string, args ...any) {
	if o.Stdout != nil {
		fmt.Fprintf(o.Stdout, format+"\n", args...)
	}
}

// Normalize strips the "v" prefix and build metadata from a version string so
// "v1.0.1", "1.0.1" and "1.0.1+meta" compare equal.
func Normalize(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimLeft(v, "vV")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	return v
}

// SameVersion reports whether two version strings are semantically equal.
func SameVersion(a, b string) bool {
	return Normalize(a) == Normalize(b)
}

// Compare orders two version strings: -1 when a < b, 0 when a == b, +1 when
// a > b. Pre-release suffixes (-beta...) sort below the plain release.
func Compare(a, b string) int {
	na, nb := Normalize(a), Normalize(b)
	if na == nb {
		return 0
	}
	pa, pb := numericParts(na), numericParts(nb)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var xa, xb int64
		if i < len(pa) {
			xa = pa[i]
		}
		if i < len(pb) {
			xb = pb[i]
		}
		if xa < xb {
			return -1
		}
		if xa > xb {
			return 1
		}
	}
	// Equal numeric core: a pre-release sorts below its release.
	if strings.Contains(na, "-") != strings.Contains(nb, "-") {
		if strings.Contains(na, "-") {
			return -1
		}
		return 1
	}
	return 0
}

// numericParts extracts the dotted numeric segments of a version core.
func numericParts(v string) []int64 {
	core := strings.SplitN(v, "-", 2)[0]
	var parts []int64
	for _, p := range strings.Split(core, ".") {
		var n int64
		for _, r := range p {
			if r < '0' || r > '9' {
				break
			}
			n = n*10 + int64(r-'0')
		}
		parts = append(parts, n)
	}
	return parts
}

// CheckLatest returns the newest release tag for the repository. It queries
// the releases/latest endpoint and, when that fails (rate limit, no releases),
// falls back to the tags endpoint.
func CheckLatest(ctx context.Context, o Options) (string, error) {
	url := o.apiBase() + "/repos/" + o.repo() + "/releases/latest"
	body, err := o.get(ctx, url)
	if err != nil {
		tagsURL := o.apiBase() + "/repos/" + o.repo() + "/tags"
		body, err = o.get(ctx, tagsURL)
		if err != nil {
			return "", fmt.Errorf("check latest release: %w", err)
		}
		var tags []struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(body, &tags); err != nil {
			return "", fmt.Errorf("parse tags response: %w", err)
		}
		if len(tags) == 0 || tags[0].Name == "" {
			return "", errors.New("repository has no reachable tags")
		}
		return tags[0].Name, nil
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &rel); err != nil {
		return "", fmt.Errorf("parse release response: %w", err)
	}
	if rel.TagName == "" {
		return "", errors.New("latest release has no tag name")
	}
	return rel.TagName, nil
}

// get performs a GitHub API-style GET and returns the (bounded) body.
func (o *Options) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "vexor-update")
	resp, err := o.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// Run updates the binary. When the latest version already matches the local
// one and Force is false it returns a Result with Updated=false and no error.
// Otherwise the three strategies are tried in order.
func Run(ctx context.Context, o Options) (*Result, error) {
	tag, err := CheckLatest(ctx, o)
	if err != nil {
		return nil, err
	}
	cur := Normalize(o.CurrentVersion)
	tgt := Normalize(tag)
	res := &Result{FromVersion: cur, ToVersion: tgt}
	if !o.Force && SameVersion(cur, tgt) {
		return res, nil
	}

	if bin, terr := goInstall(ctx, o, tag); terr == nil {
		res.Updated, res.Method, res.BinaryPath = true, "go install", bin
		return res, nil
	}

	if bin, terr := releaseDownload(ctx, o, tag); terr == nil {
		res.Updated, res.Method, res.BinaryPath = true, "release asset", bin
		return res, nil
	}

	if bin, gerr := gitRebuild(ctx, o, tag); gerr == nil {
		res.Updated, res.Method, res.BinaryPath = true, "git rebuild", bin
		return res, nil
	}

	return nil, errors.New("update failed: no strategy produced a binary (checked go install, release asset, and source rebuild)")
}

// goInstall rebuilds the CLI from source with the Go toolchain, installing
// into $GOBIN or $(go env GOPATH)/bin.
func goInstall(ctx context.Context, o Options, tag string) (string, error) {
	binDir, err := gopathBin()
	if err != nil {
		return "", err
	}
	version := tag
	if version == "" {
		version = "latest"
	}
	pkg := "github.com/" + o.repo() + "/cmd/vexor@" + version
	o.printf("[update] tier 1: go install %s", pkg)
	out, err := runCmd(ctx, "", "go", "install", pkg)
	if err != nil {
		return "", fmt.Errorf("go install: %w (%s)", err, strings.TrimSpace(out))
	}
	bin := filepath.Join(binDir, "vexor"+exeSuffix())
	if _, err := os.Stat(bin); err != nil {
		// go install may land the binary elsewhere when GOBIN is set.
		if gobin := strings.TrimSpace(os.Getenv("GOBIN")); gobin != "" {
			bin = filepath.Join(gobin, "vexor"+exeSuffix())
		}
		if _, err := os.Stat(bin); err != nil {
			return "", fmt.Errorf("go install succeeded but %s is missing", bin)
		}
	}
	return bin, nil
}

// gopathBin resolves the directory `go install` drops binaries into.
func gopathBin() (string, error) {
	if gobin := strings.TrimSpace(os.Getenv("GOBIN")); gobin != "" {
		return gobin, nil
	}
	out, err := runCmd(context.Background(), "", "go", "env", "GOPATH")
	if err != nil {
		return "", fmt.Errorf("go env GOPATH: %w", err)
	}
	first := strings.TrimSpace(strings.Split(out, "\n")[0])
	if first == "" {
		if home, err := os.UserHomeDir(); err == nil {
			first = filepath.Join(home, "go")
		}
	}
	return filepath.Join(first, "bin"), nil
}

// releaseDownload fetches the release asset for the current platform from
// GitHub and atomically replaces the running binary.
func releaseDownload(ctx context.Context, o Options, tag string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	dir := filepath.Dir(exe)
	asset := "vexor-" + runtime.GOOS + "-" + runtime.GOARCH + exeSuffix()
	downloadURL := o.assetBase() + "/" + o.repo() + "/releases/download/" + url.PathEscape(tag) + "/" + asset
	o.printf("[update] tier 2: downloading %s", downloadURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "vexor-update")
	resp, err := o.client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("asset download returned %s for %s", resp.Status, asset)
	}
	tmp, err := os.CreateTemp(dir, "vexor-update-*"+exeSuffix())
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := io.Copy(tmp, io.LimitReader(resp.Body, 256<<20)); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("download: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return "", err
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(tmpPath, 0o755)
	}
	if rerr := replaceBinary(tmpPath, exe); rerr != nil {
		return "", rerr
	}
	return exe, nil
}

// replaceBinary swaps a downloaded update over the running binary path.
func replaceBinary(tmp, target string) error {
	if err := os.Rename(tmp, target); err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("cannot replace %s: permission denied (rerun with sudo or as administrator); the downloaded update is at %s", target, tmp)
		}
		return fmt.Errorf("cannot replace %s (the running binary may be locked, e.g. on Windows): %w; the downloaded update is at %s", target, err, tmp)
	}
	return nil
}

// gitRebuild refreshes a source clone and rebuilds the binary from it.
func gitRebuild(ctx context.Context, o Options, tag string) (string, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return "", errors.New("git not found in PATH")
	}
	if _, err := exec.LookPath("go"); err != nil {
		return "", errors.New("go tool not found in PATH")
	}
	src := sourceDir(o.repo())
	if src == "" {
		return "", errors.New("no source clone located (set VEXOR_SRC to the repository checkout)")
	}
	o.printf("[update] tier 3: rebuilding from %s", src)
	if out, err := runCmd(ctx, src, "git", "fetch", "--tags", "--force"); err != nil {
		return "", fmt.Errorf("git fetch: %w (%s)", err, strings.TrimSpace(out))
	} else if tag != "" {
		if out, err := runCmd(ctx, src, "git", "checkout", "--force", tag); err != nil {
			return "", fmt.Errorf("git checkout %s: %w (%s)", tag, err, strings.TrimSpace(out))
		}
	} else {
		if out, err := runCmd(ctx, src, "git", "pull", "--ff-only"); err != nil {
			return "", fmt.Errorf("git pull: %w (%s)", err, strings.TrimSpace(out))
		}
	}
	tmp, err := os.CreateTemp("", "vexor-rebuild-*"+exeSuffix())
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if out, err := runCmd(ctx, src, "go", "build", "-trimpath", "-o", tmpPath, "./cmd/vexor"); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("go build: %w (%s)", err, strings.TrimSpace(out))
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(tmpPath, 0o755)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if rerr := replaceBinary(tmpPath, exe); rerr != nil {
		return "", rerr
	}
	return exe, nil
}

// sourceDir locates a checkout of the repo: $VEXOR_SRC, the running binary's
// directory when it contains go.mod, or conventional clone locations.
func sourceDir(repo string) string {
	if v := strings.TrimSpace(os.Getenv("VEXOR_SRC")); v != "" {
		return v
	}
	if exe, err := os.Executable(); err == nil {
		if dir := filepath.Dir(exe); hasGoMod(dir) {
			return dir
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	for _, cand := range []string{
		filepath.Join(home, "vexor"),
		filepath.Join(home, "go", "src", "github.com", repo),
	} {
		if hasGoMod(cand) {
			return cand
		}
	}
	return ""
}

func hasGoMod(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, "go.mod"))
	return err == nil && !info.IsDir()
}

// runCmd executes a command and returns its combined output.
func runCmd(ctx context.Context, dir, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}