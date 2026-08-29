package subdomain

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/0xseif-code/vexor/internal/httpclient"
)

const crtshEndpoint = "https://crt.sh/?q=%s&output=json"

// crtshEntry mirrors the JSON structure returned by crt.sh. Only the fields
// we care about are declared; unknown fields are ignored by encoding/json.
type crtshEntry struct {
	NameValue string `json:"name_value"`
}

// ErrCRTSHRequestFailed is returned when the crt.sh HTTP request itself fails.
var ErrCRTSHRequestFailed = fmt.Errorf("crt.sh request failed")

// crtshClient wraps the interaction with crt.sh's certificate transparency
// log endpoint. It uses the injected httpclient for all network I/O.
type crtshClient struct {
	http   *httpclient.Client
	domain string
}

// newCRTSHClient builds a crtshClient bound to the target domain.
func newCRTSHClient(httpClient *httpclient.Client, domain string) *crtshClient {
	return &crtshClient{http: httpClient, domain: domain}
}

// Query looks up certs for the target domain and returns the deduplicated,
// wildcard-filtered subdomain names. On any crt.sh failure it returns an
// error; callers may skip.
func (c *crtshClient) Query(ctx context.Context) ([]string, error) {
	endpoint := buildCRTSHURL(c.domain)

	resp, err := c.http.Get(ctx, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCRTSHRequestFailed, err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%w: unexpected status %d", ErrCRTSHRequestFailed, resp.StatusCode)
	}

	names, err := parseCRTSHResponse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCRTSHRequestFailed, err)
	}

	// dedupeExact handles duplicates case-sensitively; then normalize to
	// lowercase before validating characters. Invalid/wildcard entries are
	// dropped silently.
	seen := make(map[string]struct{}, len(names))
	for _, raw := range names {
		name := normalizeSubdomain(raw)
		if !validSubdomainName(name) {
			continue
		}
		if isWildcardEntry(raw) {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
	}

	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	return out, nil
}

// buildCRTSHURL builds the crt.sh JSON endpoint for a domain. The "%." wildcard
// prefix is URL-escaped so crt.sh treats it literally.
func buildCRTSHURL(domain string) string {
	q := url.QueryEscape("%." + domain)
	return fmt.Sprintf(crtshEndpoint, q)
}

// parseCRTSHResponse parses the crt.sh JSON body defensively. crt.sh may
// return an HTML error page instead of JSON when it is under load, so we
// validate that the payload actually looks like a JSON array before
// attempting to unmarshal.
func parseCRTSHResponse(body []byte) ([]string, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		// Empty response is a valid outcome (no results); return empty slice.
		return []string{}, nil
	}

	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, fmt.Errorf("response is not a JSON array (got %q)", previewBody(trimmed))
	}

	var entries []crtshEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	// name_value may contain multiple newline-separated entries per certificate.
	var names []string
	for _, e := range entries {
		for _, part := range strings.Split(e.NameValue, "\n") {
			part = strings.TrimSpace(part)
			if part != "" {
				names = append(names, part)
			}
		}
	}
	return names, nil
}

// previewBody returns a short excerpt of a body for error messages, guarding
// against dumping huge or binary payloads into the log.
func previewBody(s string) string {
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}
