package injection

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrMalformedRawRequest indicates a Burp-style request file could not be
	// parsed.
	ErrMalformedRawRequest = errors.New("malformed raw request")
	// ErrUnsupportedMethod indicates the request line used a method the
	// engine will not replay.
	ErrUnsupportedMethod = errors.New("unsupported HTTP method in raw request")
)

// Header is a single HTTP header in encounter order.
type Header struct {
	Key   string
	Value string
}

// RawRequest is the parsed form of a Burp-style request file.
type RawRequest struct {
	Method  string
	Target  string
	Version string
	Headers []Header
	Body    []byte
}

// Host extracts the Host header value, if present.
func (r *RawRequest) Host() string {
	for _, h := range r.Headers {
		if strings.EqualFold(h.Key, "Host") {
			return h.Value
		}
	}
	return ""
}

// AbsoluteURL reconstructs a full URL (scheme derived from tls, host from the
// Host header, target as typed). It returns "" when host parsing fails.
func (r *RawRequest) AbsoluteURL(tls bool) string {
	scheme := "http"
	if tls {
		scheme = "https"
	}
	host := r.Host()
	if host == "" {
		// Fall back to a bare-relative target; Do() will reject it, which is
		// surfaced as an error upstream.
		return r.Target
	}
	return scheme + "://" + host + r.Target
}

// ParseRaw parses a Burp-style raw HTTP request. Line endings are handled for
// both \r\n and bare \n. Errors carry the offending line number.
func ParseRaw(data []byte, tls bool) (*RawRequest, error) {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(text, "\n")

	req := &RawRequest{Version: "HTTP/1.1"}

	// --- request line ---
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return nil, fmt.Errorf("%w: empty request line", ErrMalformedRawRequest)
	}
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return nil, fmt.Errorf("%w: line 1 expected 'METHOD TARGET [VERSION]', got %q", ErrMalformedRawRequest, lines[0])
	}
	req.Method = strings.ToUpper(parts[0])
	req.Target = parts[1]
	if len(parts) >= 3 && strings.HasPrefix(strings.ToUpper(parts[2]), "HTTP/") {
		req.Version = parts[2]
	}

	// --- headers ---
	bodyStart := -1
	for i := 1; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], "\r")
		if strings.TrimSpace(line) == "" {
			bodyStart = i + 1
			break
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			return nil, fmt.Errorf("%w: line %d malformed header %q", ErrMalformedRawRequest, i+1, line)
		}
		req.Headers = append(req.Headers, Header{
			Key:   strings.TrimSpace(line[:colon]),
			Value: strings.TrimSpace(line[colon+1:]),
		})
	}

	// --- body ---
	if bodyStart >= 0 && bodyStart < len(lines) {
		req.Body = []byte(strings.Join(lines[bodyStart:], "\n"))
	}

	// Drop hop-by-hop headers that describe a previous connection rather than
	// the target.
	filtered := req.Headers[:0]
	for _, h := range req.Headers {
		switch {
		case strings.EqualFold(h.Key, "Content-Length"):
			continue
		case strings.EqualFold(h.Key, "Transfer-Encoding"):
			continue
		case strings.EqualFold(h.Key, "Connection"):
			continue
		case strings.EqualFold(h.Key, "Proxy-Connection"):
			continue
		case strings.EqualFold(h.Key, "Upgrade"):
			continue
		}
		filtered = append(filtered, h)
	}
	req.Headers = filtered

	// Surface common method mistakes early.
	switch req.Method {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedMethod, req.Method)
	}

	return req, nil
}
