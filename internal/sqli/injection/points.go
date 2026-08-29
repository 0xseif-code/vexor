package injection

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Point types.
const (
	TypeGET    = "GET"
	TypePOST   = "POST"
	TypeJSON   = "JSON"
	TypeXML    = "XML"
	TypeHeader = "HEADER"
	TypeCookie = "COOKIE"
	TypePath   = "PATH"
	TypeMarker = "MARKER"
)

// ErrNoInjectionPoints is returned when nothing can receive a payload.
var ErrNoInjectionPoints = errors.New("no injectable parameters or markers found")

// RenderedRequest is a fully materialised request ready to be sent.
type RenderedRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
}

// InjectionPoint is one location that can receive a payload, with closures to
// materialise an injected request and the clean baseline request.
type InjectionPoint struct {
	Type     string
	Name     string
	Value    string
	Location string

	render     func(value string) *RenderedRequest
	renderBase func() *RenderedRequest
}

// Render returns the request with value injected at this point.
func (p *InjectionPoint) Render(value string) *RenderedRequest {
	if p.render == nil {
		return nil
	}
	return p.render(value)
}

// RenderBase returns the clean request with all markers emptied and no
// injection applied.
func (p *InjectionPoint) RenderBase() *RenderedRequest {
	if p.renderBase == nil {
		return nil
	}
	return p.renderBase()
}

// RequestSource describes the request that will be scanned for points.
type RequestSource struct {
	Method  string
	URL     string
	Headers []Header
	Body    []byte
}

// Options controls how injection points are enumerated and filtered.
type Options struct {
	Level         int
	TestParameter string
	SkipParameter []string
}

type pair struct {
	key            string
	valStart, ends int
}

type env struct {
	method      string
	scheme      string
	host        string
	path        string
	query       string
	headers     []Header
	body        []byte
	contentType string
}

// newEnv parses the request source into components that support byte-offset
// splicing.
func newEnv(rs RequestSource) (*env, error) {
	u, err := url.Parse(rs.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, errors.New("invalid target URL: missing scheme or host")
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	method := rs.Method
	if method == "" {
		method = "GET"
	}
	e := &env{
		method:      method,
		scheme:      u.Scheme,
		host:        u.Host,
		path:        p,
		query:       u.RawQuery,
		headers:     rs.Headers,
		body:        rs.Body,
		contentType: strings.ToLower(headerValue(rs.Headers, "Content-Type")),
	}
	return e, nil
}

func (e *env) makeURL(path, query string) string {
	u := e.scheme + "://" + e.host + path
	if query != "" {
		u += "?" + query
	}
	return u
}

func (e *env) headersMap() map[string]string {
	m := make(map[string]string, len(e.headers)+1)
	for _, h := range e.headers {
		if _, ok := m[h.Key]; !ok {
			m[h.Key] = h.Value
		}
	}
	return m
}

func headerValue(headers []Header, key string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Key, key) {
			return h.Value
		}
	}
	return ""
}

// markers counts marker occurrences in each component.
func (e *env) markerOffsets() (pathM, queryM []int, bodyM []int) {
	pathM = offsetsOf(e.path, Marker)
	queryM = offsetsOf(e.query, Marker)
	bodyM = offsetsOfBytes(e.body, Marker[0])
	return
}

func offsetsOf(s, sub string) []int {
	var out []int
	for i := 0; ; {
		j := strings.Index(s[i:], sub)
		if j < 0 {
			return out
		}
		out = append(out, i+j)
		i += j + len(sub)
	}
}

func offsetsOfBytes(b []byte, c byte) []int {
	var out []int
	for i, x := range b {
		if x == c {
			out = append(out, i)
		}
	}
	return out
}

// Enumerate finds every injectable position in the request and returns the
// points in deterministic order. Markers take precedence: when any `*` is
// present, only marker points are produced.
func Enumerate(rs RequestSource, opts Options) ([]*InjectionPoint, error) {
	e, err := newEnv(rs)
	if err != nil {
		return nil, err
	}
	if opts.Level < 1 {
		opts.Level = 1
	}

	var points []*InjectionPoint

	pathM, queryM, bodyM := e.markerOffsets()
	hasMarkers := len(pathM)+len(queryM)+len(bodyM) > 0

	if hasMarkers {
		points = e.markerPoints(pathM, queryM, bodyM)
	} else {
		points = e.paramPoints(opts)
	}

	points = filterPoints(points, opts)
	points = dedupe(points)
	if len(points) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoInjectionPoints, describe(rs))
	}
	return points, nil
}

func describe(rs RequestSource) string {
	return rs.Method + " " + rs.URL
}

func (e *env) markerPoints(pathM, queryM, bodyM []int) []*InjectionPoint {
	strip := func(s string) string { return strings.ReplaceAll(s, Marker, "") }
	baseURL := e.makeURL(strip(e.path), strip(e.query))
	baseBody := make([]byte, 0, len(e.body))
	for _, b := range e.body {
		if b != Marker[0] {
			baseBody = append(baseBody, b)
		}
	}
	base := func() *RenderedRequest {
		return &RenderedRequest{
			Method:  e.method,
			URL:     baseURL,
			Headers: e.headersMap(),
			Body:    append([]byte(nil), baseBody...),
		}
	}

	var pts []*InjectionPoint
	pathTpl := NewTemplate(e.path)
	for i := range pathM {
		idx := i
		pts = append(pts, &InjectionPoint{
			Type:     TypeMarker,
			Name:     fmt.Sprintf("path-marker-%d", idx+1),
			Value:    "",
			Location: "URL path marker",
			render: func(v string) *RenderedRequest {
				return &RenderedRequest{
					Method:  e.method,
					URL:     e.makeURL(pathTpl.Render(idx, encPath(v)), strip(e.query)),
					Headers: e.headersMap(),
					Body:    append([]byte(nil), baseBody...),
				}
			},
			renderBase: base,
		})
	}

	queryTpl := NewTemplate(e.query)
	for i := range queryM {
		idx := i
		pts = append(pts, &InjectionPoint{
			Type:     TypeMarker,
			Name:     fmt.Sprintf("query-marker-%d", idx+1),
			Value:    "",
			Location: "URL query marker",
			render: func(v string) *RenderedRequest {
				return &RenderedRequest{
					Method:  e.method,
					URL:     e.makeURL(strip(e.path), queryTpl.Render(idx, encQuery(v))),
					Headers: e.headersMap(),
					Body:    append([]byte(nil), baseBody...),
				}
			},
			renderBase: base,
		})
	}

	bodyTpl := NewTemplate(string(e.body))
	for i := range bodyM {
		idx := i
		pts = append(pts, &InjectionPoint{
			Type:     TypeMarker,
			Name:     fmt.Sprintf("body-marker-%d", idx+1),
			Value:    "",
			Location: "POST body marker",
			render: func(v string) *RenderedRequest {
				b := bodyTpl.Render(idx, v)
				return &RenderedRequest{
					Method:  e.method,
					URL:     e.makeURL(strip(e.path), strip(e.query)),
					Headers: e.headersMap(),
					Body:    []byte(b),
				}
			},
			renderBase: base,
		})
	}
	return pts
}

func (e *env) paramPoints(opts Options) []*InjectionPoint {
	var pts []*InjectionPoint

	// Query parameters.
	qp := parsePairs(e.query)
	for _, p := range qp {
		name := urldec(p.key)
		val := urldec(e.query[p.valStart:p.ends])
		p := p
		pts = append(pts, &InjectionPoint{
			Type:     TypeGET,
			Name:     name,
			Value:    val,
			Location: "URL query parameter",
			render: func(v string) *RenderedRequest {
				query := spliceAt(e.query, p.valStart, p.ends, encQuery(v))
				return &RenderedRequest{
					Method:  e.method,
					URL:     e.makeURL(e.path, query),
					Headers: e.headersMap(),
					Body:    append([]byte(nil), e.body...),
				}
			},
			renderBase: e.pointBase(),
		})
	}

	// Body parameters.
	switch {
	case strings.Contains(e.contentType, "application/x-www-form-urlencoded"):
		fp := parsePairs(string(e.body))
		for _, p := range fp {
			name := urldec(p.key)
			val := urldec(string(e.body[p.valStart:p.ends]))
			p := p
			pts = append(pts, &InjectionPoint{
				Type:     TypePOST,
				Name:     name,
				Value:    val,
				Location: "POST form parameter",
				render: func(v string) *RenderedRequest {
					body := spliceAt(string(e.body), p.valStart, p.ends, encForm(v))
					return &RenderedRequest{
						Method:  e.method,
						URL:     e.makeURL(e.path, e.query),
						Headers: e.headersMap(),
						Body:    []byte(body),
					}
				},
				renderBase: e.pointBase(),
			})
		}
	case strings.Contains(e.contentType, "json"):
		leaves, err := scanJSON(e.body)
		if err == nil {
			for _, l := range leaves {
				val := string(e.body[l.start:l.end])
				l := l
				pts = append(pts, &InjectionPoint{
					Type:     TypeJSON,
					Name:     l.key,
					Value:    val,
					Location: "JSON field " + l.key,
					render: func(v string) *RenderedRequest {
						body := spliceBytesAt(e.body, l.start, l.end, encJSON(v))
						return &RenderedRequest{
							Method:  e.method,
							URL:     e.makeURL(e.path, e.query),
							Headers: e.headersMap(),
							Body:    body,
						}
					},
					renderBase: e.pointBase(),
				})
			}
		}
	case strings.Contains(e.contentType, "xml"):
		for _, s := range scanXML(e.body) {
			val := string(e.body[s.start:s.end])
			kind := "element"
			if s.attr {
				kind = "attribute"
			}
			s := s
			pts = append(pts, &InjectionPoint{
				Type:     TypeXML,
				Name:     s.key,
				Value:    val,
				Location: "XML " + kind + " " + s.key,
				render: func(v string) *RenderedRequest {
					body := spliceBytesAt(e.body, s.start, s.end, encXML(v))
					return &RenderedRequest{
						Method:  e.method,
						URL:     e.makeURL(e.path, e.query),
						Headers: e.headersMap(),
						Body:    body,
					}
				},
				renderBase: e.pointBase(),
			})
		}
	}

	// Cookies (level >= 2).
	if opts.Level >= 2 {
		cookieVal := headerValue(e.headers, "Cookie")
		if cookieVal != "" {
			orig := cookieVal
			for _, p := range parsePairs(cookieVal) {
				name := urldec(p.key)
				val := urldec(cookieVal[p.valStart:p.ends])
				p := p
				pts = append(pts, &InjectionPoint{
					Type:     TypeCookie,
					Name:     name,
					Value:    val,
					Location: "Cookie " + name,
					render: func(v string) *RenderedRequest {
						h := e.headersMap()
						h["Cookie"] = spliceAt(orig, p.valStart, p.ends, encCookie(v))
						return &RenderedRequest{
							Method:  e.method,
							URL:     e.makeURL(e.path, e.query),
							Headers: h,
							Body:    append([]byte(nil), e.body...),
						}
					},
					renderBase: e.pointBase(),
				})
			}
		}
	}

	// Headers (level >= 3).
	if opts.Level >= 3 {
		for _, hname := range []string{"User-Agent", "Referer", "X-Forwarded-For"} {
			hname := hname
			existing, _ := headerHas(e.headers, hname)
			val := existing
			pts = append(pts, &InjectionPoint{
				Type:     TypeHeader,
				Name:     hname,
				Value:    val,
				Location: "Header " + hname,
				render: func(v string) *RenderedRequest {
					h := e.headersMap()
					h[hname] = encHeader(v)
					return &RenderedRequest{
						Method:  e.method,
						URL:     e.makeURL(e.path, e.query),
						Headers: h,
						Body:    append([]byte(nil), e.body...),
					}
				},
				renderBase: func() *RenderedRequest {
					h := e.headersMap()
					h[hname] = encHeader(existing)
					return &RenderedRequest{
						Method:  e.method,
						URL:     e.makeURL(e.path, e.query),
						Headers: h,
						Body:    append([]byte(nil), e.body...),
					}
				},
			})
		}
	}

	// Numeric path segments (level >= 5).
	if opts.Level >= 5 {
		for i, seg := range strings.Split(e.path, "/") {
			if seg == "" || !isNumeric(seg) {
				continue
			}
			seg := seg
			idx := i
			pts = append(pts, &InjectionPoint{
				Type:     TypePath,
				Name:     seg,
				Value:    seg,
				Location: fmt.Sprintf("URL path segment %d", i),
				render: func(v string) *RenderedRequest {
					parts := strings.Split(e.path, "/")
					parts[idx] = encPath(v)
					return &RenderedRequest{
						Method:  e.method,
						URL:     e.makeURL(strings.Join(parts, "/"), e.query),
						Headers: e.headersMap(),
						Body:    append([]byte(nil), e.body...),
					}
				},
				renderBase: e.pointBase(),
			})
		}
	}

	return pts
}

func (e *env) pointBase() func() *RenderedRequest {
	return func() *RenderedRequest {
		return &RenderedRequest{
			Method:  e.method,
			URL:     e.makeURL(e.path, e.query),
			Headers: e.headersMap(),
			Body:    append([]byte(nil), e.body...),
		}
	}
}

func headerHas(headers []Header, key string) (string, bool) {
	for _, h := range headers {
		if strings.EqualFold(h.Key, key) {
			return h.Value, true
		}
	}
	return "", false
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func urldec(s string) string {
	d, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}
	return d
}

func parsePairs(s string) []pair {
	var out []pair
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '&' {
			key := s[start:i]
			vs, ve := i, i
			if eq := strings.IndexByte(s[start:i], '='); eq >= 0 {
				key = s[start : start+eq]
				vs = start + eq + 1
				ve = i
			}
			if key != "" {
				out = append(out, pair{key: key, valStart: vs, ends: ve})
			}
			start = i + 1
		}
	}
	return out
}

func spliceAt(s string, start, end int, repl string) string {
	return s[:start] + repl + s[end:]
}

func spliceBytesAt(b []byte, start, end int, repl string) []byte {
	out := make([]byte, 0, len(b)-int(end-start)+len(repl))
	out = append(out, b[:start]...)
	out = append(out, repl...)
	out = append(out, b[end:]...)
	return out
}

func filterPoints(points []*InjectionPoint, opts Options) []*InjectionPoint {
	var testNames map[string]bool
	if opts.TestParameter != "" {
		testNames = map[string]bool{}
		for _, n := range strings.Split(opts.TestParameter, ",") {
			testNames[strings.ToLower(strings.TrimSpace(n))] = true
		}
	}
	skip := map[string]bool{}
	for _, n := range opts.SkipParameter {
		skip[strings.ToLower(strings.TrimSpace(n))] = true
	}
	var out []*InjectionPoint
	for _, p := range points {
		if len(testNames) > 0 && !testNames[strings.ToLower(p.Name)] {
			continue
		}
		if skip[strings.ToLower(p.Name)] {
			continue
		}
		out = append(out, p)
	}
	return out
}

func dedupe(points []*InjectionPoint) []*InjectionPoint {
	seen := map[string]bool{}
	var out []*InjectionPoint
	for _, p := range points {
		id := p.Type + ":" + p.Location + ":" + p.Name
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, p)
	}
	return out
}
