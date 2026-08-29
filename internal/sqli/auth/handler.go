// Package auth covers auth for reaching injection points behind login gates:
// basic, digest, NTLM, bearer, cookie/form login, and CSRF extraction.
package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/url"
	"strings"
	"sync"

	"github.com/0xseif-code/vexor/internal/httpclient"
	ntlmssp "github.com/Azure/go-ntlmssp"
)

// AuthType enumerates the supported authentication methods.
type AuthType string

const (
	AuthNone   AuthType = "none"
	AuthBasic  AuthType = "basic"
	AuthDigest AuthType = "digest"
	AuthNTLM   AuthType = "ntlm"
	AuthBearer AuthType = "bearer"
	AuthForm   AuthType = "form"
)

// Request is an outgoing HTTP request Apply can decorate with auth headers
// and cookies.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
}

// Config configures the authentication handler.
type Config struct {
	Type          AuthType
	Credentials   string // format depends on type
	LoginURL      string // form auth
	LoginData     string // form auth
	CheckURL      string // verify login success
	CheckString   string // text proving success
	CSRFTokenName string
	CSRFURL       string
}

// Handler tracks auth state: logins, cookies, CSRF tokens, and re-auth.
type Handler struct {
	cfg      Config
	client   *httpclient.Client
	creds    *credentials
	cookies  []*cookiePair
	authHead map[string]string // prepared auth headers (basic/digest/bearer/ntlm)
	mu       sync.Mutex
	ntlm     *ntlmTransport
	csrf     *csrfState
}

type credentials struct {
	username string
	password string
	domain   string
	token    string // for bearer
}

type cookiePair struct {
	Name   string
	Value  string
	Path   string
	Domain string
}

type csrfState struct {
	lastToken string
}

// New builds a Handler from a config and an httpclient.
func New(cfg Config, client *httpclient.Client) *Handler {
	h := &Handler{
		cfg:      cfg,
		client:   client,
		authHead: make(map[string]string),
		csrf:     &csrfState{},
	}
	h.parseCredentials()
	return h
}

func (h *Handler) parseCredentials() {
	c := &credentials{}
	switch h.cfg.Type {
	case AuthBasic, AuthDigest, AuthNTLM:
		user, pass := splitCreds(h.cfg.Credentials)
		c.username = user
		c.password = pass
		if h.cfg.Type == AuthNTLM {
			// Format: "domain\\user:pass"
			if idx := strings.IndexAny(user, `\/`); idx >= 0 {
				c.domain = user[:idx]
				c.username = user[idx+1:]
			}
		}
	case AuthBearer:
		c.token = strings.TrimSpace(h.cfg.Credentials)
	}
	h.creds = c
}

func splitCreds(creds string) (user, pass string) {
	if idx := strings.Index(creds, ":"); idx >= 0 {
		return creds[:idx], creds[idx+1:]
	}
	return creds, ""
}

// Prepare performs the initial authentication. For form login it performs the
// login sequence and captures cookies. For header-based auth it builds the
// headers. It is safe to call before any scan.
func (h *Handler) Prepare(ctx context.Context) error {
	switch h.cfg.Type {
	case AuthNone:
		return nil
	case AuthBasic:
		enc := base64.StdEncoding.EncodeToString([]byte(h.creds.username + ":" + h.creds.password))
		h.mu.Lock()
		h.authHead["Authorization"] = "Basic " + enc
		h.mu.Unlock()
		return nil
	case AuthBearer:
		h.mu.Lock()
		h.authHead["Authorization"] = "Bearer " + h.creds.token
		h.mu.Unlock()
		return nil
	case AuthDigest:
		// Digest requires a challenge; headers are derived on demand during
		// Apply by exchanging with the server. Prepare does nothing.
		return nil
	case AuthNTLM:
		h.ntlm = newNTLMTransport(h.creds)
		return nil
	case AuthForm:
		return h.login(ctx)
	}
	return fmt.Errorf("unsupported auth type %q", h.cfg.Type)
}

// login performs a form-based authentication: fetch a CSRF token if
// configured, POST the login data, capture Set-Cookie values, then verify by
// GETting the check URL and looking for the check string.
func (h *Handler) login(ctx context.Context) error {
	if h.cfg.LoginURL == "" {
		return errors.New("form auth requires --auth-url")
	}

	loginData := h.cfg.LoginData

	// Fetch a fresh CSRF token for the login form if required.
	if h.cfg.CSRFURL != "" && h.cfg.CSRFTokenName != "" {
		token, err := h.FetchCSRFToken(ctx)
		if err != nil {
			// Non-fatal: some targets use the same page for token and login.
		} else {
			loginData = injectFormValue(loginData, h.cfg.CSRFTokenName, token, h.cfg.CSRFURL)
		}
	}

	resp, err := h.postForm(ctx, h.cfg.LoginURL, loginData)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}

	// Capture Set-Cookie values regardless of status, since login may
	// redirect before setting cookies (or set them then redirect).
	newCookies := extractCookies(resp)
	if len(newCookies) > 0 {
		h.mu.Lock()
		h.mergeCookies(newCookies)
		h.mu.Unlock()
	}

	// Verify login success.
	if h.cfg.CheckURL != "" {
		ok, err := h.verifyLogin(ctx, h.cfg.CheckURL, h.cfg.CheckString)
		if err != nil {
			return fmt.Errorf("login verification failed: %w", err)
		}
		if !ok {
			return errors.New("login verification failed: check string not found on auth-check URL")
		}
	}

	// Warning path: login succeeded (status ok) but no cookies were set — the
	// server may rely on headers only, so we continue with headers.
	if len(newCookies) == 0 && resp.IsSuccess() {
		_ = resp // caller may choose to warn
	}

	return nil
}

// postForm POSTs body data, using the correct Content-Type (urlencoded or
// multipart based on the shape of the data).
func (h *Handler) postForm(ctx context.Context, target, data string) (*httpclient.Response, error) {
	if strings.HasPrefix(strings.ToLower(data), "multipart:") {
		return h.postMultipart(ctx, target, strings.TrimPrefix(data, "multipart:"))
	}
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	return h.client.Post(ctx, target, []byte(data), headers)
}

func (h *Handler) postMultipart(ctx context.Context, target, data string) (*httpclient.Response, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for _, part := range strings.Split(data, "&") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		name, _ := url.QueryUnescape(kv[0])
		val, _ := url.QueryUnescape(kv[1])
		_ = w.WriteField(name, val)
	}
	_ = w.Close()
	headers := map[string]string{"Content-Type": w.FormDataContentType()}
	return h.client.Post(ctx, target, buf.Bytes(), headers)
}

func (h *Handler) mergeCookies(cs []*cookiePair) {
	// Replace existing cookies with the same name for the same domain/path.
	keep := h.cookies[:0]
	for _, nc := range cs {
		kept := false
		for _, oc := range h.cookies {
			if oc.Name == nc.Name && oc.Domain == nc.Domain && oc.Path == nc.Path {
				oc.Value = nc.Value
				kept = true
				break
			}
		}
		if !kept {
			keep = append(h.cookies, nc)
		}
	}
	h.cookies = append(uniqueCookies(keep), uniqueCookies(cs)...)
}

func uniqueCookies(cs []*cookiePair) []*cookiePair {
	seen := map[string]bool{}
	out := cs[:0]
	for _, c := range cs {
		key := c.Name + "|" + c.Domain + "|" + c.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	return out
}

func extractCookies(resp *httpclient.Response) []*cookiePair {
	var out []*cookiePair
	// Look for Set-Cookie headers (case-insensitive) and the raw Cookie jar
	// we may have set.
	for k, v := range resp.Headers {
		if strings.EqualFold(k, "Set-Cookie") {
			out = append(out, parseSetCookie(v))
		}
	}
	return out
}

func parseSetCookie(header string) *cookiePair {
	c := &cookiePair{}
	parts := strings.Split(header, ";")
	if len(parts) == 0 {
		return c
	}
	kv := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
	if len(kv) == 2 {
		c.Name = kv[0]
		c.Value = kv[1]
	}
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(strings.ToLower(p), "path=") {
			c.Path = strings.TrimPrefix(strings.ToLower(p), "path=")
		} else if strings.HasPrefix(strings.ToLower(p), "domain=") {
			c.Domain = strings.TrimPrefix(strings.ToLower(p), "domain=")
		}
	}
	return c
}

// buildCookies renders the Cookie header value from the stored cookies. The
// caller must hold h.mu.
func (h *Handler) buildCookies() string {
	var sb strings.Builder
	first := true
	for _, c := range h.cookies {
		if !first {
			sb.WriteString("; ")
		}
		sb.WriteString(c.Name)
		sb.WriteString("=")
		sb.WriteString(c.Value)
		first = false
	}
	return sb.String()
}

// sessionCookies returns the Cookie header value, acquiring the lock.
func (h *Handler) sessionCookies() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.buildCookies()
}

// verifyLogin GETs the check URL and reports whether the check string is
// found. It follows redirects via the httpclient's redirect handling.
func (h *Handler) verifyLogin(ctx context.Context, checkURL, checkString string) (bool, error) {
	headers := map[string]string(nil)
	if ck := h.sessionCookies(); ck != "" {
		headers = map[string]string{"Cookie": ck}
	}
	resp, err := h.client.Get(ctx, checkURL, headers)
	if err != nil {
		return false, err
	}
	if checkString == "" {
		return resp.IsSuccess(), nil
	}
	return resp.ContainsBody(checkString), nil
}

// VerifyStillAuthenticated checks the form session against the configured
// check URL. Header-based auth never expires mid-run, so it always returns
// true.
func (h *Handler) VerifyStillAuthenticated(ctx context.Context) (bool, error) {
	if h.cfg.Type != AuthForm {
		return true, nil
	}
	if h.cfg.CheckURL == "" {
		return true, nil
	}
	return h.verifyLogin(ctx, h.cfg.CheckURL, h.cfg.CheckString)
}

// Apply adds the appropriate authentication to an outgoing request. For
// header-based auth it injects the Authorization header; for form auth it
// injects session cookies; for digest/NTLM it performs the challenge dance.
func (h *Handler) Apply(req *Request) error {
	if req == nil {
		return errors.New("nil request")
	}
	if req.Headers == nil {
		req.Headers = make(map[string]string)
	}

	h.mu.Lock()
	authHead := make(map[string]string, len(h.authHead))
	for k, v := range h.authHead {
		authHead[k] = v
	}
	cookies := h.buildCookies()
	h.mu.Unlock()

	switch h.cfg.Type {
	case AuthBasic, AuthBearer:
		for k, v := range authHead {
			req.Headers[k] = v
		}
	case AuthDigest:
		return h.applyDigest(req, authHead)
	case AuthNTLM:
		return h.applyNTLM(req)
	case AuthForm:
		if cookies != "" {
			mergeCookieHeader(req.Headers, cookies)
		}
	}
	return nil
}

func mergeCookieHeader(headers map[string]string, add string) {
	if add == "" {
		return
	}
	if existing, ok := headers["Cookie"]; ok && existing != "" {
		headers["Cookie"] = existing + "; " + add
	} else {
		headers["Cookie"] = add
	}
}

// applyDigest performs the digest challenge-response. It first issues an
// unauthenticated request, reads the WWW-Authenticate challenge, then builds
// the Authorization header.
func (h *Handler) applyDigest(req *Request, authHead map[string]string) error {
	// If we already derived the header, reuse it.
	if h := digestHeaderLocked(authHead); h != "" {
		return nil
	}

	ctx := context.Background()
	resp, err := h.client.Get(ctx, req.URL, nil)
	if err != nil {
		return fmt.Errorf("digest challenge request failed: %w", err)
	}
	challenge := resp.HeaderGet("WWW-Authenticate")
	if challenge == "" {
		// No challenge — maybe not protected; proceed without auth.
		return nil
	}
	header, err := buildDigestHeader(req.Method, req.URL, challenge, h.creds.username, h.creds.password)
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.authHead["Authorization"] = header
	h.mu.Unlock()
	req.Headers["Authorization"] = header
	return nil
}

func digestHeaderLocked(headers map[string]string) string {
	for k, v := range headers {
		if strings.EqualFold(k, "Authorization") {
			return v
		}
	}
	return ""
}

// ntlmTransport runs the NTLM negotiate -> challenge -> authenticate dance
// using go-ntlmssp's message primitives (NewNegotiateMessage,
// ProcessChallenge).
type ntlmTransport struct {
	creds      *credentials
	mu         sync.Mutex
	state      int // 0 = not started, 1 = have authenticate header
	authHeader string
}

func newNTLMTransport(c *credentials) *ntlmTransport {
	return &ntlmTransport{creds: c}
}

// negotiate returns the base64 negotiate token for the initial request.
func (t *ntlmTransport) negotiate() (string, error) {
	domain, workstation := "", ""
	if t.creds != nil && t.creds.domain != "" {
		domain = t.creds.domain
	}
	msg, err := ntlmssp.NewNegotiateMessage(domain, workstation)
	if err != nil {
		return "", fmt.Errorf("ntlm negotiate: %w", err)
	}
	return "NTLM " + base64.StdEncoding.EncodeToString(msg), nil
}

// complete processes a server challenge and produces the authenticate header,
// caching it for subsequent requests.
func (t *ntlmTransport) complete(challengeB64 string) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state == 1 && t.authHeader != "" {
		return t.authHeader, nil
	}
	challenge, err := base64.StdEncoding.DecodeString(challengeB64)
	if err != nil {
		return "", fmt.Errorf("ntlm challenge decode: %w", err)
	}
	user, domain, domainNeeded := ntlmssp.GetDomain(t.creds.username)
	authMsg, err := ntlmssp.ProcessChallenge(challenge, user, t.creds.password, domainNeeded)
	if err != nil {
		return "", fmt.Errorf("ntlm challenge: %w", err)
	}
	t.authHeader = "NTLM " + base64.StdEncoding.EncodeToString(authMsg)
	t.state = 1
	_ = domain
	return t.authHeader, nil
}

// applyNTLM performs the NTLM handshake against the request's target URL:
// it sends a negotiate header, reads the challenge from the 401 response,
// then computes the authenticate header and sets it on the request so the
// caller's subsequent send is authenticated.
func (h *Handler) applyNTLM(req *Request) error {
	if h.ntlm == nil {
		return nil
	}
	t := h.ntlm

	// If we already have a cached authenticate header, just set it.
	t.mu.Lock()
	cached := t.authHeader
	t.mu.Unlock()
	if cached != "" {
		req.Headers["Authorization"] = cached
		return nil
	}

	negotiate, err := t.negotiate()
	if err != nil {
		return err
	}
	headers := map[string]string{"Authorization": negotiate}
	resp, err := h.client.Get(context.Background(), req.URL, headers)
	if err != nil {
		return fmt.Errorf("ntlm negotiate request failed: %w", err)
	}
	challenge := resp.HeaderGet("WWW-Authenticate")
	idx := strings.Index(strings.ToLower(challenge), "ntlm ")
	if idx < 0 {
		// No NTLM challenge; endpoint may not require NTLM. Proceed without.
		return nil
	}
	challengeB64 := strings.TrimSpace(challenge[idx+len("ntlm "):])
	authHeader, err := t.complete(challengeB64)
	if err != nil {
		return err
	}
	req.Headers["Authorization"] = authHeader
	return nil
}

// FetchCSRFToken retrieves a fresh CSRF token from the configured CSRF URL.
// It supports token extraction from HTML form hidden inputs, HTML meta tags,
// or JSON responses (by name lookup in a JSON object).
func (h *Handler) FetchCSRFToken(ctx context.Context) (string, error) {
	if h.cfg.CSRFURL == "" || h.cfg.CSRFTokenName == "" {
		return "", errors.New("csrf url and token name required")
	}
	headers := map[string]string(nil)
	if h.cfg.Type == AuthForm {
		if ck := h.sessionCookies(); ck != "" {
			headers = map[string]string{"Cookie": ck}
		}
	}
	resp, err := h.client.Get(ctx, h.cfg.CSRFURL, headers)
	if err != nil {
		return "", fmt.Errorf("fetch csrf: %w", err)
	}
	token, ok := extractToken(resp, h.cfg.CSRFTokenName)
	if !ok {
		return "", fmt.Errorf("csrf token %q not found in response from %s", h.cfg.CSRFTokenName, h.cfg.CSRFURL)
	}
	h.mu.Lock()
	h.csrf.lastToken = token
	h.mu.Unlock()
	return token, nil
}

// LastCSRFToken returns the most recently extracted token, if any.
func (h *Handler) LastCSRFToken() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.csrf.lastToken
}

// extractToken looks for the token in a response body or headers. Order of
// preference: JSON value (by key), HTML form input, HTML meta tag, response
// header.
func extractToken(resp *httpclient.Response, name string) (string, bool) {
	body := resp.BodyString()
	ct := resp.HeaderGet("Content-Type")

	// JSON response.
	if strings.Contains(strings.ToLower(ct), "json") || looksLikeJSON(body) {
		if t, ok := jsonToken(body, name); ok {
			return t, true
		}
	}
	// HTML form input & meta tag.
	if t, ok := htmlToken(body, name); ok {
		return t, true
	}
	return "", false
}

func looksLikeJSON(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")
}

func jsonToken(body, name string) (string, bool) {
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		return "", false
	}
	if v, ok := lookupJSON(obj, name); ok {
		if s, isStr := v.(string); isStr {
			return s, true
		}
	}
	return "", false
}

func lookupJSON(obj map[string]interface{}, key string) (interface{}, bool) {
	if v, ok := obj[key]; ok {
		return v, true
	}
	// Case-insensitive top-level match.
	for k, v := range obj {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	// Recurse one level into nested objects.
	for _, v := range obj {
		if sub, ok := v.(map[string]interface{}); ok {
			if r, ok := lookupJSON(sub, key); ok {
				return r, true
			}
		}
	}
	return nil, false
}

// htmlToken extracts a token from an HTML document: hidden input named `name`
// or a meta tag with name/Attribute `name`.
func htmlToken(body, name string) (string, bool) {
	doc, err := parseHTML(body)
	if err != nil || doc == nil {
		return "", false
	}
	return doc.token(name)
}

// injectFormValue replaces the value of a form field (or adds it) in a
// urlencoded body string.
func injectFormValue(data, name, value, _ string) string {
	parts := strings.Split(data, "&")
	for i, p := range parts {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) == 2 && kv[0] == name {
			parts[i] = name + "=" + url.QueryEscape(value)
			return strings.Join(parts, "&")
		}
	}
	return data + "&" + name + "=" + url.QueryEscape(value)
}

// --- digest hashing helpers ---

// parseChallenge extracts the digest parameters from a WWW-Authenticate value.
func parseChallenge(challenge string) map[string]string {
	params := make(map[string]string)
	rest := challenge
	// Strip the scheme prefix (e.g. "Digest ").
	if idx := strings.IndexByte(rest, ' '); idx >= 0 {
		rest = rest[idx+1:]
	}
	i := 0
	for i < len(rest) {
		// Skip separators and whitespace between parameters.
		for i < len(rest) && (rest[i] == ',' || rest[i] == ' ' || rest[i] == '\t') {
			i++
		}
		if i >= len(rest) {
			break
		}
		eq := strings.IndexByte(rest[i:], '=')
		if eq < 0 {
			break
		}
		key := strings.TrimSpace(rest[i : i+eq])
		i += eq + 1
		var val string
		if i < len(rest) && rest[i] == '"' {
			i++
			closeIdx := strings.IndexByte(rest[i:], '"')
			if closeIdx < 0 {
				val = rest[i:]
				i = len(rest)
			} else {
				val = rest[i : i+closeIdx]
				i += closeIdx + 1
			}
		} else {
			comma := strings.IndexByte(rest[i:], ',')
			if comma < 0 {
				val = rest[i:]
				i = len(rest)
			} else {
				val = rest[i : i+comma]
				i += comma
			}
		}
		params[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(val)
	}
	return params
}

// buildDigestHeader computes the digest Authorization value for the given
// challenge using MD5 (the standard RFC 2617 algorithm).
func buildDigestHeader(method, uri, challenge, user, pass string) (string, error) {
	params := parseChallenge(challenge)
	if params["realm"] == "" {
		return "", errors.New("digest challenge missing realm")
	}
	nonce := params["nonce"]
	qop := params["qop"]
	algorithm := params["algorithm"]
	opaque := params["opaque"]

	if algorithm == "" {
		algorithm = "MD5"
	}
	nc := "00000001"
	cnonce := randomHex(8)

	ha1 := md5Sum(user + ":" + params["realm"] + ":" + pass)
	ha2 := md5Sum(method + ":" + uri)
	var response string
	if strings.Contains(qop, "auth") {
		response = md5Sum(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
	} else {
		response = md5Sum(ha1 + ":" + nonce + ":" + ha2)
	}

	parts := []string{
		`username="` + user + `"`,
		`realm="` + params["realm"] + `"`,
		`nonce="` + nonce + `"`,
		`uri="` + uri + `"`,
		`response="` + response + `"`,
		`algorithm=` + algorithm,
	}
	if opaque != "" {
		parts = append(parts, `opaque="`+opaque+`"`)
	}
	if qop != "" && strings.Contains(qop, "auth") {
		parts = append(parts, `qop=auth`, `nc=`+nc, `cnonce="`+cnonce+`"`)
	}
	return "Digest " + strings.Join(parts, ", "), nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = io.ReadFull(rand.Reader, b)
	return hex.EncodeToString(b)
}

// md5Sum returns the lowercase hex MD5 of s.
func md5Sum(s string) string {
	return hexMD5([]byte(s))
}
