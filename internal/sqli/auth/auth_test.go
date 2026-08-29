package auth

import (
	"testing"

	"github.com/0xseif-code/vexor/internal/httpclient"
)

func TestBasicPrepare(t *testing.T) {
	client := httpclient.NewClient(httpclient.DefaultOptions())
	h := New(Config{Type: AuthBasic, Credentials: "admin:secret"}, client)
	if err := h.Prepare(t.Context()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	req := &Request{Method: "GET", URL: "http://example.com/", Headers: map[string]string{}}
	if err := h.Apply(req); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if want := "Basic YWRtaW46c2VjcmV0"; req.Headers["Authorization"] != want {
		t.Errorf("Authorization = %q, want %q", req.Headers["Authorization"], want)
	}
}

func TestBearerPrepare(t *testing.T) {
	client := httpclient.NewClient(httpclient.DefaultOptions())
	h := New(Config{Type: AuthBearer, Credentials: "tok123"}, client)
	if err := h.Prepare(t.Context()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	req := &Request{Method: "GET", URL: "http://example.com/", Headers: map[string]string{}}
	if err := h.Apply(req); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if req.Headers["Authorization"] != "Bearer tok123" {
		t.Errorf("Authorization = %q", req.Headers["Authorization"])
	}
}

func TestParseChallenge(t *testing.T) {
	challenge := `Digest realm="testrealm", nonce="abc123", qop="auth", algorithm=MD5, opaque="abc"`
	p := parseChallenge(challenge)
	if p["realm"] != "testrealm" || p["nonce"] != "abc123" || p["qop"] != "auth" {
		t.Errorf("parseChallenge = %v", p)
	}
}

func TestBuildDigestHeader(t *testing.T) {
	challenge := `Digest realm="testrealm", nonce="abc123", qop="auth", algorithm=MD5`
	hdr, err := buildDigestHeader("GET", "/", challenge, "user", "pass")
	if err != nil {
		t.Fatalf("buildDigestHeader: %v", err)
	}
	if hdr[:7] != "Digest " {
		t.Errorf("digest header prefix = %q", hdr[:7])
	}
	if !contains(hdr, `username="user"`) || !contains(hdr, "response=") {
		t.Errorf("digest header = %q", hdr)
	}
}

func TestExtractTokenHTML(t *testing.T) {
	body := `<html><form><input type="hidden" name="csrf" value="tok_abc"></form><meta name="csrf-token" content="tok_meta"></html>`
	resp := &httpclient.Response{Body: []byte(body), Headers: map[string]string{"Content-Type": "text/html"}}
	tok, ok := extractToken(resp, "csrf")
	if !ok || tok != "tok_abc" {
		t.Errorf("extractToken hidden input = %q, %v", tok, ok)
	}
	tok, ok = extractToken(resp, "csrf-token")
	if !ok || tok != "tok_meta" {
		t.Errorf("extractToken meta = %q, %v", tok, ok)
	}
}

func TestExtractTokenJSON(t *testing.T) {
	body := `{"data":{"csrf_token":"tok_json"}}`
	resp := &httpclient.Response{Body: []byte(body), Headers: map[string]string{"Content-Type": "application/json"}}
	tok, ok := extractToken(resp, "csrf_token")
	if !ok || tok != "tok_json" {
		t.Errorf("extractToken json = %q, %v", tok, ok)
	}
}

func TestInjectFormValue(t *testing.T) {
	data := "user=admin&pass=hunter2"
	out := injectFormValue(data, "csrf", "TOK", "http://example.com")
	if out != "user=admin&pass=hunter2&csrf=TOK" {
		t.Errorf("injectFormValue = %q", out)
	}
	// Existing field gets replaced.
	data2 := "user=admin&csrf=old"
	out2 := injectFormValue(data2, "csrf", "newtok", "http://example.com")
	if out2 != "user=admin&csrf=newtok" {
		t.Errorf("injectFormValue replace = %q", out2)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
