package waf

import (
	"testing"

	"github.com/0xseif-code/vexor/internal/httpclient"
)

func TestPassiveCloudflare(t *testing.T) {
	resp := &httpclient.Response{
		StatusCode: 403,
		Headers: map[string]string{
			"Server":     "cloudflare",
			"cf-ray":     "abc123-CDG",
			"Set-Cookie": "__cf_bm=xyz; path=/",
		},
		Body: []byte("error"),
	}
	wafs, ok := passiveMatch(resp)
	if !ok {
		t.Fatal("expected a WAF match")
	}
	found := false
	for _, w := range wafs {
		if w.Name == "Cloudflare" {
			found = true
			if w.Confidence < 80 {
				t.Errorf("Cloudflare confidence = %d", w.Confidence)
			}
			if len(w.Evidence) == 0 {
				t.Error("expected evidence")
			}
		}
	}
	if !found {
		t.Errorf("Cloudflare not detected: %+v", wafs)
	}
}

func TestPassiveF5Cookies(t *testing.T) {
	resp := &httpclient.Response{
		Headers: map[string]string{
			"Set-Cookie": "BIGipServerPool1=12345.6789.0000; path=/",
		},
		Body: nil,
	}
	wafs, ok := passiveMatch(resp)
	if !ok {
		t.Fatal("expected F5 match")
	}
	for _, w := range wafs {
		if w.Name == "F5 BIG-IP" {
			return
		}
	}
	t.Errorf("F5 not detected: %+v", wafs)
}

func TestNoMatch(t *testing.T) {
	resp := &httpclient.Response{StatusCode: 200, Headers: map[string]string{"Server": "nginx"}, Body: []byte("hello")}
	wafs, ok := passiveMatch(resp)
	if ok {
		t.Errorf("unexpected match: %+v", wafs)
	}
}

func TestSuggestedChain(t *testing.T) {
	s := SuggestedTamperChain("Cloudflare")
	if len(s) == 0 || s[0] != "space2comment" {
		t.Errorf("Cloudflare chain = %v", s)
	}
	if len(SuggestedTamperChain("Unknown")) == 0 {
		t.Error("expected generic fallback chain")
	}
}

func TestCompareResponsesBlock(t *testing.T) {
	normal := &httpclient.Response{StatusCode: 200, Body: []byte("ok")}
	probe := &httpclient.Response{StatusCode: 403, Body: []byte("blocked")}
	w := compareResponses(normal, probe, nil)
	if w == nil {
		t.Fatal("expected generic WAF detection on block")
	}
	if w.Name != "Unknown WAF" {
		t.Errorf("name = %q", w.Name)
	}
}

func TestAllVendorsCovered(t *testing.T) {
	names := []string{
		"Cloudflare", "AWS WAF", "Akamai", "Imperva", "F5 BIG-IP", "Sucuri",
		"ModSecurity", "Barracuda", "Fortinet", "Wordfence", "Naxsi",
		"PerimeterX", "Reblaze",
	}
	// Ensure each vendor has a signature present in the signal list.
	sigNames := map[string]bool{}
	for _, s := range wafSignatures {
		sigNames[s.name] = true
	}
	for _, n := range names {
		if !sigNames[n] {
			t.Errorf("missing signature for %s", n)
		}
	}
}

func TestSignatureCount(t *testing.T) {
	if len(wafSignatures) < 13 {
		t.Errorf("expected >= 13 signatures, got %d", len(wafSignatures))
	}
}
