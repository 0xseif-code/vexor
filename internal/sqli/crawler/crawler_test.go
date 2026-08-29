package crawler

import (
	"net/url"
	"testing"
)

func TestExtractPageLinks(t *testing.T) {
	body := []byte(`
	<html><body>
	<a href="/page1?id=1">1</a>
	<a href="mailto:x@y.com">mail</a>
	<a href="javascript:void(0)">js</a>
	<a href="#frag">frag</a>
	<script src="/static/app.js"></script>
	<link href="/style.css" rel="stylesheet">
	<iframe src="/embed/x"></iframe>
	<form action="/search" method="post">
	  <input type="hidden" name="csrf" value="abc">
	  <input type="text" name="q" value="hello">
	  <input type="password" name="pw">
	  <input type="submit" value="Go">
	  <select name="cat"><option value="1">One</option></select>
	  <textarea name="note">note</textarea>
	</form>
	</body></html>`)
	links, forms := extractPage(body, "http://example.com/")
	if len(links) == 0 {
		t.Fatal("expected links")
	}
	for _, l := range links {
		if l == "javascript:void(0)" || l == "mailto:x@y.com" || l == "#frag" {
			t.Errorf("should have filtered %q", l)
		}
	}
	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}
	f := forms[0]
	if f.action != "/search" {
		t.Errorf("form action = %q", f.action)
	}
	if f.method != "POST" {
		t.Errorf("form method = %q", f.method)
	}
	if v, ok := f.fields["q"]; !ok || v != "hello" {
		t.Errorf("field q = %v", f.fields["q"])
	}
	if _, ok := f.fields["submit"]; ok {
		t.Error("submit input should be excluded")
	}
	if v, ok := f.fields["pw"]; !ok || v != "FUZZ_pw" {
		t.Errorf("password field should be fuzzed: %v", f.fields)
	}
	if v, ok := f.fields["cat"]; !ok || v != "1" {
		t.Errorf("select field = %v", f.fields["cat"])
	}
}

func TestParseRobots(t *testing.T) {
	body := `User-agent: *
Disallow: /admin
Disallow: /private # comment
Allow: /public
`
	d := parseRobots(body)
	if len(d) != 2 {
		t.Fatalf("expected 2 disallow rules, got %v", d)
	}
	if d[0] != "/admin" {
		t.Errorf("first disallow = %q", d[0])
	}
	if d[1] != "/private" {
		t.Errorf("second disallow = %q", d[1])
	}
}

func TestRobotsDisallowsAll(t *testing.T) {
	if !robotsDisallowsAll([]string{"/"}) {
		t.Error("expected '/' to mean disallow all")
	}
	if robotsDisallowsAll([]string{"/admin"}) {
		t.Error("'/admin' should not mean disallow all")
	}
}

func TestCollectParams(t *testing.T) {
	params := collectParams("id=1&name=abc&")
	if len(params) != 2 || params[0] != "id" || params[1] != "name" {
		t.Errorf("collectParams = %v", params)
	}
}

func TestResolveURL(t *testing.T) {
	base, _ := url.Parse("http://example.com/a/b")
	cases := map[string]string{
		"/x?id=1":         "http://example.com/x?id=1",
		"../y":            "http://example.com/y",
		"https://o.com/z": "https://o.com/z",
		"//cdn.net/f":     "http://cdn.net/f",
	}
	for in, want := range cases {
		got := resolveURL(base, in)
		if got != want {
			t.Errorf("resolveURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParamLessKey(t *testing.T) {
	if got := paramLessKey("http://x.com/?page=2"); got != "http://x.com/" {
		t.Errorf("paramLessKey = %q", got)
	}
}

func TestNewDefaults(t *testing.T) {
	// Defaults applied without a client (client may be nil in pure tests).
	c := New(Config{StartURL: "http://example.com/", SameDomainOnly: true}, nil)
	if c.cfg.MaxDepth != 2 {
		t.Errorf("MaxDepth default = %d", c.cfg.MaxDepth)
	}
	if !c.cfg.SameDomainOnly {
		t.Error("SameDomainOnly should default true")
	}
}
