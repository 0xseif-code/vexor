package injection

import (
	"errors"
	"strings"
	"testing"
)

func TestTemplateMarkers(t *testing.T) {
	tpl := NewTemplate("/search?q=hello*&x=1")
	if !tpl.HasMarkers() {
		t.Fatal("expected markers")
	}
	got := tpl.Render(0, "' OR 1=1-- -")
	want := "/search?q=hello' OR 1=1-- -&x=1"
	if got != want {
		t.Fatalf("Render(0) = %q, want %q", got, want)
	}
	if empty := tpl.RenderAllEmpty(); empty != "/search?q=hello&x=1" {
		t.Fatalf("RenderAllEmpty = %q", empty)
	}
}

func TestEnumerateGET(t *testing.T) {
	src := RequestSource{
		Method: "GET",
		URL:    "http://x.test/items?id=1&tag=a&b",
	}
	pts, err := Enumerate(src, Options{Level: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(pts) != 3 {
		t.Fatalf("points = %d, want 3", len(pts))
	}
	if pts[0].Name != "id" || pts[0].Type != TypeGET {
		t.Fatalf("first point = %s/%s", pts[0].Type, pts[0].Name)
	}
	// Rendering the first point must replace only the id value.
	rr := pts[0].Render("1 AND 1=1")
	if !strings.Contains(rr.URL, "id=1%20AND%201%3D1") {
		t.Fatalf("render URL = %q", rr.URL)
	}
	if strings.Contains(rr.URL, "tag=") && !strings.Contains(rr.URL, "tag=a") {
		t.Fatalf("other param corrupted: %q", rr.URL)
	}
	base := pts[0].RenderBase()
	if base.URL != src.URL {
		t.Fatalf("base URL = %q, want %q", base.URL, src.URL)
	}
}

func TestEnumerateNoPoints(t *testing.T) {
	src := RequestSource{Method: "GET", URL: "http://x.test/static/page.html"}
	_, err := Enumerate(src, Options{Level: 1})
	if !errors.Is(err, ErrNoInjectionPoints) {
		t.Fatalf("err = %v, want ErrNoInjectionPoints", err)
	}
}

func TestEnumerateMarkersOnly(t *testing.T) {
	src := RequestSource{
		Method: "GET",
		URL:    "http://x.test/q?a=1*&b=2*",
	}
	pts, err := Enumerate(src, Options{Level: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(pts) != 2 {
		t.Fatalf("marker points = %d, want 2", len(pts))
	}
	if pts[0].Type != TypeMarker {
		t.Fatalf("point type = %s, want MARKER", pts[0].Type)
	}
	rr := pts[0].Render("' UNION SELECT 1-- -")
	if !strings.Contains(rr.URL, "UNION%20SELECT") {
		t.Fatalf("payload not injected: %q", rr.URL)
	}
	if strings.Contains(rr.URL, "*") {
		t.Fatalf("other marker not emptied: %q", rr.URL)
	}
}

func TestEnumerateJSON(t *testing.T) {
	src := RequestSource{
		Method:  "POST",
		URL:     "http://x.test/order",
		Headers: []Header{{Key: "Content-Type", Value: "application/json"}},
		Body:    []byte(`{"query":{"id":5,"name":"socks"},"status":"new"}`),
	}
	pts, err := Enumerate(src, Options{Level: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(pts) != 3 {
		t.Fatalf("json points = %d, want 3", len(pts))
	}
	names := map[string]bool{}
	for _, p := range pts {
		names[p.Name] = true
	}
	if !names["query.id"] || !names["query.name"] || !names["status"] {
		t.Fatalf("names = %v", names)
	}
	// Replacing the name value must keep the JSON valid.
	var namePt *InjectionPoint
	for _, p := range pts {
		if p.Name == "query.name" {
			namePt = p
		}
	}
	rr := namePt.Render(`socks' AND '1'='1`)
	json := string(rr.Body)
	if !strings.Contains(json, `"name":"socks' AND '1'='1"`) {
		t.Fatalf("json body = %s", json)
	}
}

func TestEnumerateXML(t *testing.T) {
	src := RequestSource{
		Method:  "POST",
		URL:     "http://x.test/rpc",
		Headers: []Header{{Key: "Content-Type", Value: "text/xml"}},
		Body:    []byte(`<op name="sum"><a>1</a><b>2</b></op>`),
	}
	pts, err := Enumerate(src, Options{Level: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(pts) != 3 {
		t.Fatalf("xml points = %d, want 3 (attr + 2 texts)", len(pts))
	}
	// attribute point must splice inside quotes.
	var attrPt, aPt *InjectionPoint
	for _, p := range pts {
		switch p.Name {
		case "name":
			attrPt = p
		case "a":
			aPt = p
		}
	}
	if attrPt == nil || aPt == nil {
		t.Fatalf("missing expected points: %+v", pts)
	}
	rr := attrPt.Render("sum' and '1'='1")
	if !strings.Contains(string(rr.Body), `name="sum' and '1'='1"`) {
		t.Fatalf("attr body = %s", rr.Body)
	}
	rrA := aPt.Render("' OR 1=1-- -")
	if !strings.Contains(string(rrA.Body), "<a>' OR 1=1-- -</a>") {
		t.Fatalf("element body = %s", rrA.Body)
	}
}

func TestEnumerateCookiesAndHeaders(t *testing.T) {
	src := RequestSource{
		Method:  "GET",
		URL:     "http://x.test/dash?x=1",
		Headers: []Header{{Key: "Cookie", Value: "sid=abc; lang=en"}},
	}
	// Level 1: no cookie/header points.
	pts, _ := Enumerate(src, Options{Level: 1})
	for _, p := range pts {
		if p.Type == TypeCookie || p.Type == TypeHeader {
			t.Fatalf("level 1 should not include %s points", p.Type)
		}
	}
	// Level 2: cookies appear.
	pts2, _ := Enumerate(src, Options{Level: 2})
	foundCookie := false
	for _, p := range pts2 {
		if p.Type == TypeCookie && p.Name == "sid" {
			foundCookie = true
			rr := p.Render("pwned")
			if !strings.Contains(rr.Headers["Cookie"], "sid=pwned") {
				t.Fatalf("cookie render = %q", rr.Headers["Cookie"])
			}
		}
	}
	if !foundCookie {
		t.Fatal("cookie point missing at level 2")
	}
	// Level 3: headers too.
	pts3, _ := Enumerate(src, Options{Level: 3})
	foundHeader := false
	for _, p := range pts3 {
		if p.Type == TypeHeader && p.Name == "User-Agent" {
			foundHeader = true
		}
	}
	if !foundHeader {
		t.Fatal("header point missing at level 3")
	}
}

func TestParseRaw(t *testing.T) {
	raw := "POST /api/login HTTP/1.1\r\nHost: t.test\r\nContent-Type: application/json\r\nContent-Length: 12\r\n\r\n{\"u\":\"a\"}"
	rr, err := ParseRaw([]byte(raw), false)
	if err != nil {
		t.Fatal(err)
	}
	if rr.Method != "POST" || rr.Target != "/api/login" {
		t.Fatalf("request line parsed wrong: %+v", rr)
	}
	if rr.AbsoluteURL(false) != "http://t.test/api/login" {
		t.Fatalf("abs url = %s", rr.AbsoluteURL(false))
	}
	for _, h := range rr.Headers {
		if h.Key == "Content-Length" {
			t.Fatal("Content-Length should be dropped")
		}
	}
	if string(rr.Body) != `{"u":"a"}` {
		t.Fatalf("body = %q", rr.Body)
	}
}

func TestParseRawMalformedLineNumber(t *testing.T) {
	raw := "GET / HTTP/1.1\nHost: t.test\nBadHeaderNoColon\n\nbody text\n"
	_, err := ParseRaw([]byte(raw), false)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("err should mention line 3, got %v", err)
	}
}

func TestEncoding(t *testing.T) {
	if got := encQuery("a b&c=d#e+f"); got != "a%20b%26c%3Dd%23e%2Bf" {
		t.Fatalf("encQuery = %q", got)
	}
	if got := encForm("a b&c=d"); got != "a+b%26c%3Dd" {
		t.Fatalf("encForm = %q", got)
	}
	if got := encHeader("x\ry\n"); got != "x%0Dy%0A" {
		t.Fatalf("encHeader = %q", got)
	}
	if got := encCookie("a b;c"); got != "a%20b%3Bc" {
		t.Fatalf("encCookie = %q", got)
	}
}
