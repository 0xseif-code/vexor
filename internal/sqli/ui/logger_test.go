package ui

import (
	"regexp"
	"strings"
	"testing"
)

func TestLoggerFormat(t *testing.T) {
	var sb strings.Builder
	SetLogger(NewLogger(&sb))
	Info("testing connection to the target URL")
	out := sb.String()
	// [HH:MM:SS] [INFO] message
	re := regexp.MustCompile(`^\[\d{2}:\d{2}:\d{2}\] \[INFO\] testing connection to the target URL\n$`)
	if !re.MatchString(out) {
		t.Fatalf("logger output %q does not match expected format", out)
	}
}

func TestLoggerLevelsEmitLabels(t *testing.T) {
	var sb strings.Builder
	SetLogger(NewLogger(&sb))
	Warning("parameter not dynamic")
	Error("boom")
	Critical("fatal")
	out := sb.String()
	for _, want := range []string{"[WARNING]", "[ERROR]", "[CRITICAL]"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing level label %s in output:\n%s", want, out)
		}
	}
}

func TestLoggerTimestampsPresent(t *testing.T) {
	var sb strings.Builder
	SetLogger(NewLogger(&sb))
	Info("x")
	if !strings.Contains(sb.String(), "[") || strings.Index(sb.String(), "]") < 8 {
		t.Fatalf("missing timestamp header in %q", sb.String())
	}
}
