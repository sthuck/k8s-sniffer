package log

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in    string
		want  Level
		isErr bool
	}{
		{"", LevelInfo, false},
		{"info", LevelInfo, false},
		{"INFO", LevelInfo, false},
		{"debug", LevelDebug, false},
		{"trace", "", true},
	}
	for _, tc := range tests {
		got, err := ParseLevel(tc.in)
		if tc.isErr {
			if err == nil {
				t.Errorf("ParseLevel(%q): want error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseLevel(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("ParseLevel(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestInitSuppressesDebugAtInfo(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	Init(Config{Level: LevelInfo, Writer: &buf})
	log := WithComponent("test")
	log.Debug("hidden")
	log.Info("visible")
	if strings.Contains(buf.String(), "hidden") {
		t.Fatal("debug log should be suppressed at info level")
	}
	if !strings.Contains(buf.String(), "visible") {
		t.Fatalf("info log missing: %q", buf.String())
	}
}

func TestInitShowsDebugAtDebug(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	Init(Config{Level: LevelDebug, Writer: &buf})
	WithComponent("test").Debug("detail")
	if !strings.Contains(buf.String(), "detail") {
		t.Fatalf("debug log missing: %q", buf.String())
	}
}

func TestResolveLevel(t *testing.T) {
	t.Parallel()
	got, err := ResolveLevel("debug", "info")
	if err != nil || got != LevelDebug {
		t.Fatalf("ResolveLevel(flag) = %q, %v", got, err)
	}
	got, err = ResolveLevel("", "debug")
	if err != nil || got != LevelDebug {
		t.Fatalf("ResolveLevel(env) = %q, %v", got, err)
	}
}

func TestWithComponent(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	Init(Config{Level: LevelInfo, Writer: &buf})
	WithComponent("hub").Info("started")
	if !strings.Contains(buf.String(), "component=hub") {
		t.Fatalf("component attr missing: %q", buf.String())
	}
}

func TestDefaultBeforeInit(t *testing.T) {
	t.Parallel()
	if Default() != slog.Default() {
		t.Fatal("Default should return slog.Default")
	}
}
