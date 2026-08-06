package capture

import (
	"strings"
	"testing"
)

func TestTcpdumpCommandArgsTerminateOptionsBeforeFilter(t *testing.T) {
	args, err := (&Tcpdump{TcpdumpPath: "/usr/bin/tcpdump"}).commandArgs(
		"/proc/123/ns/net",
		65535,
		"tcp port 8080",
		nil,
	)
	if err != nil {
		t.Fatalf("commandArgs: %v", err)
	}
	got := strings.Join(args, "|")
	if !strings.Contains(got, "|--|tcp port 8080") {
		t.Fatalf("args do not terminate options before filter: %v", args)
	}
}

func TestTcpdumpCommandArgsRejectOptionLikeFilter(t *testing.T) {
	if _, err := (&Tcpdump{}).commandArgs("/proc/123/ns/net", 65535, "-r /host/file", nil); err == nil {
		t.Fatal("expected option-like filter to be rejected")
	}
}

func TestCappedBufferTruncates(t *testing.T) {
	buf := &cappedBuffer{remaining: 4}
	if _, err := buf.Write([]byte("abcdef")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := buf.String(); got != "abcd\n[stderr truncated]" {
		t.Fatalf("String() = %q", got)
	}
}
