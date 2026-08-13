package tlsworker

import (
	"strings"
	"testing"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
)

func TestParseTextStream(t *testing.T) {
	input := `PID:1234, Comm:openssl, TID:1234, Version:TLS1.2, Tuple:10.0.0.1:443-10.0.0.2:12345, Topic:OpenSSL, Payload:
GET /e2e-secret-token HTTP/1.1
Host: https-openssl

PID:1234, Comm:openssl, Received 12 bytes, Payload:
HTTP/1.1 200
`
	ch := make(chan parsedEvent, 8)
	go func() {
		parseStream(strings.NewReader(input), ch)
		close(ch)
	}()
	var got []parsedEvent
	for ev := range ch {
		got = append(got, ev)
	}
	if len(got) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(got), got)
	}
	if !strings.Contains(string(got[0].Payload), "e2e-secret-token") {
		t.Fatalf("payload = %q", got[0].Payload)
	}
	if got[0].PID != 1234 || got[0].Process != "openssl" {
		t.Fatalf("header = pid %d comm %s", got[0].PID, got[0].Process)
	}
	if got[1].Direction != snifferv1.Direction_DIRECTION_INBOUND {
		t.Fatalf("direction = %s, want inbound", got[1].Direction)
	}
}

func TestParseJSONLine(t *testing.T) {
	line := `{"pid":99,"Comm":"nginx","payload":"POST /e2e-secret-token","eventType":0}`
	ev, ok := parseJSONLine(line)
	if !ok {
		t.Fatal("expected json event")
	}
	if ev.PID != 99 || string(ev.Payload) != "POST /e2e-secret-token" {
		t.Fatalf("ev = %+v", ev)
	}
	if ev.Direction != snifferv1.Direction_DIRECTION_OUTBOUND {
		t.Fatalf("direction = %s", ev.Direction)
	}
}

func TestPIDFromNetnsPath(t *testing.T) {
	if got := PIDFromNetnsPath("/proc/12345/ns/net"); got != 12345 {
		t.Fatalf("got %d", got)
	}
	if got := PIDFromNetnsPath("/var/run/netns/foo"); got != 0 {
		t.Fatalf("got %d", got)
	}
}

func TestPidsSharingNetnsIncludesSelf(t *testing.T) {
	pids := pidsSharingNetns(1)
	if len(pids) == 0 {
		t.Fatal("expected at least pid 1")
	}
	found := false
	for _, p := range pids {
		if p == 1 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("pids = %v, missing 1", pids)
	}
}

func TestClassifyExecError(t *testing.T) {
	if got := classifyExecError(snifferv1.TlsMode_TLS_MODE_EBPF, errString("permission denied: bpf")); got != snifferv1.TlsStatus_TLS_STATUS_DENIED {
		t.Fatalf("got %s", got)
	}
	if got := classifyExecError(snifferv1.TlsMode_TLS_MODE_AUTO, errString("permission denied")); got != snifferv1.TlsStatus_TLS_STATUS_FALLBACK {
		t.Fatalf("got %s", got)
	}
	if got := classifyExecError(snifferv1.TlsMode_TLS_MODE_AUTO, errString("libssl not found")); got != snifferv1.TlsStatus_TLS_STATUS_FALLBACK {
		t.Fatalf("got %s", got)
	}
}

type errString string

func (e errString) Error() string { return string(e) }
