package tlsworker

import (
	"context"
	"strings"
	"testing"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
)

func TestWantsAttach(t *testing.T) {
	if WantsAttach(snifferv1.TlsMode_TLS_MODE_OFF) || WantsAttach(snifferv1.TlsMode_TLS_MODE_UNSPECIFIED) {
		t.Fatal("off/unspecified should not attach")
	}
	if !WantsAttach(snifferv1.TlsMode_TLS_MODE_AUTO) || !WantsAttach(snifferv1.TlsMode_TLS_MODE_EBPF) || !WantsAttach(snifferv1.TlsMode_TLS_MODE_KEYLOG) {
		t.Fatal("auto/ebpf/keylog should attach")
	}
}

func TestECaptureKeylogReportsFallback(t *testing.T) {
	events, statuses, err := (ECapture{}).Attach(context.Background(), Target{
		Mode:      snifferv1.TlsMode_TLS_MODE_KEYLOG,
		SessionID: "s1",
	})
	if err != nil {
		t.Fatal(err)
	}
	st := <-statuses
	if st.Status != snifferv1.TlsStatus_TLS_STATUS_FALLBACK {
		t.Fatalf("status = %s, want FALLBACK", st.Status)
	}
	if _, ok := <-events; ok {
		t.Fatal("expected no events")
	}
}

func TestECaptureMissingBinary(t *testing.T) {
	e := ECapture{Binary: "ecapture-not-installed-for-unit-test"}
	_, statuses, err := e.Attach(context.Background(), Target{
		PID:  1,
		Mode: snifferv1.TlsMode_TLS_MODE_AUTO,
	})
	if err != nil {
		t.Fatal(err)
	}
	st := <-statuses
	if st.Status != snifferv1.TlsStatus_TLS_STATUS_FALLBACK {
		t.Fatalf("status = %s (%s), want FALLBACK", st.Status, st.Detail)
	}
	if !strings.Contains(st.Detail, "not found") {
		t.Fatalf("detail = %q", st.Detail)
	}
}

func TestECaptureUnknownPID(t *testing.T) {
	e := ECapture{Binary: "true"}
	_, statuses, err := e.Attach(context.Background(), Target{
		PID:  0,
		Mode: snifferv1.TlsMode_TLS_MODE_EBPF,
	})
	if err != nil {
		t.Fatal(err)
	}
	st := <-statuses
	if st.Status != snifferv1.TlsStatus_TLS_STATUS_UNSUPPORTED {
		t.Fatalf("status = %s, want UNSUPPORTED", st.Status)
	}
}
