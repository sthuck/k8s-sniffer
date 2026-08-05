package capture

import (
	"testing"
	"time"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
)

func TestSpecProtoRoundTrip(t *testing.T) {
	spec := Spec{
		Namespace:   "prod",
		PodPatterns: []string{"payments-.*", "checkout-.*"},
		BPFFilter:   "tcp port 8080",
		Duration:    90 * time.Second,
		Out:         "session.pcapng",
		Snaplen:     2048,
		Agent: AgentConfig{
			Namespace: "k8s-sniffer",
			Image:     "example.com/agent:v1",
			CRISocket: DefaultCRISocket,
		},
	}

	got := SpecFromProto(spec.ToProto())

	// Out is client-side state and must not survive the round trip.
	want := spec
	want.Out = ""
	if got.Namespace != want.Namespace || got.BPFFilter != want.BPFFilter ||
		got.Duration != want.Duration || got.Snaplen != want.Snaplen || got.Agent != want.Agent {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
	if len(got.PodPatterns) != len(want.PodPatterns) {
		t.Fatalf("patterns = %v, want %v", got.PodPatterns, want.PodPatterns)
	}
	for i := range want.PodPatterns {
		if got.PodPatterns[i] != want.PodPatterns[i] {
			t.Fatalf("patterns = %v, want %v", got.PodPatterns, want.PodPatterns)
		}
	}
	if got.Out != "" {
		t.Errorf("Out = %q, want empty after round trip", got.Out)
	}
}

func TestToProtoOmitsZeroDurationAndForcesTLSOff(t *testing.T) {
	pb := Spec{Namespace: "prod", PodPatterns: []string{"api"}}.WithDefaults().ToProto()

	if pb.GetDuration() != nil {
		t.Errorf("Duration = %v, want nil for an open-ended session", pb.GetDuration())
	}
	if pb.GetTlsMode() != snifferv1.TlsMode_TLS_MODE_OFF {
		t.Errorf("TlsMode = %v, want TLS_MODE_OFF in phase 1", pb.GetTlsMode())
	}
}

func TestPrivilegedRoundTrip(t *testing.T) {
	unprivileged := Spec{Agent: AgentConfig{Unprivileged: true}}
	if got := SpecFromProto(unprivileged.ToProto()); !got.Agent.Unprivileged {
		t.Error("unprivileged opt-out lost on round trip")
	}
	if got := SpecFromProto(Spec{}.ToProto()); got.Agent.Unprivileged {
		t.Error("default spec became unprivileged on round trip")
	}
	// A client that omits the field entirely must still get privileged agents.
	if got := SpecFromProto(&snifferv1.CaptureSpec{Namespace: "prod"}); !got.Agent.Privileged() {
		t.Error("absent agent_privileged should mean privileged")
	}
}

func TestSpecFromProtoNil(t *testing.T) {
	if got := SpecFromProto(nil); got.Namespace != "" || len(got.PodPatterns) != 0 {
		t.Fatalf("SpecFromProto(nil) = %+v, want zero spec", got)
	}
}
