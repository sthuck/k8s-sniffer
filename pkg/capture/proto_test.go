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
		Snaplen:     2048,
		TLSMode:     TLSModeOff,
	}

	got := SpecFromProto(spec.ToProto())

	if got.Namespace != spec.Namespace || got.BPFFilter != spec.BPFFilter ||
		got.Duration != spec.Duration || got.Snaplen != spec.Snaplen || got.TLSMode != spec.TLSMode {
		t.Fatalf("round trip = %+v, want %+v", got, spec)
	}
	if len(got.PodPatterns) != len(spec.PodPatterns) {
		t.Fatalf("patterns = %v, want %v", got.PodPatterns, spec.PodPatterns)
	}
	for i := range spec.PodPatterns {
		if got.PodPatterns[i] != spec.PodPatterns[i] {
			t.Fatalf("patterns = %v, want %v", got.PodPatterns, spec.PodPatterns)
		}
	}
}

// The Go and wire enums must stay numerically identical, because conversion is
// a plain cast in both directions.
func TestTLSModeMatchesProtoEnum(t *testing.T) {
	pairs := map[TLSMode]snifferv1.TlsMode{
		TLSModeUnspecified: snifferv1.TlsMode_TLS_MODE_UNSPECIFIED,
		TLSModeOff:         snifferv1.TlsMode_TLS_MODE_OFF,
		TLSModeEBPF:        snifferv1.TlsMode_TLS_MODE_EBPF,
		TLSModeKeylog:      snifferv1.TlsMode_TLS_MODE_KEYLOG,
		TLSModeAuto:        snifferv1.TlsMode_TLS_MODE_AUTO,
	}
	for mode, want := range pairs {
		if int32(mode) != int32(want) {
			t.Errorf("%s = %d, want %d (%s)", mode, int32(mode), int32(want), want)
		}
	}
}

// A requested mode must survive the round trip so the hub can reject or report
// it, instead of the request looking like a plain unencrypted capture.
func TestTLSModeIsNotSilentlyDowngraded(t *testing.T) {
	for _, mode := range []TLSMode{TLSModeOff, TLSModeEBPF, TLSModeKeylog, TLSModeAuto, TLSMode(42)} {
		pb := Spec{Namespace: "prod", TLSMode: mode}.ToProto()
		if got := TLSMode(pb.GetTlsMode()); got != mode {
			t.Errorf("ToProto lost tls mode: got %d, want %d", got, mode)
		}
		if got := SpecFromProto(pb).TLSMode; got != mode {
			t.Errorf("SpecFromProto lost tls mode: got %d, want %d", got, mode)
		}
	}

	// An unimplemented mode must fail validation rather than capture encrypted
	// traffic only.
	spec := Spec{Namespace: "prod", PodPatterns: []string{"api"}, TLSMode: TLSModeEBPF}
	if err := spec.WithDefaults().Validate(); err == nil {
		t.Error("Validate() accepted an unimplemented tls mode")
	}
}

func TestToProtoOmitsZeroDuration(t *testing.T) {
	pb := Spec{Namespace: "prod", PodPatterns: []string{"api"}}.WithDefaults().ToProto()

	if pb.GetDuration() != nil {
		t.Errorf("Duration = %v, want nil for an open-ended session", pb.GetDuration())
	}
}

// Agent deployment settings must not be reachable from a client request.
func TestCaptureSpecCarriesNoAgentDeploymentSettings(t *testing.T) {
	fields := (&snifferv1.CaptureSpec{}).ProtoReflect().Descriptor().Fields()
	for i := range fields.Len() {
		switch name := string(fields.Get(i).Name()); name {
		case "agent_namespace", "agent_image", "agent_cri_socket", "agent_privileged":
			t.Errorf("CaptureSpec exposes trusted agent setting %q to clients", name)
		}
	}
}

func TestSpecFromProtoNil(t *testing.T) {
	if got := SpecFromProto(nil); got.Namespace != "" || len(got.PodPatterns) != 0 {
		t.Fatalf("SpecFromProto(nil) = %+v, want zero spec", got)
	}
}
