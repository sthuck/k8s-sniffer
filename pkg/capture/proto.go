package capture

import (
	"google.golang.org/protobuf/types/known/durationpb"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
)

// ToProto converts the spec into its wire form. The conversion is total: TLS
// mode maps numerically, so an unknown value survives to Validate instead of
// being downgraded here.
func (s Spec) ToProto() *snifferv1.CaptureSpec {
	spec := &snifferv1.CaptureSpec{
		Namespace:   s.Namespace,
		PodPatterns: append([]string(nil), s.PodPatterns...),
		BpfFilter:   s.BPFFilter,
		TlsMode:     snifferv1.TlsMode(s.TLSMode),
		Snaplen:     s.Snaplen,
	}
	if s.Duration > 0 {
		spec.Duration = durationpb.New(s.Duration)
	}
	return spec
}

// SpecFromProto rebuilds a Spec from the wire form. Sink and agent settings are
// absent by design; the caller supplies its own SinkSpec, and the hub its own
// AgentConfig.
func SpecFromProto(in *snifferv1.CaptureSpec) Spec {
	if in == nil {
		return Spec{}
	}
	spec := Spec{
		Namespace:   in.GetNamespace(),
		PodPatterns: append([]string(nil), in.GetPodPatterns()...),
		BPFFilter:   in.GetBpfFilter(),
		Snaplen:     in.GetSnaplen(),
		TLSMode:     TLSMode(in.GetTlsMode()),
	}
	if d := in.GetDuration(); d != nil {
		spec.Duration = d.AsDuration()
	}
	return spec
}
