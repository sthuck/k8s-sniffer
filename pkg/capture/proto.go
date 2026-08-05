package capture

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
)

// ToProto converts the spec into its wire form. Out is intentionally dropped:
// sinks belong to whoever subscribes to the session, not to the hub.
func (s Spec) ToProto() *snifferv1.CaptureSpec {
	spec := &snifferv1.CaptureSpec{
		Namespace:   s.Namespace,
		PodPatterns: append([]string(nil), s.PodPatterns...),
		BpfFilter:   s.BPFFilter,
		// Phase 1 captures wire traffic only; T3.1 plumbs the real mode here.
		TlsMode:         snifferv1.TlsMode_TLS_MODE_OFF,
		Snaplen:         s.Snaplen,
		AgentNamespace:  s.Agent.Namespace,
		AgentImage:      s.Agent.Image,
		AgentCriSocket:  s.Agent.CRISocket,
		AgentPrivileged: proto.Bool(s.Agent.Privileged()),
	}
	if s.Duration > 0 {
		spec.Duration = durationpb.New(s.Duration)
	}
	return spec
}

// SpecFromProto rebuilds a Spec from the wire form. Out is left to the caller
// (the client owns its sink).
func SpecFromProto(in *snifferv1.CaptureSpec) Spec {
	if in == nil {
		return Spec{}
	}
	spec := Spec{
		Namespace:   in.GetNamespace(),
		PodPatterns: append([]string(nil), in.GetPodPatterns()...),
		BPFFilter:   in.GetBpfFilter(),
		Snaplen:     in.GetSnaplen(),
		Agent: AgentConfig{
			Namespace: in.GetAgentNamespace(),
			Image:     in.GetAgentImage(),
			CRISocket: in.GetAgentCriSocket(),
			// Absent means "hub default", i.e. privileged.
			Unprivileged: in.AgentPrivileged != nil && !in.GetAgentPrivileged(),
		},
	}
	if d := in.GetDuration(); d != nil {
		spec.Duration = d.AsDuration()
	}
	return spec
}
