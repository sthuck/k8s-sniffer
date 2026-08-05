// Package capture holds the types shared by the CLI, hub and agent: the capture
// request (Spec), the client's sink configuration (SinkSpec), the hub's trusted
// agent deployment configuration (AgentConfig), and their validation rules. It
// must stay free of Kubernetes client or gRPC server logic so every component
// can depend on it.
//
// The three types are separate on purpose. Spec is what a client may ask for
// and is the only one that crosses the hub API; SinkSpec never leaves the
// client; AgentConfig never comes from a client, because agents run privileged
// on nodes.
package capture

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
)

// Defaults locked by T0.3: agents live in their own namespace, run privileged,
// and resolve netns through the containerd CRI socket.
const (
	DefaultAgentNamespace = "k8s-sniffer"
	// DefaultCRISocketPath is a node filesystem path, not a dial URI: it is the
	// hostPath volume source mounted into the agent (T1.6). Use
	// AgentConfig.CRIEndpoint for the URI a CRI client dials.
	DefaultCRISocketPath = "/run/containerd/containerd.sock"

	// DefaultSnaplen matches tcpdump's modern default (whole packet).
	DefaultSnaplen uint32 = 262144
	// MinSnaplen keeps enough bytes for L2..L4 headers to stay parseable.
	MinSnaplen uint32 = 64
)

// StdoutSink is the Out value that makes the client stream PCAP to stdout.
const StdoutSink = "-"

// agentImageRef is injected at link time with the digest-pinned agent image
// published for a release:
//
//	-ldflags '-X github.com/sthuck/k8s-sniffer/pkg/capture.agentImageRef=REF'
//
// It is empty in development builds, which forces an explicit --agent-image
// rather than defaulting to a mutable tag. See AgentConfig.Image.
var agentImageRef string

// DefaultAgentImage returns the release-pinned agent image, or "" in builds
// that were not given one.
func DefaultAgentImage() string { return agentImageRef }

// TLSMode mirrors sniffer.v1.TlsMode numerically, so conversion to and from the
// wire form is lossless and no unknown value can be silently downgraded.
type TLSMode int32

const (
	TLSModeUnspecified TLSMode = 0
	TLSModeOff         TLSMode = 1
	TLSModeEBPF        TLSMode = 2
	TLSModeKeylog      TLSMode = 3
	TLSModeAuto        TLSMode = 4
)

var tlsModeNames = map[TLSMode]string{
	TLSModeUnspecified: "unspecified",
	TLSModeOff:         "off",
	TLSModeEBPF:        "ebpf",
	TLSModeKeylog:      "keylog",
	TLSModeAuto:        "auto",
}

func (m TLSMode) String() string {
	if name, ok := tlsModeNames[m]; ok {
		return name
	}
	return fmt.Sprintf("TLSMode(%d)", int32(m))
}

// Known reports whether the mode names a real mode this build understands.
// TLSModeUnspecified is not a mode: it means "apply the default".
func (m TLSMode) Known() bool {
	_, ok := tlsModeNames[m]
	return ok && m != TLSModeUnspecified
}

// Implemented reports whether the mode can actually be honoured. Until T3.1
// only "off" can; other modes are rejected instead of degrading a session to an
// encrypted-only capture the user did not ask for.
func (m TLSMode) Implemented() bool { return m == TLSModeOff }

// ParseTLSMode maps a CLI-style name to a mode. T3.1 wires this to a flag.
func ParseTLSMode(name string) (TLSMode, error) {
	for mode, modeName := range tlsModeNames {
		if mode != TLSModeUnspecified && modeName == name {
			return mode, nil
		}
	}
	return TLSModeUnspecified, fmt.Errorf("unknown tls mode %q (want off, ebpf, keylog or auto)", name)
}

// Spec is the CaptureSpec from the architecture doc: what to capture. It holds
// no client sink and no agent deployment settings, so a hub can validate it
// exactly as received from an untrusted client.
type Spec struct {
	// Namespace of the pods to capture (required).
	Namespace string
	// PodPatterns are RE2 patterns matched (unanchored) against pod names. A
	// pod is selected when any pattern matches. At least one is required.
	PodPatterns []string
	// BPFFilter is a tcpdump-syntax capture filter applied in every target
	// netns. Not validated locally: only tcpdump can compile it.
	BPFFilter string
	// Duration is a hard stop for the session. Zero means run until stopped.
	Duration time.Duration
	// Snaplen is the per-packet capture length; zero means DefaultSnaplen.
	Snaplen uint32
	// TLSMode requests TLS handling; zero value means the build default.
	TLSMode TLSMode
}

// WithDefaults returns a copy of s with unset optional fields filled in.
func (s Spec) WithDefaults() Spec {
	out := s
	if out.Snaplen == 0 {
		out.Snaplen = DefaultSnaplen
	}
	if out.TLSMode == TLSModeUnspecified {
		out.TLSMode = TLSModeOff
	}
	return out
}

// Validate reports every problem with the spec at once so a CLI user does not
// have to fix flags one at a time. Defaults are not applied: call WithDefaults
// first if the spec comes straight from flags or off the wire.
func (s Spec) Validate() error {
	var errs []error

	if s.Namespace == "" {
		errs = append(errs, errors.New("namespace: required"))
	} else if msgs := validation.IsDNS1123Label(s.Namespace); len(msgs) > 0 {
		errs = append(errs, fmt.Errorf("namespace: invalid %q: %s", s.Namespace, msgs[0]))
	}

	if len(s.PodPatterns) == 0 {
		errs = append(errs, errors.New("pod patterns: at least one required"))
	}
	for i, pattern := range s.PodPatterns {
		if pattern == "" {
			errs = append(errs, fmt.Errorf("pod patterns[%d]: empty", i))
			continue
		}
		if _, err := regexp.Compile(pattern); err != nil {
			errs = append(errs, fmt.Errorf("pod patterns[%d]: %w", i, err))
		}
	}

	if s.Duration < 0 {
		errs = append(errs, fmt.Errorf("duration: must not be negative, got %s", s.Duration))
	}

	if s.Snaplen != 0 && s.Snaplen < MinSnaplen {
		errs = append(errs, fmt.Errorf("snaplen: must be 0 or >= %d, got %d", MinSnaplen, s.Snaplen))
	}

	switch {
	case s.TLSMode == TLSModeUnspecified:
		errs = append(errs, errors.New("tls mode: unset (apply WithDefaults before validating)"))
	case !s.TLSMode.Known():
		errs = append(errs, fmt.Errorf("tls mode: unknown value %d", int32(s.TLSMode)))
	case !s.TLSMode.Implemented():
		errs = append(errs, fmt.Errorf("tls mode: %s is not implemented yet (T3.1); only off is supported", s.TLSMode))
	}

	return errors.Join(errs...)
}

// CompilePatterns compiles PodPatterns in order. The pod matcher (T1.4) uses
// the result; callers should treat a non-nil error as a spec error.
func (s Spec) CompilePatterns() ([]*regexp.Regexp, error) {
	compiled := make([]*regexp.Regexp, 0, len(s.PodPatterns))
	for i, pattern := range s.PodPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("pod patterns[%d]: %w", i, err)
		}
		compiled = append(compiled, re)
	}
	return compiled, nil
}

// SinkSpec is client-side output configuration. It is deliberately not part of
// Spec: it never crosses the hub API, because a hub must not write files on a
// client's behalf.
type SinkSpec struct {
	// Out is a file path or StdoutSink.
	Out string
}

// WithDefaults returns a copy with unset fields filled in.
func (s SinkSpec) WithDefaults() SinkSpec {
	out := s
	if out.Out == "" {
		out.Out = StdoutSink
	}
	return out
}

func (s SinkSpec) Validate() error {
	if s.Out == "" {
		return errors.New("out: required (path or \"-\")")
	}
	return nil
}

// IsStdout reports whether the sink streams to stdout.
func (s SinkSpec) IsStdout() bool { return s.Out == StdoutSink }

// AgentConfig is trusted hub-side configuration for the ephemeral agent pods.
// It comes from operator configuration (or CLI flags when the user runs the hub
// in-process with their own credentials), never from a session request: agents
// run privileged with host and CRI access.
type AgentConfig struct {
	// Namespace the agent pods are created in.
	Namespace string
	// Image reference for the agent container. Must be digest-pinned unless
	// AllowMutableImage is set, so a privileged node agent cannot change code
	// underneath the operator when a tag is overwritten.
	Image string
	// CRISocketHostPath is the absolute node path of the CRI socket, used as
	// the hostPath volume source (T1.6).
	CRISocketHostPath string
	// Unprivileged drops securityContext.privileged from the agent pod, which
	// then needs the capability set documented in ARCHITECTURE.md §5.3. Stated
	// negatively so the zero value keeps the T0.3 default (privileged) and
	// defaulting never has to distinguish "unset" from "explicitly off".
	Unprivileged bool
	// AllowMutableImage permits a tag-based image reference. Development and
	// e2e flows (which load a locally built image into kind) set it explicitly.
	AllowMutableImage bool
	// HubIngestAddr is the gRPC dial target agents use for AgentIngestService
	// (host:port, no scheme). Required when scheduling agent pods.
	HubIngestAddr string
}

// Privileged reports whether the agent container should run privileged.
func (c AgentConfig) Privileged() bool { return !c.Unprivileged }

// CRIEndpoint returns the URI a CRI client dials for the mounted socket. The
// path is mounted at the same location inside the agent, so host path and
// in-container path coincide.
func (c AgentConfig) CRIEndpoint() string {
	if c.CRISocketHostPath == "" {
		return ""
	}
	return "unix://" + c.CRISocketHostPath
}

// DefaultAgentConfig returns the T0.3 defaults. Image is only populated in
// builds that were given a release image; see DefaultAgentImage.
func DefaultAgentConfig() AgentConfig {
	return AgentConfig{
		Namespace:         DefaultAgentNamespace,
		Image:             DefaultAgentImage(),
		CRISocketHostPath: DefaultCRISocketPath,
	}
}

// WithDefaults returns a copy of c with unset fields filled in.
func (c AgentConfig) WithDefaults() AgentConfig {
	out := c
	defaults := DefaultAgentConfig()
	if out.Namespace == "" {
		out.Namespace = defaults.Namespace
	}
	if out.Image == "" {
		out.Image = defaults.Image
	}
	if out.CRISocketHostPath == "" {
		out.CRISocketHostPath = defaults.CRISocketHostPath
	}
	return out
}

func (c AgentConfig) Validate() error {
	return errors.Join(c.validate()...)
}

func (c AgentConfig) validate() []error {
	var errs []error

	if c.Namespace == "" {
		errs = append(errs, errors.New("agent namespace: required"))
	} else if msgs := validation.IsDNS1123Label(c.Namespace); len(msgs) > 0 {
		errs = append(errs, fmt.Errorf("agent namespace: invalid %q: %s", c.Namespace, msgs[0]))
	}

	switch {
	case c.Image == "":
		errs = append(errs, errors.New("agent image: required (this build has no release image pinned; pass one explicitly)"))
	case !c.AllowMutableImage && !IsDigestPinned(c.Image):
		errs = append(errs, fmt.Errorf("agent image: %q is not digest-pinned; privileged agents require an immutable reference (set AllowMutableImage for development)", c.Image))
	}

	if c.CRISocketHostPath == "" {
		errs = append(errs, errors.New("agent cri socket host path: required"))
	} else if strings.Contains(c.CRISocketHostPath, "://") {
		errs = append(errs, fmt.Errorf("agent cri socket host path: %q is a URI, want an absolute node path such as %s", c.CRISocketHostPath, DefaultCRISocketPath))
	} else if !filepath.IsAbs(c.CRISocketHostPath) {
		errs = append(errs, fmt.Errorf("agent cri socket host path: %q must be absolute", c.CRISocketHostPath))
	}

	return errs
}

// IsDigestPinned reports whether an image reference names an immutable digest
// rather than a tag.
func IsDigestPinned(ref string) bool {
	at := strings.LastIndex(ref, "@")
	if at <= 0 {
		return false
	}
	algo, hex, ok := strings.Cut(ref[at+1:], ":")
	return ok && algo != "" && hex != ""
}
