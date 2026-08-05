// Package capture holds the types shared by the CLI, hub and agent: the
// capture request (Spec) and its validation rules. It must stay free of
// Kubernetes client or gRPC server logic so every component can depend on it.
package capture

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
)

// Defaults locked by T0.3: agents live in their own namespace, run privileged,
// and resolve netns through the containerd CRI socket.
const (
	DefaultAgentNamespace = "k8s-sniffer"
	DefaultAgentImage     = "ghcr.io/sthuck/k8s-sniffer-agent:dev"
	DefaultCRISocket      = "unix:///run/containerd/containerd.sock"

	// DefaultSnaplen matches tcpdump's modern default (whole packet).
	DefaultSnaplen uint32 = 262144
	// MinSnaplen keeps enough bytes for L2..L4 headers to stay parseable.
	MinSnaplen uint32 = 64
)

// StdoutSink is the Out value that makes the client stream PCAP to stdout.
const StdoutSink = "-"

// Spec is the CaptureSpec from the architecture doc: everything needed to run
// one capture session. Out is client-side only and is not sent to the hub.
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
	// Out is a file path or StdoutSink.
	Out string
	// Snaplen is the per-packet capture length; zero means DefaultSnaplen.
	Snaplen uint32
	// Agent configures the ephemeral per-node agent pods.
	Agent AgentConfig
}

// AgentConfig carries the knobs the hub needs to schedule agent pods.
type AgentConfig struct {
	// Namespace the agent pods are created in.
	Namespace string
	// Image reference for the agent container.
	Image string
	// CRISocket is the node path used to resolve container -> netns.
	CRISocket string
	// Unprivileged drops securityContext.privileged from the agent pod, which
	// then needs the capability set documented in ARCHITECTURE.md §5.3. Stated
	// negatively so the zero value keeps the T0.3 default (privileged) and
	// defaulting never has to distinguish "unset" from "explicitly off".
	Unprivileged bool
}

// Privileged reports whether the agent container should run privileged.
func (c AgentConfig) Privileged() bool { return !c.Unprivileged }

// DefaultAgentConfig returns the T0.3 defaults.
func DefaultAgentConfig() AgentConfig {
	return AgentConfig{
		Namespace: DefaultAgentNamespace,
		Image:     DefaultAgentImage,
		CRISocket: DefaultCRISocket,
	}
}

// WithDefaults returns a copy of s with unset optional fields filled in.
func (s Spec) WithDefaults() Spec {
	out := s
	if out.Snaplen == 0 {
		out.Snaplen = DefaultSnaplen
	}
	if out.Out == "" {
		out.Out = StdoutSink
	}
	defaults := DefaultAgentConfig()
	if out.Agent.Namespace == "" {
		out.Agent.Namespace = defaults.Namespace
	}
	if out.Agent.Image == "" {
		out.Agent.Image = defaults.Image
	}
	if out.Agent.CRISocket == "" {
		out.Agent.CRISocket = defaults.CRISocket
	}
	return out
}

// Validate reports every problem with the spec at once so a CLI user does not
// have to fix flags one at a time. Defaults are not applied: call WithDefaults
// first if the spec comes straight from flags.
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

	if s.Out == "" {
		errs = append(errs, errors.New("out: required (path or \"-\")"))
	}

	if s.Snaplen != 0 && s.Snaplen < MinSnaplen {
		errs = append(errs, fmt.Errorf("snaplen: must be 0 or >= %d, got %d", MinSnaplen, s.Snaplen))
	}

	errs = append(errs, s.Agent.validate()...)

	return errors.Join(errs...)
}

func (c AgentConfig) validate() []error {
	var errs []error
	if c.Namespace == "" {
		errs = append(errs, errors.New("agent namespace: required"))
	} else if msgs := validation.IsDNS1123Label(c.Namespace); len(msgs) > 0 {
		errs = append(errs, fmt.Errorf("agent namespace: invalid %q: %s", c.Namespace, msgs[0]))
	}
	if c.Image == "" {
		errs = append(errs, errors.New("agent image: required"))
	}
	if c.CRISocket == "" {
		errs = append(errs, errors.New("agent cri socket: required"))
	}
	return errs
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
