package capture

import (
	"strings"
	"testing"
	"time"
)

const testImage = "example.com/agent@sha256:0000000000000000000000000000000000000000000000000000000000000000"

func validSpec() Spec {
	return Spec{
		Namespace:   "prod",
		PodPatterns: []string{"payments-.*", "checkout-.*"},
		TLSMode:     TLSModeOff,
	}
}

func validAgentConfig() AgentConfig {
	cfg := DefaultAgentConfig()
	cfg.Image = testImage
	cfg.HubIngestAddr = "127.0.0.1:50051"
	return cfg
}

func TestSpecValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Spec)
		wantErr string
	}{
		{
			name:   "valid",
			mutate: func(*Spec) {},
		},
		{
			name:   "valid with duration and bpf filter",
			mutate: func(s *Spec) { s.Duration = 5 * time.Minute; s.BPFFilter = "tcp port 8080" },
		},
		{
			name:    "empty namespace",
			mutate:  func(s *Spec) { s.Namespace = "" },
			wantErr: "namespace: required",
		},
		{
			name:    "namespace not a dns label",
			mutate:  func(s *Spec) { s.Namespace = "Prod_1" },
			wantErr: "namespace: invalid",
		},
		{
			name:    "no patterns",
			mutate:  func(s *Spec) { s.PodPatterns = nil },
			wantErr: "at least one required",
		},
		{
			name:    "empty pattern",
			mutate:  func(s *Spec) { s.PodPatterns = []string{"api-.*", ""} },
			wantErr: "pod patterns[1]: empty",
		},
		{
			name:    "bad regex",
			mutate:  func(s *Spec) { s.PodPatterns = []string{"payments-(unclosed"} },
			wantErr: "pod patterns[0]:",
		},
		{
			name:    "negative duration",
			mutate:  func(s *Spec) { s.Duration = -time.Second },
			wantErr: "duration:",
		},
		{
			name:    "snaplen too small",
			mutate:  func(s *Spec) { s.Snaplen = 10 },
			wantErr: "snaplen:",
		},
		{
			name:    "unspecified tls mode",
			mutate:  func(s *Spec) { s.TLSMode = TLSModeUnspecified },
			wantErr: "tls mode: unset",
		},
		{
			name:    "unknown tls mode",
			mutate:  func(s *Spec) { s.TLSMode = TLSMode(42) },
			wantErr: "tls mode: unknown value 42",
		},
		{
			name:    "tls mode not implemented yet",
			mutate:  func(s *Spec) { s.TLSMode = TLSModeAuto },
			wantErr: "tls mode: auto is not implemented yet",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := validSpec()
			tc.mutate(&spec)

			err := spec.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %q, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestSpecValidateReportsAllProblems(t *testing.T) {
	spec := Spec{PodPatterns: []string{"("}, Duration: -time.Second}

	err := spec.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want errors")
	}
	for _, want := range []string{"namespace: required", "pod patterns[0]:", "duration:", "tls mode:"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Validate() = %q, missing %q", err, want)
		}
	}
}

// A spec straight off the wire must pass validation without the caller having
// to invent a sink or agent settings first.
func TestSpecValidateDoesNotRequireClientOrAgentFields(t *testing.T) {
	spec := SpecFromProto(validSpec().ToProto()).WithDefaults()

	if err := spec.Validate(); err != nil {
		t.Fatalf("Validate() on a wire spec = %v, want nil", err)
	}
}

func TestSpecWithDefaults(t *testing.T) {
	got := Spec{Namespace: "prod", PodPatterns: []string{"api"}}.WithDefaults()

	if err := got.Validate(); err != nil {
		t.Fatalf("defaulted spec invalid: %v", err)
	}
	if got.Snaplen != DefaultSnaplen {
		t.Errorf("Snaplen = %d, want %d", got.Snaplen, DefaultSnaplen)
	}
	if got.TLSMode != TLSModeOff {
		t.Errorf("TLSMode = %s, want off", got.TLSMode)
	}
}

func TestSpecWithDefaultsKeepsExplicitValues(t *testing.T) {
	spec := validSpec()
	spec.Snaplen = 128

	got := spec.WithDefaults()

	if got.Snaplen != 128 {
		t.Fatalf("WithDefaults() overwrote Snaplen: %d", got.Snaplen)
	}
}

func TestCompilePatterns(t *testing.T) {
	spec := validSpec()

	compiled, err := spec.CompilePatterns()
	if err != nil {
		t.Fatalf("CompilePatterns() error: %v", err)
	}
	if len(compiled) != 2 {
		t.Fatalf("got %d patterns, want 2", len(compiled))
	}
	if !compiled[0].MatchString("payments-7d9f-abc") {
		t.Error("payments pattern did not match payments-7d9f-abc")
	}
	if compiled[0].MatchString("checkout-1") {
		t.Error("payments pattern unexpectedly matched checkout-1")
	}

	spec.PodPatterns = []string{"*bad"}
	if _, err := spec.CompilePatterns(); err == nil {
		t.Error("CompilePatterns() = nil error for invalid pattern")
	}
}

func TestTLSMode(t *testing.T) {
	for name, want := range map[string]TLSMode{
		"off":    TLSModeOff,
		"ebpf":   TLSModeEBPF,
		"keylog": TLSModeKeylog,
		"auto":   TLSModeAuto,
	} {
		got, err := ParseTLSMode(name)
		if err != nil {
			t.Fatalf("ParseTLSMode(%q) error: %v", name, err)
		}
		if got != want {
			t.Errorf("ParseTLSMode(%q) = %d, want %d", name, got, want)
		}
		if got.String() != name {
			t.Errorf("%d.String() = %q, want %q", got, got.String(), name)
		}
		if !got.Known() {
			t.Errorf("%s.Known() = false", name)
		}
	}

	if _, err := ParseTLSMode("mitm"); err == nil {
		t.Error("ParseTLSMode(\"mitm\") = nil error")
	}
	if _, err := ParseTLSMode("unspecified"); err == nil {
		t.Error("ParseTLSMode(\"unspecified\") should not accept the zero value name")
	}
	if TLSMode(42).Known() {
		t.Error("TLSMode(42).Known() = true")
	}
	if TLSModeUnspecified.Known() {
		t.Error("unspecified is a defaulting marker, not a known mode")
	}
	if !TLSModeOff.Implemented() {
		t.Error("off must be implemented")
	}
	if TLSModeAuto.Implemented() {
		t.Error("auto must not report itself implemented before T3.1")
	}
}

func TestSinkSpec(t *testing.T) {
	if err := (SinkSpec{}).Validate(); err == nil {
		t.Error("empty SinkSpec validated")
	}
	defaulted := SinkSpec{}.WithDefaults()
	if !defaulted.IsStdout() {
		t.Errorf("default sink = %q, want %q", defaulted.Out, StdoutSink)
	}
	if err := defaulted.Validate(); err != nil {
		t.Errorf("defaulted sink invalid: %v", err)
	}
	file := SinkSpec{Out: "session.pcapng"}
	if file.IsStdout() {
		t.Error("file sink reported as stdout")
	}
	if got := file.WithDefaults(); got.Out != "session.pcapng" {
		t.Errorf("WithDefaults() overwrote Out: %q", got.Out)
	}
}

func TestAgentConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*AgentConfig)
		wantErr string
	}{
		{
			name:   "valid",
			mutate: func(*AgentConfig) {},
		},
		{
			name:   "mutable tag allowed when explicitly opted in",
			mutate: func(c *AgentConfig) { c.Image = "local/agent:dev"; c.AllowMutableImage = true },
		},
		{
			name:    "missing image",
			mutate:  func(c *AgentConfig) { c.Image = "" },
			wantErr: "agent image: required",
		},
		{
			name:    "mutable tag rejected by default",
			mutate:  func(c *AgentConfig) { c.Image = "ghcr.io/sthuck/k8s-sniffer-agent:dev" },
			wantErr: "not digest-pinned",
		},
		{
			name:    "bad agent namespace",
			mutate:  func(c *AgentConfig) { c.Namespace = "Sniffer Agents" },
			wantErr: "agent namespace: invalid",
		},
		{
			name:    "missing cri socket",
			mutate:  func(c *AgentConfig) { c.CRISocketHostPath = "" },
			wantErr: "agent cri socket host path: required",
		},
		{
			name:    "cri socket given as a uri",
			mutate:  func(c *AgentConfig) { c.CRISocketHostPath = "unix:///run/containerd/containerd.sock" },
			wantErr: "is a URI",
		},
		{
			name:    "cri socket not absolute",
			mutate:  func(c *AgentConfig) { c.CRISocketHostPath = "run/containerd/containerd.sock" },
			wantErr: "must be absolute",
		},
		{
			name:    "missing hub ingest address",
			mutate:  func(c *AgentConfig) { c.HubIngestAddr = "" },
			wantErr: "agent hub ingest address: required",
		},
		{
			name:    "invalid log level",
			mutate:  func(c *AgentConfig) { c.LogLevel = "trace" },
			wantErr: "agent log level",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validAgentConfig()
			tc.mutate(&cfg)

			err := cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %q, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestAgentConfigDefaults(t *testing.T) {
	cfg := DefaultAgentConfig()

	if !cfg.Privileged() {
		t.Error("default agent config is unprivileged; T0.3 locked privileged agents for phase 1")
	}
	if !(AgentConfig{}).Privileged() {
		t.Error("zero AgentConfig must default to privileged")
	}
	if cfg.Namespace != DefaultAgentNamespace {
		t.Errorf("Namespace = %q, want %q", cfg.Namespace, DefaultAgentNamespace)
	}
	// A dev build has no release image, so the default path must not silently
	// point at a mutable tag.
	if cfg.Image != DefaultAgentImage() {
		t.Errorf("Image = %q, want the build-injected ref %q", cfg.Image, DefaultAgentImage())
	}
	if DefaultAgentImage() == "" {
		if err := cfg.Validate(); err == nil {
			t.Error("default config in a build without a pinned image must not validate")
		}
	} else if err := cfg.Validate(); err != nil {
		t.Errorf("build injected agent image %q but the default config is invalid: %v", DefaultAgentImage(), err)
	}
}

func TestAgentConfigWithDefaultsKeepsExplicitValues(t *testing.T) {
	cfg := AgentConfig{Namespace: "debug-tools", Image: testImage, Unprivileged: true}

	got := cfg.WithDefaults()

	if got.Namespace != "debug-tools" || got.Image != testImage {
		t.Fatalf("WithDefaults() overwrote explicit values: %+v", got)
	}
	if got.CRISocketHostPath != DefaultCRISocketPath {
		t.Errorf("CRISocketHostPath = %q, want %q", got.CRISocketHostPath, DefaultCRISocketPath)
	}
	if got.Privileged() {
		t.Error("WithDefaults() re-enabled privileged mode; an opt-out must survive defaulting")
	}
}

// The mount source and the dial URI are different strings; conflating them
// produces a hostPath volume that does not exist on the node.
func TestCRIEndpointIsDerivedFromHostPath(t *testing.T) {
	cfg := AgentConfig{CRISocketHostPath: DefaultCRISocketPath}

	if got := cfg.CRIEndpoint(); got != "unix://"+DefaultCRISocketPath {
		t.Errorf("CRIEndpoint() = %q, want %q", got, "unix://"+DefaultCRISocketPath)
	}
	if got := (AgentConfig{}).CRIEndpoint(); got != "" {
		t.Errorf("CRIEndpoint() with no path = %q, want empty", got)
	}
}

func TestIsDigestPinned(t *testing.T) {
	pinned := []string{
		testImage,
		"ghcr.io/sthuck/k8s-sniffer-agent@sha256:abc",
		"ghcr.io/sthuck/k8s-sniffer-agent:v1@sha256:abc",
	}
	for _, ref := range pinned {
		if !IsDigestPinned(ref) {
			t.Errorf("IsDigestPinned(%q) = false", ref)
		}
	}
	mutable := []string{"", "agent", "agent:dev", "ghcr.io/x/agent:v1", "agent@", "@sha256:abc", "agent@sha256"}
	for _, ref := range mutable {
		if IsDigestPinned(ref) {
			t.Errorf("IsDigestPinned(%q) = true", ref)
		}
	}
}
