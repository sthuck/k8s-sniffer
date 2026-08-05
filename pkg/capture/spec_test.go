package capture

import (
	"strings"
	"testing"
	"time"
)

func validSpec() Spec {
	return Spec{
		Namespace:   "prod",
		PodPatterns: []string{"payments-.*", "checkout-.*"},
		Out:         "session.pcapng",
		Agent:       DefaultAgentConfig(),
	}
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
			name:    "missing out",
			mutate:  func(s *Spec) { s.Out = "" },
			wantErr: "out: required",
		},
		{
			name:    "snaplen too small",
			mutate:  func(s *Spec) { s.Snaplen = 10 },
			wantErr: "snaplen:",
		},
		{
			name:    "missing agent image",
			mutate:  func(s *Spec) { s.Agent.Image = "" },
			wantErr: "agent image: required",
		},
		{
			name:    "bad agent namespace",
			mutate:  func(s *Spec) { s.Agent.Namespace = "Sniffer Agents" },
			wantErr: "agent namespace: invalid",
		},
		{
			name:    "missing cri socket",
			mutate:  func(s *Spec) { s.Agent.CRISocket = "" },
			wantErr: "agent cri socket: required",
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
	spec := Spec{PodPatterns: []string{"("}}

	err := spec.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want errors")
	}
	for _, want := range []string{"namespace: required", "pod patterns[0]:", "out: required", "agent image: required"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Validate() = %q, missing %q", err, want)
		}
	}
}

func TestWithDefaults(t *testing.T) {
	got := Spec{Namespace: "prod", PodPatterns: []string{"api"}}.WithDefaults()

	if err := got.Validate(); err != nil {
		t.Fatalf("defaulted spec invalid: %v", err)
	}
	if got.Snaplen != DefaultSnaplen {
		t.Errorf("Snaplen = %d, want %d", got.Snaplen, DefaultSnaplen)
	}
	if got.Out != StdoutSink {
		t.Errorf("Out = %q, want %q", got.Out, StdoutSink)
	}
	if got.Agent != DefaultAgentConfig() {
		t.Errorf("Agent = %+v, want %+v", got.Agent, DefaultAgentConfig())
	}
}

func TestWithDefaultsKeepsExplicitValues(t *testing.T) {
	spec := validSpec()
	spec.Snaplen = 128
	spec.Agent.Namespace = "debug-tools"
	spec.Agent.Unprivileged = true

	got := spec.WithDefaults()

	if got.Snaplen != 128 || got.Out != "session.pcapng" || got.Agent.Namespace != "debug-tools" {
		t.Fatalf("WithDefaults() overwrote explicit values: %+v", got)
	}
	if got.Agent.Privileged() {
		t.Error("WithDefaults() re-enabled privileged mode; an opt-out must survive defaulting")
	}
}

func TestDefaultAgentConfigIsPrivileged(t *testing.T) {
	if !DefaultAgentConfig().Privileged() {
		t.Error("default agent config is unprivileged; T0.3 locked privileged agents for phase 1")
	}
	if !(AgentConfig{}).Privileged() {
		t.Error("zero AgentConfig must default to privileged")
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
