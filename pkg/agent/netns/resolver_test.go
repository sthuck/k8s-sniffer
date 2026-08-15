package netns

import (
	"strings"
	"testing"

	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	"github.com/sthuck/k8s-sniffer/pkg/capture"
)

func TestParseCRIEndpoint(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		endpoint    string
		wantNetwork string
		wantAddr    string
		wantErr     string
	}{
		{name: "unix uri", endpoint: "unix:///run/containerd/containerd.sock", wantNetwork: "unix", wantAddr: "/run/containerd/containerd.sock"},
		{name: "bare absolute path", endpoint: "/run/containerd/containerd.sock", wantNetwork: "unix", wantAddr: "/run/containerd/containerd.sock"},
		{name: "tcp uri", endpoint: "tcp://127.0.0.1:12345", wantNetwork: "tcp", wantAddr: "127.0.0.1:12345"},
		{name: "bare hostport", endpoint: "127.0.0.1:12345", wantNetwork: "tcp", wantAddr: "127.0.0.1:12345"},
		{name: "empty", endpoint: "", wantErr: "required"},
		{name: "bad scheme", endpoint: "http://example", wantErr: "unsupported scheme"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			network, addr, err := parseCRIEndpoint(tc.endpoint)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("parseCRIEndpoint(%q) = %q %q %v, want err containing %q", tc.endpoint, network, addr, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCRIEndpoint(%q): %v", tc.endpoint, err)
			}
			if network != tc.wantNetwork || addr != tc.wantAddr {
				t.Fatalf("parseCRIEndpoint(%q) = %q %q, want %q %q", tc.endpoint, network, addr, tc.wantNetwork, tc.wantAddr)
			}
		})
	}
}

func TestParseContainerPID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		info    map[string]string
		want    int
		wantErr string
	}{
		{
			name: "containerd verbose info json",
			info: map[string]string{
				"info": `{"pid":12345,"sandboxID":"abc"}`,
			},
			want: 12345,
		},
		{
			name: "cri-o top-level pid",
			info: map[string]string{
				"pid": "6789",
			},
			want: 6789,
		},
		{
			name: "prefer top-level pid when both present",
			info: map[string]string{
				"pid":  "111",
				"info": `{"pid":222}`,
			},
			want: 111,
		},
		{
			name:    "missing pid",
			info:    map[string]string{"info": `{"sandboxID":"abc"}`},
			wantErr: "pid not available",
		},
		{
			name:    "invalid json",
			info:    map[string]string{"info": "not-json"},
			wantErr: "parse container info json",
		},
		{
			name:    "invalid top-level pid",
			info:    map[string]string{"pid": "not-a-number"},
			wantErr: "parse container pid",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseContainerPID(tc.info)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("parseContainerPID() = %d, want error containing %q", got, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("parseContainerPID() error = %q, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseContainerPID() = %v", err)
			}
			if got != tc.want {
				t.Fatalf("pid = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestWorkloadContainers(t *testing.T) {
	t.Parallel()

	containers := []*runtimeapi.Container{
		{Metadata: &runtimeapi.ContainerMetadata{Name: "sidecar"}},
		{Metadata: &runtimeapi.ContainerMetadata{Name: "POD"}},
		{Metadata: &runtimeapi.ContainerMetadata{Name: "app"}},
	}
	got := workloadContainers(containers)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].GetMetadata().GetName() != "sidecar" || got[1].GetMetadata().GetName() != "app" {
		t.Fatalf("containers = %q, %q", got[0].GetMetadata().GetName(), got[1].GetMetadata().GetName())
	}

	onlyPOD := []*runtimeapi.Container{
		{Metadata: &runtimeapi.ContainerMetadata{Name: "POD"}},
	}
	got = workloadContainers(onlyPOD)
	if len(got) != 1 || got[0].GetMetadata().GetName() != "POD" {
		t.Fatalf("fallback = %v", got)
	}
}

func TestPickSandbox(t *testing.T) {
	t.Parallel()
	pod := &snifferv1.PodRef{Namespace: "tabnine", Name: "app-1", Uid: "uid-1"}
	older := &runtimeapi.PodSandbox{Id: "old", CreatedAt: 1, Metadata: &runtimeapi.PodSandboxMetadata{Uid: "uid-1"}}
	newer := &runtimeapi.PodSandbox{Id: "new", CreatedAt: 2, Metadata: &runtimeapi.PodSandboxMetadata{Uid: "uid-1"}}
	other := &runtimeapi.PodSandbox{Id: "other", CreatedAt: 3, Metadata: &runtimeapi.PodSandboxMetadata{Uid: "uid-2"}}

	got := pickSandbox([]*runtimeapi.PodSandbox{older, newer, other}, pod)
	if got == nil || got.GetId() != "new" {
		t.Fatalf("pickSandbox() = %v, want newest uid match", got)
	}
	if got := pickSandbox([]*runtimeapi.PodSandbox{other}, pod); got != nil {
		t.Fatalf("pickSandbox() = %v, want nil on uid miss", got)
	}
}

func TestNoSandboxError(t *testing.T) {
	t.Parallel()
	pod := &snifferv1.PodRef{Namespace: "tabnine", Name: "app-1"}
	err := noSandboxError(pod, capture.DefaultCRISocketPath, 0)
	if err == nil || !strings.Contains(err.Error(), "via "+capture.DefaultCRISocketPath) {
		t.Fatalf("missing socket: %v", err)
	}
	if !strings.Contains(err.Error(), "--cri-socket") || !strings.Contains(err.Error(), capture.DefaultK3sCRISocketPath) {
		t.Fatalf("missing k3s hint: %v", err)
	}
	err = noSandboxError(pod, capture.DefaultK3sCRISocketPath, 4)
	if err == nil || !strings.Contains(err.Error(), "4 ready sandboxes") {
		t.Fatalf("missing visible count: %v", err)
	}
}

func TestTrimRuntimePrefix(t *testing.T) {
	t.Parallel()
	if got := trimRuntimePrefix("containerd://abc123"); got != "abc123" {
		t.Fatalf("trimRuntimePrefix() = %q", got)
	}
	if got := trimRuntimePrefix("abc123"); got != "abc123" {
		t.Fatalf("trimRuntimePrefix() changed plain id to %q", got)
	}
}
