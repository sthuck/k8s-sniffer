package capture

import "testing"

func TestCRISocketForRuntimeVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		runtime string
		current string
		want    string
	}{
		{name: "kind containerd default", runtime: "containerd://1.7.18", current: DefaultCRISocketPath, want: DefaultCRISocketPath},
		{name: "empty current kind", runtime: "containerd://1.7.18", want: DefaultCRISocketPath},
		{name: "k3s default", runtime: "containerd://1.7.22-k3s1", current: DefaultCRISocketPath, want: DefaultK3sCRISocketPath},
		{name: "k3s empty current", runtime: "containerd://1.7.22-k3s1", want: DefaultK3sCRISocketPath},
		{name: "rke2 default", runtime: "containerd://1.7.22-rke2r1", current: DefaultCRISocketPath, want: DefaultK3sCRISocketPath},
		{name: "explicit path wins on k3s", runtime: "containerd://1.7.22-k3s1", current: "/custom/cri.sock", want: "/custom/cri.sock"},
		{name: "cri-o default", runtime: "cri-o://1.30.0", current: DefaultCRISocketPath, want: DefaultCRIOSocketPath},
		{name: "docker cri-dockerd", runtime: "docker://24.0.0", current: DefaultCRISocketPath, want: DefaultCRIDockerdSocketPath},
		{name: "unknown runtime keeps default", runtime: "", current: DefaultCRISocketPath, want: DefaultCRISocketPath},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := CRISocketForRuntimeVersion(tc.runtime, tc.current)
			if got != tc.want {
				t.Fatalf("CRISocketForRuntimeVersion(%q, %q) = %q, want %q", tc.runtime, tc.current, got, tc.want)
			}
		})
	}
}

func TestCRISocketCandidates(t *testing.T) {
	t.Parallel()
	got := CRISocketCandidates(DefaultCRISocketPath)
	if got[0] != DefaultCRISocketPath {
		t.Fatalf("first = %q, want preferred", got[0])
	}
	seen := map[string]int{}
	for _, p := range got {
		seen[p]++
		if seen[p] > 1 {
			t.Fatalf("duplicate %q", p)
		}
	}
	for _, want := range WellKnownCRISocketPaths() {
		if seen[want] != 1 {
			t.Fatalf("missing well-known %q in %v", want, got)
		}
	}
}

func TestHostCRIMountPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		host string
		want string
	}{
		{host: DefaultCRISocketPath, want: HostRunMountPath + "/containerd/containerd.sock"},
		{host: DefaultK3sCRISocketPath, want: HostRunMountPath + "/k3s/containerd/containerd.sock"},
		{host: "/var/run/crio/crio.sock", want: HostRunMountPath + "/crio/crio.sock"},
		{host: "/custom/cri.sock", want: "/custom/cri.sock"},
	}
	for _, tc := range tests {
		if got := HostCRIMountPath(tc.host); got != tc.want {
			t.Fatalf("HostCRIMountPath(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
	if !NeedsExtraCRISocketMount("/custom/cri.sock") {
		t.Fatal("custom path should need an extra mount")
	}
	if NeedsExtraCRISocketMount(DefaultK3sCRISocketPath) {
		t.Fatal("k3s path is under /run")
	}
}
