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
