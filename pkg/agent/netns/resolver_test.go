package netns

import (
	"strings"
	"testing"

	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

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
