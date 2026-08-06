package agent

import (
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	"github.com/sthuck/k8s-sniffer/pkg/capture"
)

const testImage = "example.com/agent@sha256:0000000000000000000000000000000000000000000000000000000000000000"

func validAgentConfig() capture.AgentConfig {
	cfg := capture.DefaultAgentConfig()
	cfg.Image = testImage
	cfg.HubIngestAddr = "127.0.0.1:50051"
	return cfg
}

func TestPodManifestGolden(t *testing.T) {
	pod, err := PodManifest("sess-abc123", "node-a", validAgentConfig(), 0)
	if err != nil {
		t.Fatalf("PodManifest: %v", err)
	}

	got, err := yaml.Marshal(pod)
	if err != nil {
		t.Fatalf("marshal pod: %v", err)
	}

	goldenPath := filepath.Join("testdata", "agent-pod.golden.yaml")
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("manifest differs from golden %s\n--- got\n%s\n--- want\n%s", goldenPath, got, want)
	}
}

func TestPodManifestRequiresSessionAndNode(t *testing.T) {
	cfg := validAgentConfig()
	if _, err := PodManifest("", "node-a", cfg, 0); err == nil {
		t.Fatal("expected error for empty session id")
	}
	if _, err := PodManifest("sess-1", "", cfg, 0); err == nil {
		t.Fatal("expected error for empty node name")
	}
}

func TestPodManifestUnprivileged(t *testing.T) {
	cfg := validAgentConfig()
	cfg.Unprivileged = true

	pod, err := PodManifest("sess-1", "node-a", cfg, 0)
	if err != nil {
		t.Fatalf("PodManifest: %v", err)
	}
	sc := pod.Spec.Containers[0].SecurityContext
	if sc.Privileged != nil {
		t.Fatal("unprivileged config should not set privileged")
	}
	if sc.Capabilities == nil || len(sc.Capabilities.Add) == 0 {
		t.Fatal("unprivileged config should add capture capabilities")
	}
}

func TestPodManifestMutableImagePullPolicy(t *testing.T) {
	cfg := validAgentConfig()
	cfg.AllowMutableImage = true
	cfg.Image = "local/agent:dev"

	pod, err := PodManifest("sess-1", "node-a", cfg, 0)
	if err != nil {
		t.Fatalf("PodManifest: %v", err)
	}
	if pod.Spec.Containers[0].ImagePullPolicy != corev1.PullAlways {
		t.Fatalf("pull policy = %q, want PullAlways", pod.Spec.Containers[0].ImagePullPolicy)
	}
}

func TestPodManifestDisablesServiceAccountToken(t *testing.T) {
	pod, err := PodManifest("sess-1", "node-a", validAgentConfig(), 0)
	if err != nil {
		t.Fatalf("PodManifest: %v", err)
	}
	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		t.Fatal("expected automountServiceAccountToken: false")
	}
}

func TestPodManifestRequiresHubAddr(t *testing.T) {
	cfg := validAgentConfig()
	cfg.HubIngestAddr = ""
	if _, err := PodManifest("sess-1", "node-a", cfg, 0); err == nil {
		t.Fatal("expected error for empty hub ingest address")
	}
}

func TestPodManifestInjectsLogLevel(t *testing.T) {
	cfg := validAgentConfig()
	cfg.LogLevel = "debug"

	pod, err := PodManifest("sess-1", "node-a", cfg, 0)
	if err != nil {
		t.Fatalf("PodManifest: %v", err)
	}
	env := pod.Spec.Containers[0].Env
	found := false
	for _, e := range env {
		if e.Name == envLogLevel && e.Value == "debug" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected K8S_SNIFFER_LOG_LEVEL=debug in pod env")
	}
}

func TestPodManifestValidatesConfig(t *testing.T) {
	cfg := capture.AgentConfig{}
	if _, err := PodManifest("sess-1", "node-a", cfg, 0); err == nil {
		t.Fatal("expected validation error")
	}
}
