package agent

import (
	"os"
	"testing"
)

func TestConfigFromEnv(t *testing.T) {
	t.Setenv(EnvSessionID, "sess-1")
	t.Setenv(EnvNode, "node-a")
	t.Setenv(EnvHubAddr, "hub:50051")
	t.Setenv(EnvCRISocket, "/run/containerd/containerd.sock")

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if cfg.SessionID != "sess-1" || cfg.Node != "node-a" || cfg.HubAddr != "hub:50051" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestConfigFromEnvMissing(t *testing.T) {
	for _, key := range []string{EnvSessionID, EnvNode, EnvHubAddr, EnvCRISocket} {
		t.Run(key, func(t *testing.T) {
			os.Clearenv()
			t.Setenv(key, "")
			if _, err := ConfigFromEnv(); err == nil {
				t.Fatalf("expected error when %s missing", key)
			}
		})
	}
}
