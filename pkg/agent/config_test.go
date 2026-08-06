package agent

import (
	"testing"
)

func TestConfigFromEnv(t *testing.T) {
	t.Setenv(EnvSessionID, "sess-1")
	t.Setenv(EnvNode, "node-a")
	t.Setenv(EnvAgentPod, "agent-1")
	t.Setenv(EnvStreamID, "stream-1")
	t.Setenv(EnvHubAddr, "hub:50051")
	t.Setenv(EnvCRISocket, "/run/containerd/containerd.sock")

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if cfg.SessionID != "sess-1" || cfg.Node != "node-a" || cfg.AgentPod != "agent-1" ||
		cfg.StreamID != "stream-1" || cfg.HubAddr != "hub:50051" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestConfigFromEnvMissing(t *testing.T) {
	valid := map[string]string{
		EnvSessionID: "sess-1",
		EnvNode:      "node-a",
		EnvAgentPod:  "agent-1",
		EnvStreamID:  "stream-1",
		EnvHubAddr:   "hub:50051",
		EnvCRISocket: "/run/containerd/containerd.sock",
	}
	for key, value := range valid {
		t.Setenv(key, value)
	}
	for key := range valid {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "")
			if _, err := ConfigFromEnv(); err == nil {
				t.Fatalf("expected error when %s missing", key)
			}
		})
	}
}

func TestConfigRejectsInvalidCRISocket(t *testing.T) {
	cfg := Config{
		SessionID: "sess-1",
		Node:      "node-a",
		AgentPod:  "agent-1",
		StreamID:  "stream-1",
		HubAddr:   "hub:50051",
		CRISocket: "unix:///run/containerd/containerd.sock",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected URI CRI socket to fail validation")
	}
}
