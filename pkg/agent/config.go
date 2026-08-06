package agent

import (
	"errors"
	"fmt"
	"os"
)

// Environment variables injected into the agent pod (see hub PodManifest).
const (
	EnvSessionID  = "K8S_SNIFFER_SESSION_ID"
	EnvNode       = "K8S_SNIFFER_NODE"
	EnvAgentPod   = "K8S_SNIFFER_AGENT_POD"
	EnvHubAddr    = "K8S_SNIFFER_HUB_ADDR"
	EnvCRISocket  = "K8S_SNIFFER_CRI_SOCKET"
	EnvLogLevel   = "K8S_SNIFFER_LOG_LEVEL"
)

// Config is runtime configuration for the node agent.
type Config struct {
	SessionID string
	Node      string
	AgentPod  string
	HubAddr   string
	CRISocket string
}

// ConfigFromEnv loads agent configuration from the standard environment
// variables. AgentPod may be empty when not set (downward API optional).
func ConfigFromEnv() (Config, error) {
	cfg := Config{
		SessionID: os.Getenv(EnvSessionID),
		Node:      os.Getenv(EnvNode),
		AgentPod:  os.Getenv(EnvAgentPod),
		HubAddr:   os.Getenv(EnvHubAddr),
		CRISocket: os.Getenv(EnvCRISocket),
	}
	return cfg, cfg.Validate()
}

func (c Config) Validate() error {
	var errs []error
	if c.SessionID == "" {
		errs = append(errs, fmt.Errorf("%s: required", EnvSessionID))
	}
	if c.Node == "" {
		errs = append(errs, fmt.Errorf("%s: required", EnvNode))
	}
	if c.HubAddr == "" {
		errs = append(errs, fmt.Errorf("%s: required", EnvHubAddr))
	}
	if c.CRISocket == "" {
		errs = append(errs, fmt.Errorf("%s: required", EnvCRISocket))
	}
	return errors.Join(errs...)
}
