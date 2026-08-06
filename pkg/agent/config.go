package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sharedcapture "github.com/sthuck/k8s-sniffer/pkg/capture"
)

// Environment variables injected into the agent pod (see hub PodManifest).
const (
	EnvSessionID = sharedcapture.EnvAgentSessionID
	EnvNode      = sharedcapture.EnvAgentNode
	EnvAgentPod  = sharedcapture.EnvAgentPod
	EnvStreamID  = sharedcapture.EnvAgentStreamID
	EnvHubAddr   = sharedcapture.EnvAgentHubAddr
	EnvCRISocket = sharedcapture.EnvAgentCRISocket
	EnvLogLevel  = sharedcapture.EnvAgentLogLevel
)

// Config is runtime configuration for the node agent.
type Config struct {
	SessionID string
	Node      string
	AgentPod  string
	StreamID  string
	HubAddr   string
	CRISocket string
}

// ConfigFromEnv loads agent configuration from the standard environment variables.
func ConfigFromEnv() (Config, error) {
	cfg := Config{
		SessionID: os.Getenv(EnvSessionID),
		Node:      os.Getenv(EnvNode),
		AgentPod:  os.Getenv(EnvAgentPod),
		StreamID:  os.Getenv(EnvStreamID),
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
	if c.AgentPod == "" {
		errs = append(errs, fmt.Errorf("%s: required", EnvAgentPod))
	}
	if c.StreamID == "" {
		errs = append(errs, fmt.Errorf("%s: required", EnvStreamID))
	}
	if c.HubAddr == "" {
		errs = append(errs, fmt.Errorf("%s: required", EnvHubAddr))
	}
	if c.CRISocket == "" {
		errs = append(errs, fmt.Errorf("%s: required", EnvCRISocket))
	} else if strings.Contains(c.CRISocket, "://") {
		errs = append(errs, fmt.Errorf("%s: must be a filesystem path, got %q", EnvCRISocket, c.CRISocket))
	} else if !filepath.IsAbs(c.CRISocket) {
		errs = append(errs, fmt.Errorf("%s: must be absolute, got %q", EnvCRISocket, c.CRISocket))
	}
	return errors.Join(errs...)
}
