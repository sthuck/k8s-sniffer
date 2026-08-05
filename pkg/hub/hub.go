// Package hub owns session lifecycle: pod discovery, node grouping, agent
// scheduling, stream fan-in and cleanup. It implements
// snifferv1.HubServiceServer and snifferv1.AgentIngestServiceServer so the same
// code serves the in-process CLI hub (Phase 1) and a standalone deployment
// (Phase 4).
package hub

import (
	"sync"
	"time"

	"k8s.io/client-go/kubernetes"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	"github.com/sthuck/k8s-sniffer/pkg/capture"
	"github.com/sthuck/k8s-sniffer/pkg/hub/agent"
)

// Options configures an in-process Hub.
type Options struct {
	// Kubernetes client for pod discovery and agent scheduling.
	Kubernetes kubernetes.Interface
	// Agent deployment settings (trusted operator config).
	Agent capture.AgentConfig
	// ReadyTimeout overrides agent pod Ready wait (zero = agent.DefaultReadyTimeout).
	ReadyTimeout time.Duration
}

// Hub is the session orchestrator. Embed the unimplemented servers so new RPCs
// compile until they are implemented.
type Hub struct {
	snifferv1.UnimplementedHubServiceServer
	snifferv1.UnimplementedAgentIngestServiceServer

	mu       sync.RWMutex
	opts     Options
	agents   *agent.Manager
	sessions map[string]*sessionState
}

// New returns a Hub ready to register on a gRPC server.
func New(opts Options) (*Hub, error) {
	if opts.Kubernetes == nil {
		return nil, errKubernetesRequired
	}
	agentCfg := opts.Agent.WithDefaults()
	if err := agentCfg.Validate(); err != nil {
		return nil, err
	}
	mgr := agent.NewManager(opts.Kubernetes, agentCfg)
	if opts.ReadyTimeout > 0 {
		mgr.WithReadyTimeout(opts.ReadyTimeout)
	}
	return &Hub{
		opts:     opts,
		agents:   mgr,
		sessions: make(map[string]*sessionState),
	}, nil
}

func (h *Hub) getSession(id string) (*sessionState, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	s, ok := h.sessions[id]
	return s, ok
}

func (h *Hub) putSession(s *sessionState) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sessions[s.proto.Id] = s
}

func (h *Hub) deleteSession(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.sessions, id)
}
