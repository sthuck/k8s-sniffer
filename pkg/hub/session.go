package hub

import (
	"sync"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type agentRecord struct {
	node     string
	podName  string
	streamID string
}

// sessionState is the in-memory hub state for one capture session.
type sessionState struct {
	mu      sync.RWMutex
	proto   *snifferv1.Session
	events  *eventLog
	stopCh  chan struct{}
	agents  map[string]agentRecord
	assigns map[string]*snifferv1.AgentAssignment
}

func newSessionState(id string, spec *snifferv1.CaptureSpec) *sessionState {
	return &sessionState{
		proto: &snifferv1.Session{
			Id:        id,
			Spec:      spec,
			State:     snifferv1.SessionState_SESSION_STATE_PENDING,
			CreatedAt: timestamppb.Now(),
		},
		events:  newEventLog(),
		stopCh:  make(chan struct{}),
		agents:  make(map[string]agentRecord),
		assigns: make(map[string]*snifferv1.AgentAssignment),
	}
}

func (s *sessionState) setState(state snifferv1.SessionState, failureReason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proto.State = state
	s.proto.FailureReason = failureReason
	if state == snifferv1.SessionState_SESSION_STATE_STOPPED || state == snifferv1.SessionState_SESSION_STATE_FAILED {
		s.proto.StoppedAt = timestamppb.Now()
	}
}

func (s *sessionState) setNodes(nodes []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proto.Nodes = append([]string(nil), nodes...)
}

func (s *sessionState) snapshot() *snifferv1.Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.proto
}

func (s *sessionState) emit(ev *snifferv1.SessionEvent) {
	if ev.Timestamp == nil {
		ev.Timestamp = timestamppb.Now()
	}
	s.events.append(ev)
}

func (s *sessionState) emitState(sessionID string, state snifferv1.SessionState) {
	s.emit(&snifferv1.SessionEvent{
		SessionId: sessionID,
		Severity:  snifferv1.Severity_SEVERITY_INFO,
		Message:   "session state: " + state.String(),
		Payload: &snifferv1.SessionEvent_SessionState{
			SessionState: &snifferv1.SessionStateChanged{State: state},
		},
	})
}

func (s *sessionState) recordAgent(node, podName, streamID string, assignment *snifferv1.AgentAssignment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[node] = agentRecord{node: node, podName: podName, streamID: streamID}
	s.assigns[node] = assignment
}

func (s *sessionState) assignmentFor(node string) (*snifferv1.AgentAssignment, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.assigns[node]
	return a, ok
}
