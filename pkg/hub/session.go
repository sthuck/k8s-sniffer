package hub

import (
	"context"
	"fmt"
	"sync"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type agentRecord struct {
	node     string
	podName  string
	streamID string
}

// sessionState is the in-memory hub state for one capture session.
type sessionState struct {
	mu          sync.RWMutex
	lifecycleMu sync.Mutex
	proto       *snifferv1.Session
	events      *eventLog
	packets     *packetLog
	ctx         context.Context
	cancel      context.CancelFunc
	stopOnce    sync.Once
	agents      map[string]agentRecord
	assigns     map[string]*snifferv1.AgentAssignment
}

func newSessionState(id string, spec *snifferv1.CaptureSpec) *sessionState {
	ctx, cancel := context.WithCancel(context.Background())
	return &sessionState{
		proto: &snifferv1.Session{
			Id:        id,
			Spec:      spec,
			State:     snifferv1.SessionState_SESSION_STATE_PENDING,
			CreatedAt: timestamppb.Now(),
		},
		events:  newEventLog(),
		packets: newPacketLog(),
		ctx:     ctx,
		cancel:  cancel,
		agents:  make(map[string]agentRecord),
		assigns: make(map[string]*snifferv1.AgentAssignment),
	}
}

func (s *sessionState) context() context.Context {
	return s.ctx
}

func (s *sessionState) signalStop() {
	s.stopOnce.Do(s.cancel)
}

func (s *sessionState) done() <-chan struct{} {
	return s.ctx.Done()
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
	return proto.Clone(s.proto).(*snifferv1.Session)
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
	if !ok {
		return nil, false
	}
	return proto.Clone(a).(*snifferv1.AgentAssignment), true
}

func (s *sessionState) validateCaptureBatch(batch *snifferv1.CaptureBatch) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if batch.GetSessionId() != "" && batch.GetSessionId() != s.proto.Id {
		return fmt.Errorf("session_id mismatch")
	}
	if s.proto.State != snifferv1.SessionState_SESSION_STATE_RUNNING {
		return fmt.Errorf("session not running")
	}
	rec, ok := s.agents[batch.GetNode()]
	if !ok {
		return fmt.Errorf("no agent for node %q", batch.GetNode())
	}
	if batch.GetStreamId() != "" && rec.streamID != batch.GetStreamId() {
		return fmt.Errorf("stream_id mismatch")
	}
	return nil
}

func isTerminalState(state snifferv1.SessionState) bool {
	return state == snifferv1.SessionState_SESSION_STATE_STOPPED ||
		state == snifferv1.SessionState_SESSION_STATE_FAILED
}
