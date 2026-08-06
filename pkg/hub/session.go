package hub

import (
	"context"
	"fmt"
	"sync"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	maxBatchRecords      = 64
	maxBatchPayloadBytes = 4 << 20
)

type agentRecord struct {
	node         string
	podName      string
	streamID     string
	lastSequence uint64
	ingestActive bool
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
	stateChange chan struct{}
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
		events:      newEventLog(),
		packets:     newPacketLog(),
		ctx:         ctx,
		cancel:      cancel,
		agents:      make(map[string]agentRecord),
		assigns:     make(map[string]*snifferv1.AgentAssignment),
		stateChange: make(chan struct{}),
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
	close(s.stateChange)
	s.stateChange = make(chan struct{})
	if state == snifferv1.SessionState_SESSION_STATE_STOPPED || state == snifferv1.SessionState_SESSION_STATE_FAILED {
		s.proto.StoppedAt = timestamppb.Now()
	}
}

func (s *sessionState) waitUntilRunning(ctx context.Context) error {
	for {
		s.mu.RLock()
		state := s.proto.State
		changed := s.stateChange
		s.mu.RUnlock()
		switch state {
		case snifferv1.SessionState_SESSION_STATE_RUNNING:
			return nil
		case snifferv1.SessionState_SESSION_STATE_STOPPING,
			snifferv1.SessionState_SESSION_STATE_STOPPED,
			snifferv1.SessionState_SESSION_STATE_FAILED:
			return fmt.Errorf("session entered state %s before capture started", state)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
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

func (s *sessionState) assignmentFor(node, podName, streamID string) (*snifferv1.AgentAssignment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if node == "" || podName == "" || streamID == "" {
		return nil, fmt.Errorf("node, agent_pod, and stream_id are required")
	}
	rec, ok := s.agents[node]
	if !ok {
		return nil, fmt.Errorf("no agent for node %q", node)
	}
	if rec.podName != podName || rec.streamID != streamID {
		return nil, fmt.Errorf("agent identity mismatch")
	}
	a, ok := s.assigns[node]
	if !ok {
		return nil, fmt.Errorf("no assignment for node %q", node)
	}
	return proto.Clone(a).(*snifferv1.AgentAssignment), nil
}

func (s *sessionState) validateCaptureBatch(batch *snifferv1.CaptureBatch) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if batch.GetSessionId() == "" || batch.GetSessionId() != s.proto.Id {
		return fmt.Errorf("session_id mismatch")
	}
	switch s.proto.State {
	case snifferv1.SessionState_SESSION_STATE_STARTING,
		snifferv1.SessionState_SESSION_STATE_RUNNING,
		snifferv1.SessionState_SESSION_STATE_STOPPING:
	default:
		return fmt.Errorf("session does not accept capture data in state %s", s.proto.State)
	}
	rec, ok := s.agents[batch.GetNode()]
	if !ok {
		return fmt.Errorf("no agent for node %q", batch.GetNode())
	}
	if batch.GetStreamId() == "" || rec.streamID != batch.GetStreamId() {
		return fmt.Errorf("stream_id mismatch")
	}
	if len(batch.GetRecords()) > maxBatchRecords {
		return fmt.Errorf("too many records: %d > %d", len(batch.GetRecords()), maxBatchRecords)
	}
	assignment := s.assigns[batch.GetNode()]
	var payloadBytes int
	lastSequence := rec.lastSequence
	for i, record := range batch.GetRecords() {
		n, err := validateCaptureRecord(record, assignment)
		if err != nil {
			return fmt.Errorf("records[%d]: %w", i, err)
		}
		if frame := record.GetWireFrame(); frame != nil {
			if frame.GetSequence() != lastSequence+1 {
				return fmt.Errorf("records[%d]: sequence %d, want %d", i, frame.GetSequence(), lastSequence+1)
			}
			lastSequence = frame.GetSequence()
		}
		payloadBytes += n
		if payloadBytes > maxBatchPayloadBytes {
			return fmt.Errorf("payload bytes exceed %d", maxBatchPayloadBytes)
		}
	}
	return nil
}

func (s *sessionState) commitCaptureRecord(node, streamID string, record *snifferv1.CaptureRecord) error {
	frame := record.GetWireFrame()
	if frame == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.agents[node]
	if !ok || rec.streamID != streamID {
		return fmt.Errorf("agent identity mismatch")
	}
	if frame.GetSequence() != rec.lastSequence+1 {
		return fmt.Errorf("sequence %d, want %d", frame.GetSequence(), rec.lastSequence+1)
	}
	rec.lastSequence = frame.GetSequence()
	s.agents[node] = rec
	return nil
}

func (s *sessionState) validateAgentEnvelope(sessionID, node, podName, streamID string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sessionID == "" || sessionID != s.proto.Id {
		return fmt.Errorf("session_id mismatch")
	}
	rec, ok := s.agents[node]
	if !ok {
		return fmt.Errorf("no agent for node %q", node)
	}
	if podName == "" || podName != rec.podName || streamID == "" || streamID != rec.streamID {
		return fmt.Errorf("agent identity mismatch")
	}
	return nil
}

func (s *sessionState) claimCaptureStream(node, podName, streamID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.agents[node]
	if !ok || podName == "" || podName != rec.podName || streamID == "" || streamID != rec.streamID {
		return fmt.Errorf("agent identity mismatch")
	}
	if rec.ingestActive {
		return fmt.Errorf("capture stream already active")
	}
	rec.ingestActive = true
	s.agents[node] = rec
	return nil
}

func (s *sessionState) releaseCaptureStream(node, streamID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.agents[node]
	if !ok || rec.streamID != streamID {
		return
	}
	rec.ingestActive = false
	s.agents[node] = rec
}

func validateCaptureRecord(record *snifferv1.CaptureRecord, assignment *snifferv1.AgentAssignment) (int, error) {
	if record == nil {
		return 0, fmt.Errorf("record is required")
	}
	var pod *snifferv1.PodRef
	var payload []byte
	switch {
	case record.GetWireFrame() != nil:
		frame := record.GetWireFrame()
		pod = frame.GetPod()
		payload = frame.GetPayload()
		if frame.GetSource() != snifferv1.PacketSource_PACKET_SOURCE_WIRE {
			return 0, fmt.Errorf("wire frame has invalid source %s", frame.GetSource())
		}
		if frame.GetTimestamp() == nil || frame.GetTimestamp().CheckValid() != nil {
			return 0, fmt.Errorf("wire frame timestamp is invalid")
		}
		if frame.GetOriginalLength() < uint32(len(payload)) {
			return 0, fmt.Errorf("payload exceeds original length")
		}
	case record.GetTlsEvent() != nil:
		event := record.GetTlsEvent()
		pod = event.GetPod()
		payload = event.GetPayload()
	default:
		return 0, fmt.Errorf("record payload is required")
	}
	target := assignedTarget(assignment, pod)
	if target == nil {
		return 0, fmt.Errorf("pod is not assigned to this agent")
	}
	if record.GetTlsEvent() != nil && target.GetTlsMode() == snifferv1.TlsMode_TLS_MODE_OFF {
		return 0, fmt.Errorf("TLS events are disabled for this target")
	}
	return len(payload), nil
}

func assignedTarget(assignment *snifferv1.AgentAssignment, pod *snifferv1.PodRef) *snifferv1.Target {
	if assignment == nil || pod == nil {
		return nil
	}
	for _, target := range assignment.GetTargets() {
		candidate := target.GetPod()
		if candidate.GetNamespace() == pod.GetNamespace() &&
			candidate.GetName() == pod.GetName() &&
			candidate.GetUid() == pod.GetUid() &&
			candidate.GetNode() == pod.GetNode() {
			return target
		}
	}
	return nil
}

func isTerminalState(state snifferv1.SessionState) bool {
	return state == snifferv1.SessionState_SESSION_STATE_STOPPED ||
		state == snifferv1.SessionState_SESSION_STATE_FAILED
}
