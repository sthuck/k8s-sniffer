package hub

import (
	"context"
	"fmt"
	"sync"
	"time"

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

type podStat struct {
	pod     *snifferv1.PodRef
	packets uint64
	bytes   uint64
	dropped uint64
}

type sessionCounters struct {
	packets uint64
	bytes   uint64
	dropped uint64
	perPod  map[string]*podStat
}

// sessionState is the in-memory hub state for one capture session.
type sessionState struct {
	mu           sync.RWMutex
	lifecycleMu  sync.Mutex
	reconcileMu  sync.Mutex
	proto        *snifferv1.Session
	events       *eventLog
	packets      *packetLog
	ctx          context.Context
	cancel       context.CancelFunc
	stopOnce     sync.Once
	agents       map[string]agentRecord
	assigns      map[string]*snifferv1.AgentAssignment
	stateChange  chan struct{}
	assignGen    uint64
	assignChange chan struct{}
	stats        sessionCounters
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
		events:       newEventLog(),
		packets:      newPacketLog(),
		ctx:          ctx,
		cancel:       cancel,
		agents:       make(map[string]agentRecord),
		assigns:      make(map[string]*snifferv1.AgentAssignment),
		stateChange:  make(chan struct{}),
		assignChange: make(chan struct{}),
		stats:        sessionCounters{perPod: make(map[string]*podStat)},
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
	s.notifyAssignLocked()
}

func (s *sessionState) updateAssignment(node string, assignment *snifferv1.AgentAssignment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assigns[node] = assignment
	s.notifyAssignLocked()
}

func (s *sessionState) removeAgent(node string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.agents, node)
	delete(s.assigns, node)
	nodes := make([]string, 0, len(s.agents))
	for n := range s.agents {
		nodes = append(nodes, n)
	}
	s.proto.Nodes = nodes
	s.notifyAssignLocked()
}

func (s *sessionState) notifyAssignLocked() {
	s.assignGen++
	close(s.assignChange)
	s.assignChange = make(chan struct{})
}

func (s *sessionState) assignmentGeneration() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.assignGen
}

func (s *sessionState) assignmentForNode(node string) (*snifferv1.AgentAssignment, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.assigns[node]
	if !ok {
		return nil, false
	}
	return proto.Clone(a).(*snifferv1.AgentAssignment), true
}

func (s *sessionState) currentTargets() map[string]*snifferv1.PodRef {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]*snifferv1.PodRef)
	for _, a := range s.assigns {
		for _, t := range a.GetTargets() {
			if p := t.GetPod(); p != nil && p.GetUid() != "" {
				out[p.GetUid()] = p
			}
		}
	}
	return out
}

func (s *sessionState) agentNodes() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	nodes := make([]string, 0, len(s.agents))
	for n := range s.agents {
		nodes = append(nodes, n)
	}
	return nodes
}

func (s *sessionState) waitAssignChange(ctx context.Context, node string, gen uint64) error {
	for {
		s.mu.RLock()
		if isTerminalState(s.proto.State) || s.proto.State == snifferv1.SessionState_SESSION_STATE_STOPPING {
			s.mu.RUnlock()
			return fmt.Errorf("session stopping")
		}
		if _, ok := s.agents[node]; !ok {
			s.mu.RUnlock()
			return fmt.Errorf("agent removed")
		}
		if s.assignGen != gen {
			s.mu.RUnlock()
			return nil
		}
		changed := s.assignChange
		s.mu.RUnlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.done():
			return fmt.Errorf("session stopped")
		case <-changed:
		}
	}
}

func (s *sessionState) addPacketLocked(pod *snifferv1.PodRef, nBytes int) {
	if nBytes < 0 {
		nBytes = 0
	}
	s.stats.packets++
	s.stats.bytes += uint64(nBytes)
	if pod == nil || pod.GetUid() == "" {
		return
	}
	st := s.podStatLocked(pod)
	st.packets++
	st.bytes += uint64(nBytes)
}

func (s *sessionState) addDropped(n uint64, pod *snifferv1.PodRef) {
	if n == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.dropped += n
	if pod == nil || pod.GetUid() == "" {
		return
	}
	st := s.podStatLocked(pod)
	st.dropped += n
}

func (s *sessionState) podStatLocked(pod *snifferv1.PodRef) *podStat {
	st, ok := s.stats.perPod[pod.GetUid()]
	if !ok {
		st = &podStat{pod: proto.Clone(pod).(*snifferv1.PodRef)}
		s.stats.perPod[pod.GetUid()] = st
	}
	return st
}

func (s *sessionState) snapshotStats() *snifferv1.SessionStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := &snifferv1.SessionStats{
		Packets: s.stats.packets,
		Bytes:   s.stats.bytes,
		Dropped: s.stats.dropped,
	}
	for _, st := range s.stats.perPod {
		out.PerPod = append(out.PerPod, &snifferv1.PodCounters{
			Pod:     proto.Clone(st.pod).(*snifferv1.PodRef),
			Packets: st.packets,
			Bytes:   st.bytes,
			Dropped: st.dropped,
		})
	}
	return out
}

func (s *sessionState) emitStats() {
	stats := s.snapshotStats()
	s.emit(&snifferv1.SessionEvent{
		SessionId: s.proto.Id,
		Severity:  snifferv1.Severity_SEVERITY_INFO,
		Message:   fmt.Sprintf("stats packets=%d bytes=%d dropped=%d", stats.GetPackets(), stats.GetBytes(), stats.GetDropped()),
		Payload:   &snifferv1.SessionEvent_Stats{Stats: stats},
	})
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
	n := int(frame.GetOriginalLength())
	if n == 0 {
		n = len(frame.GetPayload())
	}
	s.addPacketLocked(frame.GetPod(), n)
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

func (s *sessionState) activeCaptureStreams() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, rec := range s.agents {
		if rec.ingestActive {
			n++
		}
	}
	return n
}

// waitCaptureStreamsIdle waits until agents finish StreamCapture or timeout.
func (s *sessionState) waitCaptureStreamsIdle(ctx context.Context, timeout time.Duration) {
	if s.activeCaptureStreams() == 0 {
		return
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if s.activeCaptureStreams() == 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			return
		case <-ticker.C:
		}
	}
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
