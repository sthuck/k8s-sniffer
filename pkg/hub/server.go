package hub

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	"github.com/sthuck/k8s-sniffer/pkg/capture"
	"github.com/sthuck/k8s-sniffer/pkg/hub/agent"
	"github.com/sthuck/k8s-sniffer/pkg/hub/discovery"
)

var errKubernetesRequired = errors.New("kubernetes client: required")

func (h *Hub) CreateSession(ctx context.Context, req *snifferv1.CreateSessionRequest) (*snifferv1.CreateSessionResponse, error) {
	spec := capture.SpecFromProto(req.GetSpec()).WithDefaults()
	if err := spec.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "spec: %v", err)
	}

	sessionID := uuid.NewString()
	hubLog.Info("session create started",
		slog.String("session_id", sessionID),
		slog.String("namespace", spec.Namespace),
	)
	hubLog.Debug("session spec",
		slog.String("session_id", sessionID),
		slog.Any("pod_patterns", spec.PodPatterns),
		slog.String("bpf_filter", spec.BPFFilter),
		slog.Duration("duration", spec.Duration),
	)

	wireSpec := spec.ToProto()
	sess := newSessionState(sessionID, wireSpec)
	h.putSession(sess)

	sess.lifecycleMu.Lock()
	sess.emitState(sessionID, snifferv1.SessionState_SESSION_STATE_PENDING)
	err := h.startSession(ctx, sess, spec)
	sess.lifecycleMu.Unlock()

	if err != nil {
		hubLog.Info("session create failed",
			slog.String("session_id", sessionID),
			slog.String("err", err.Error()),
		)
		failed := h.failSession(ctx, sess, err)
		return &snifferv1.CreateSessionResponse{Session: failed}, nil
	}

	hubLog.Info("session create completed",
		slog.String("session_id", sessionID),
		slog.String("state", sess.snapshot().GetState().String()),
	)
	return &snifferv1.CreateSessionResponse{Session: sess.snapshot()}, nil
}

func (h *Hub) failSession(ctx context.Context, sess *sessionState, err error) *snifferv1.Session {
	sessionID := sess.proto.Id
	hubLog.Debug("cleaning up failed session agents", slog.String("session_id", sessionID))
	if delErr := h.agents.DeleteSessionAgents(ctx, sessionID); delErr != nil {
		hubLog.Info("failed to delete agents for failed session",
			slog.String("session_id", sessionID),
			slog.String("err", delErr.Error()),
		)
	}
	sess.setState(snifferv1.SessionState_SESSION_STATE_FAILED, err.Error())
	sess.emitState(sessionID, snifferv1.SessionState_SESSION_STATE_FAILED)
	sess.emit(&snifferv1.SessionEvent{
		SessionId: sessionID,
		Severity:  snifferv1.Severity_SEVERITY_ERROR,
		Message:   err.Error(),
		Payload: &snifferv1.SessionEvent_Error{
			Error: &snifferv1.CaptureError{
				Stage:  snifferv1.ErrorStage_ERROR_STAGE_AGENT_SCHEDULING,
				Reason: snifferv1.ErrorReason_ERROR_REASON_INTERNAL,
				Detail: err.Error(),
			},
		},
	})
	snapshot := sess.snapshot()
	sess.signalStop()
	sess.events.close()
	sess.packets.close()
	h.deleteSession(sessionID)
	return snapshot
}

func (h *Hub) startSession(ctx context.Context, sess *sessionState, spec capture.Spec) error {
	sessionID := sess.proto.Id
	sess.setState(snifferv1.SessionState_SESSION_STATE_STARTING, "")
	sess.emitState(sessionID, snifferv1.SessionState_SESSION_STATE_STARTING)

	matcher, err := discovery.NewPodMatcher(spec)
	if err != nil {
		return fmt.Errorf("pod matcher: %w", err)
	}

	pods, err := discovery.ListMatchingPods(ctx, h.opts.Kubernetes, spec.Namespace, matcher)
	if err != nil {
		return fmt.Errorf("list pods: %w", err)
	}
	hubLog.Debug("discovery listed pods",
		slog.String("session_id", sessionID),
		slog.Int("matched", len(pods)),
	)

	groups, skipped := discovery.GroupByNode(pods)
	hubLog.Debug("discovery grouped pods by node",
		slog.String("session_id", sessionID),
		slog.Int("nodes", len(groups)),
		slog.Int("skipped", len(skipped)),
	)
	for _, skip := range skipped {
		sess.emit(&snifferv1.SessionEvent{
			SessionId: sessionID,
			Severity:  snifferv1.Severity_SEVERITY_WARNING,
			Message:   fmt.Sprintf("skipped pod %s: %s", skip.Pod.GetName(), skip.Reason),
			Payload: &snifferv1.SessionEvent_Error{
				Error: &snifferv1.CaptureError{
					Stage:     snifferv1.ErrorStage_ERROR_STAGE_DISCOVERY,
					Reason:    snifferv1.ErrorReason_ERROR_REASON_UNSUPPORTED,
					Detail:    skip.Reason,
					Retryable: true,
					Pod:       skip.Pod,
				},
			},
		})
	}

	if len(groups) == 0 {
		hubLog.Info("no pods matched for session",
			slog.String("session_id", sessionID),
			slog.String("namespace", spec.Namespace),
		)
		return fmt.Errorf("no running pods matched in namespace %q", spec.Namespace)
	}

	nodes := make([]string, 0, len(groups))
	for _, group := range groups {
		if err := sess.context().Err(); err != nil {
			return fmt.Errorf("session stopped during agent scheduling: %w", err)
		}

		for _, target := range group.Targets {
			sess.emit(&snifferv1.SessionEvent{
				SessionId: sessionID,
				Severity:  snifferv1.Severity_SEVERITY_INFO,
				Message:   fmt.Sprintf("matched pod %s on node %s", target.GetName(), group.Node),
				Payload: &snifferv1.SessionEvent_PodAttached{
					PodAttached: &snifferv1.PodAttached{Pod: target},
				},
			})
		}

		streamID := uuid.NewString()
		assignment := buildAssignment(sessionID, group, spec, streamID)
		createOpts := agent.CreateOptions{
			ActiveDeadline: spec.Duration,
			StreamID:       streamID,
		}

		pod, err := h.agents.CreateForNode(sess.context(), sessionID, group.Node, createOpts)
		if err != nil {
			return err
		}
		sess.recordAgent(group.Node, pod.Name, streamID, assignment)

		sess.emit(&snifferv1.SessionEvent{
			SessionId: sessionID,
			Severity:  snifferv1.Severity_SEVERITY_INFO,
			Message:   fmt.Sprintf("scheduling agent %s on node %s", pod.Name, group.Node),
			Payload: &snifferv1.SessionEvent_AgentState{
				AgentState: &snifferv1.AgentStateChanged{
					Node:     group.Node,
					AgentPod: pod.Name,
					Phase:    snifferv1.AgentPhase_AGENT_PHASE_SCHEDULING,
					Targets:  targetsFromAssignment(assignment),
				},
			},
		})

		if err := h.agents.WaitReady(sess.context(), sessionID, pod); err != nil {
			return fmt.Errorf("wait for agent on node %q: %w", group.Node, err)
		}

		nodes = append(nodes, group.Node)

		sess.emit(&snifferv1.SessionEvent{
			SessionId: sessionID,
			Severity:  snifferv1.Severity_SEVERITY_INFO,
			Message:   fmt.Sprintf("agent %s ready on node %s", pod.Name, group.Node),
			Payload: &snifferv1.SessionEvent_AgentState{
				AgentState: &snifferv1.AgentStateChanged{
					Node:     group.Node,
					AgentPod: pod.Name,
					Phase:    snifferv1.AgentPhase_AGENT_PHASE_READY,
					Targets:  targetsFromAssignment(assignment),
				},
			},
		})
	}

	sess.setNodes(nodes)
	sess.setState(snifferv1.SessionState_SESSION_STATE_RUNNING, "")
	sess.emitState(sessionID, snifferv1.SessionState_SESSION_STATE_RUNNING)
	hubLog.Info("session running",
		slog.String("session_id", sessionID),
		slog.Int("nodes", len(nodes)),
		slog.Any("node_names", nodes),
	)
	return nil
}

func buildAssignment(sessionID string, group discovery.NodeGroup, spec capture.Spec, streamID string) *snifferv1.AgentAssignment {
	targets := make([]*snifferv1.Target, 0, len(group.Targets))
	for _, pod := range group.Targets {
		targets = append(targets, &snifferv1.Target{
			Pod:       pod,
			BpfFilter: spec.BPFFilter,
			TlsMode:   snifferv1.TlsMode(spec.TLSMode),
			Snaplen:   spec.Snaplen,
		})
	}
	return &snifferv1.AgentAssignment{
		SessionId: sessionID,
		Node:      group.Node,
		StreamId:  streamID,
		Targets:   targets,
	}
}

func targetsFromAssignment(a *snifferv1.AgentAssignment) []*snifferv1.PodRef {
	out := make([]*snifferv1.PodRef, 0, len(a.GetTargets()))
	for _, t := range a.GetTargets() {
		out = append(out, t.GetPod())
	}
	return out
}

func (h *Hub) StopSession(ctx context.Context, req *snifferv1.StopSessionRequest) (*snifferv1.StopSessionResponse, error) {
	sessionID := req.GetSessionId()
	sess, ok := h.getSession(sessionID)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "session %q not found", sessionID)
	}
	hubLog.Info("session stop requested", slog.String("session_id", sessionID))
	snapshot, err := h.stopSession(ctx, sess)
	if err != nil {
		hubLog.Info("session stop failed",
			slog.String("session_id", sessionID),
			slog.String("err", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "stop session: %v", err)
	}
	hubLog.Info("session stopped", slog.String("session_id", sessionID))
	return &snifferv1.StopSessionResponse{Session: snapshot}, nil
}

func (h *Hub) stopSession(ctx context.Context, sess *sessionState) (*snifferv1.Session, error) {
	sess.lifecycleMu.Lock()
	defer sess.lifecycleMu.Unlock()

	sessionID := sess.proto.Id
	if isTerminalState(sess.snapshot().GetState()) {
		return sess.snapshot(), nil
	}

	sess.setState(snifferv1.SessionState_SESSION_STATE_STOPPING, "")
	sess.emitState(sessionID, snifferv1.SessionState_SESSION_STATE_STOPPING)
	sess.signalStop()

	if err := h.agents.DeleteSessionAgents(ctx, sessionID); err != nil {
		return nil, err
	}

	sess.setState(snifferv1.SessionState_SESSION_STATE_STOPPED, "")
	sess.emitState(sessionID, snifferv1.SessionState_SESSION_STATE_STOPPED)
	snapshot := sess.snapshot()
	sess.events.close()
	sess.packets.close()
	h.deleteSession(sessionID)
	return snapshot, nil
}

func (h *Hub) GetSession(_ context.Context, req *snifferv1.GetSessionRequest) (*snifferv1.GetSessionResponse, error) {
	sess, ok := h.getSession(req.GetSessionId())
	if !ok {
		return nil, status.Errorf(codes.NotFound, "session %q not found", req.GetSessionId())
	}
	return &snifferv1.GetSessionResponse{Session: sess.snapshot()}, nil
}

func (h *Hub) ListSessions(_ context.Context, _ *snifferv1.ListSessionsRequest) (*snifferv1.ListSessionsResponse, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	sessions := make([]*snifferv1.Session, 0, len(h.sessions))
	for _, s := range h.sessions {
		sessions = append(sessions, s.snapshot())
	}
	return &snifferv1.ListSessionsResponse{Sessions: sessions}, nil
}

func (h *Hub) WatchEvents(req *snifferv1.WatchEventsRequest, stream snifferv1.HubService_WatchEventsServer) error {
	sess, ok := h.getSession(req.GetSessionId())
	if !ok {
		return status.Errorf(codes.NotFound, "session %q not found", req.GetSessionId())
	}

	var id int
	var ch <-chan *snifferv1.SessionEvent
	var history []*snifferv1.SessionEvent
	if req.GetReplayHistory() {
		id, ch, history = sess.events.subscribeWithReplay()
	} else {
		id, ch, _ = sess.events.subscribeWithReplay()
	}
	defer sess.events.unsubscribe(id)

	for _, ev := range history {
		if err := stream.Send(ev); err != nil {
			return err
		}
	}

	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return nil
			}
			if err := stream.Send(ev); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-sess.done():
			return nil
		}
	}
}

func (h *Hub) SubscribePackets(req *snifferv1.SubscribePacketsRequest, stream snifferv1.HubService_SubscribePacketsServer) error {
	sess, ok := h.getSession(req.GetSessionId())
	if !ok {
		return status.Errorf(codes.NotFound, "session %q not found", req.GetSessionId())
	}
	id, ch, done := sess.packets.subscribe()
	defer sess.packets.unsubscribe(id)

	for {
		select {
		case rec, ok := <-ch:
			if !ok {
				return nil
			}
			if !recordMatchesFilter(rec, req.GetKinds()) {
				continue
			}
			if err := stream.Send(rec); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-done:
			return nil
		}
	}
}

func recordMatchesFilter(rec *snifferv1.CaptureRecord, kinds []snifferv1.RecordKind) bool {
	if len(kinds) == 0 {
		return true
	}
	for _, k := range kinds {
		switch k {
		case snifferv1.RecordKind_RECORD_KIND_WIRE_FRAME:
			if rec.GetWireFrame() != nil {
				return true
			}
		case snifferv1.RecordKind_RECORD_KIND_TLS_EVENT:
			if rec.GetTlsEvent() != nil {
				return true
			}
		}
	}
	return false
}

func (h *Hub) WatchTargets(req *snifferv1.WatchTargetsRequest, stream snifferv1.AgentIngestService_WatchTargetsServer) error {
	sess, ok := h.getSession(req.GetSessionId())
	if !ok {
		return status.Errorf(codes.NotFound, "session %q not found", req.GetSessionId())
	}
	streamID := incomingStreamID(stream.Context())
	assignment, err := sess.assignmentFor(req.GetNode(), req.GetAgentPod(), streamID)
	if err != nil {
		return status.Errorf(codes.PermissionDenied, "agent assignment: %v", err)
	}
	if err := stream.Send(assignment); err != nil {
		return err
	}
	select {
	case <-stream.Context().Done():
		return stream.Context().Err()
	case <-sess.done():
		return nil
	}
}

func (h *Hub) StreamCapture(stream snifferv1.AgentIngestService_StreamCaptureServer) error {
	var accepted uint64
	var claimedSession *sessionState
	var claimedNode, claimedStreamID string
	defer func() {
		if claimedSession != nil {
			claimedSession.releaseCaptureStream(claimedNode, claimedStreamID)
		}
	}()
	for {
		batch, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&snifferv1.StreamCaptureSummary{RecordsAccepted: accepted})
		}
		if err != nil {
			return err
		}
		sess, ok := h.getSession(batch.GetSessionId())
		if !ok {
			return status.Errorf(codes.NotFound, "session %q not found", batch.GetSessionId())
		}
		if claimedSession == nil {
			if err := sess.claimCaptureStream(batch.GetNode(), batch.GetStreamId()); err != nil {
				return status.Errorf(codes.FailedPrecondition, "capture stream: %v", err)
			}
			claimedSession = sess
			claimedNode = batch.GetNode()
			claimedStreamID = batch.GetStreamId()
		} else if sess != claimedSession || batch.GetNode() != claimedNode || batch.GetStreamId() != claimedStreamID {
			return status.Error(codes.FailedPrecondition, "capture stream identity changed")
		}
		if err := sess.validateCaptureBatch(batch); err != nil {
			return status.Errorf(codes.FailedPrecondition, "capture batch: %v", err)
		}
		for _, rec := range batch.GetRecords() {
			if err := sess.packets.publish(stream.Context(), rec); err != nil {
				if errors.Is(err, errPacketLogClosed) {
					return stream.SendAndClose(&snifferv1.StreamCaptureSummary{RecordsAccepted: accepted})
				}
				return err
			}
			accepted++
		}
		if batch.GetDropped() > 0 {
			sess.emit(&snifferv1.SessionEvent{
				SessionId: batch.GetSessionId(),
				Severity:  snifferv1.Severity_SEVERITY_WARNING,
				Message:   fmt.Sprintf("agent dropped %d capture records", batch.GetDropped()),
				Payload: &snifferv1.SessionEvent_Stats{
					Stats: &snifferv1.SessionStats{Dropped: batch.GetDropped()},
				},
			})
		}
		hubLog.Debug("capture batch ingested",
			slog.String("session_id", batch.GetSessionId()),
			slog.String("stream_id", batch.GetStreamId()),
			slog.Int("records", len(batch.GetRecords())),
		)
	}
}

func (h *Hub) ReportStatus(_ context.Context, req *snifferv1.ReportStatusRequest) (*snifferv1.ReportStatusResponse, error) {
	sess, ok := h.getSession(req.GetSessionId())
	if !ok {
		return nil, status.Errorf(codes.NotFound, "session %q not found", req.GetSessionId())
	}
	if err := sess.validateAgentEnvelope(req.GetSessionId(), req.GetNode(), req.GetStreamId()); err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "agent status: %v", err)
	}
	event := &snifferv1.SessionEvent{
		SessionId: req.GetSessionId(),
		Severity:  snifferv1.Severity_SEVERITY_INFO,
	}
	switch {
	case req.GetError() != nil:
		event.Severity = snifferv1.Severity_SEVERITY_ERROR
		event.Message = req.GetError().GetDetail()
		event.Payload = &snifferv1.SessionEvent_Error{Error: req.GetError()}
	case req.GetStats() != nil:
		event.Message = "agent capture statistics updated"
		event.Payload = &snifferv1.SessionEvent_Stats{Stats: req.GetStats()}
	case req.GetAgentState() != nil:
		event.Message = "agent state: " + req.GetAgentState().GetPhase().String()
		event.Payload = &snifferv1.SessionEvent_AgentState{AgentState: req.GetAgentState()}
	case req.GetTlsState() != nil:
		event.Message = "agent TLS state: " + req.GetTlsState().GetStatus().String()
		event.Payload = &snifferv1.SessionEvent_TlsState{TlsState: req.GetTlsState()}
	default:
		return nil, status.Error(codes.InvalidArgument, "status payload is required")
	}
	sess.emit(event)
	return &snifferv1.ReportStatusResponse{}, nil
}

func incomingStreamID(ctx context.Context) string {
	values := metadata.ValueFromIncomingContext(ctx, capture.AgentStreamMetadataKey)
	if len(values) != 1 {
		return ""
	}
	return values[0]
}

func (h *Hub) StopAll(ctx context.Context) error {
	h.mu.RLock()
	ids := make([]string, 0, len(h.sessions))
	for id := range h.sessions {
		ids = append(ids, id)
	}
	h.mu.RUnlock()

	hubLog.Info("stopping all sessions", slog.Int("count", len(ids)))

	var errs []error
	for _, id := range ids {
		sess, ok := h.getSession(id)
		if !ok {
			continue
		}
		if _, err := h.stopSession(ctx, sess); err != nil {
			hubLog.Info("session stop failed during StopAll",
				slog.String("session_id", id),
				slog.String("err", err.Error()),
			)
			errs = append(errs, fmt.Errorf("session %q: %w", id, err))
		}
	}
	return errors.Join(errs...)
}
