package hub

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	"github.com/sthuck/k8s-sniffer/pkg/capture"
	"github.com/sthuck/k8s-sniffer/pkg/hub/discovery"
)

var errKubernetesRequired = errors.New("kubernetes client: required")

func (h *Hub) CreateSession(ctx context.Context, req *snifferv1.CreateSessionRequest) (*snifferv1.CreateSessionResponse, error) {
	spec := capture.SpecFromProto(req.GetSpec()).WithDefaults()
	if err := spec.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "spec: %v", err)
	}

	sessionID := uuid.NewString()
	wireSpec := spec.ToProto()
	sess := newSessionState(sessionID, wireSpec)
	h.putSession(sess)
	sess.emitState(sessionID, snifferv1.SessionState_SESSION_STATE_PENDING)

	if err := h.startSession(ctx, sess, spec); err != nil {
		_ = h.agents.DeleteSessionAgents(ctx, sessionID)
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
		close(sess.stopCh)
		return &snifferv1.CreateSessionResponse{Session: sess.snapshot()}, nil
	}

	return &snifferv1.CreateSessionResponse{Session: sess.snapshot()}, nil
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

	groups, skipped := discovery.GroupByNode(pods)
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

	nodes := make([]string, 0, len(groups))
	for _, group := range groups {
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

		pod, err := h.agents.CreateForNode(ctx, sessionID, group.Node)
		if err != nil {
			return err
		}

		sess.emit(&snifferv1.SessionEvent{
			SessionId: sessionID,
			Severity:  snifferv1.Severity_SEVERITY_INFO,
			Message:   fmt.Sprintf("scheduling agent %s on node %s", pod.Name, group.Node),
			Payload: &snifferv1.SessionEvent_AgentState{
				AgentState: &snifferv1.AgentStateChanged{
					Node:      group.Node,
					AgentPod:  pod.Name,
					Phase:     snifferv1.AgentPhase_AGENT_PHASE_SCHEDULING,
					Targets:   targetsFromAssignment(assignment),
				},
			},
		})

		if err := h.agents.WaitReady(ctx, pod); err != nil {
			return fmt.Errorf("wait for agent on node %q: %w", group.Node, err)
		}

		sess.recordAgent(group.Node, pod.Name, streamID, assignment)
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
	sess, ok := h.getSession(req.GetSessionId())
	if !ok {
		return nil, status.Errorf(codes.NotFound, "session %q not found", req.GetSessionId())
	}
	if err := h.stopSession(ctx, sess); err != nil {
		return nil, status.Errorf(codes.Internal, "stop session: %v", err)
	}
	return &snifferv1.StopSessionResponse{Session: sess.snapshot()}, nil
}

func (h *Hub) stopSession(ctx context.Context, sess *sessionState) error {
	sessionID := sess.proto.Id
	state := sess.snapshot().GetState()
	if state == snifferv1.SessionState_SESSION_STATE_STOPPED || state == snifferv1.SessionState_SESSION_STATE_FAILED {
		return nil
	}

	sess.setState(snifferv1.SessionState_SESSION_STATE_STOPPING, "")
	sess.emitState(sessionID, snifferv1.SessionState_SESSION_STATE_STOPPING)

	select {
	case <-sess.stopCh:
	default:
		close(sess.stopCh)
	}

	if err := h.agents.DeleteSessionAgents(ctx, sessionID); err != nil {
		return err
	}

	sess.setState(snifferv1.SessionState_SESSION_STATE_STOPPED, "")
	sess.emitState(sessionID, snifferv1.SessionState_SESSION_STATE_STOPPED)
	sess.events.close()
	h.deleteSession(sessionID)
	return nil
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
	if req.GetReplayHistory() {
		for _, ev := range sess.events.history() {
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
	id, ch := sess.events.subscribe()
	defer sess.events.unsubscribe(id)

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
		case <-sess.stopCh:
			return nil
		}
	}
}

func (h *Hub) SubscribePackets(req *snifferv1.SubscribePacketsRequest, stream snifferv1.HubService_SubscribePacketsServer) error {
	sess, ok := h.getSession(req.GetSessionId())
	if !ok {
		return status.Errorf(codes.NotFound, "session %q not found", req.GetSessionId())
	}
	// Packet fan-out from agents lands in T1.12; block until the session ends.
	select {
	case <-stream.Context().Done():
		return stream.Context().Err()
	case <-sess.stopCh:
		return nil
	}
}

func (h *Hub) WatchTargets(req *snifferv1.WatchTargetsRequest, stream snifferv1.AgentIngestService_WatchTargetsServer) error {
	sess, ok := h.getSession(req.GetSessionId())
	if !ok {
		return status.Errorf(codes.NotFound, "session %q not found", req.GetSessionId())
	}
	assignment, ok := sess.assignmentFor(req.GetNode())
	if !ok {
		return status.Errorf(codes.NotFound, "no assignment for node %q in session %q", req.GetNode(), req.GetSessionId())
	}
	if err := stream.Send(assignment); err != nil {
		return err
	}
	select {
	case <-stream.Context().Done():
		return stream.Context().Err()
	case <-sess.stopCh:
		return nil
	}
}

func (h *Hub) StreamCapture(stream snifferv1.AgentIngestService_StreamCaptureServer) error {
	for {
		_, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&snifferv1.StreamCaptureSummary{})
		}
		if err != nil {
			return err
		}
		// Record fan-out to SubscribePackets subscribers lands in T1.12.
	}
}

func (h *Hub) ReportStatus(context.Context, *snifferv1.ReportStatusRequest) (*snifferv1.ReportStatusResponse, error) {
	return &snifferv1.ReportStatusResponse{}, nil
}

// StopAll stops every active session and deletes its agents. Intended for
// process shutdown (Ctrl-C) before T1.14 wires signal handling.
func (h *Hub) StopAll(ctx context.Context) error {
	h.mu.RLock()
	ids := make([]string, 0, len(h.sessions))
	for id := range h.sessions {
		ids = append(ids, id)
	}
	h.mu.RUnlock()

	var first error
	for _, id := range ids {
		sess, ok := h.getSession(id)
		if !ok {
			continue
		}
		if err := h.stopSession(ctx, sess); err != nil && first == nil {
			first = err
		}
	}
	return first
}
