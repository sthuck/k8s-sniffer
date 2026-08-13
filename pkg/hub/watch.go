package hub

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	"github.com/sthuck/k8s-sniffer/pkg/capture"
	"github.com/sthuck/k8s-sniffer/pkg/hub/agent"
	"github.com/sthuck/k8s-sniffer/pkg/hub/discovery"
)

const (
	defaultWatchInterval = time.Second
	defaultStatsInterval = 5 * time.Second
)

func (h *Hub) startLiveFollow(sess *sessionState, spec capture.Spec) {
	go h.watchPods(sess, spec)
	go h.runStats(sess)
}

func (h *Hub) watchPods(sess *sessionState, spec capture.Spec) {
	interval := h.opts.WatchInterval
	if interval <= 0 {
		interval = defaultWatchInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var watchCh <-chan watch.Event
	watcher, err := h.opts.Kubernetes.CoreV1().Pods(spec.Namespace).Watch(sess.context(), metav1.ListOptions{})
	if err != nil {
		hubLog.Info("pod watch failed; polling for live attach/detach",
			slog.String("session_id", sess.proto.Id),
			slog.String("namespace", spec.Namespace),
			slog.String("err", err.Error()),
		)
	} else {
		defer watcher.Stop()
		watchCh = watcher.ResultChan()
		hubLog.Debug("pod watch started",
			slog.String("session_id", sess.proto.Id),
			slog.String("namespace", spec.Namespace),
		)
	}

	h.reconcileSession(sess, spec)
	for {
		select {
		case <-sess.done():
			return
		case <-ticker.C:
			h.reconcileSession(sess, spec)
		case _, ok := <-watchCh:
			if !ok {
				watchCh = nil
				continue
			}
			h.reconcileSession(sess, spec)
		}
	}
}

func (h *Hub) runStats(sess *sessionState) {
	interval := h.opts.StatsInterval
	if interval <= 0 {
		interval = defaultStatsInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-sess.done():
			return
		case <-ticker.C:
			sess.emitStats()
		}
	}
}

func (h *Hub) reconcileSession(sess *sessionState, spec capture.Spec) {
	sess.reconcileMu.Lock()
	defer sess.reconcileMu.Unlock()
	if sess.snapshot().GetState() != snifferv1.SessionState_SESSION_STATE_RUNNING {
		return
	}

	sessionID := sess.proto.Id
	matcher, err := discovery.NewPodMatcher(spec)
	if err != nil {
		hubLog.Info("live reconcile matcher failed",
			slog.String("session_id", sessionID),
			slog.String("err", err.Error()),
		)
		return
	}
	pods, err := discovery.ListMatchingPods(sess.context(), h.opts.Kubernetes, spec.Namespace, matcher)
	if err != nil {
		if sess.context().Err() != nil {
			return
		}
		hubLog.Info("live discovery list failed",
			slog.String("session_id", sessionID),
			slog.String("err", err.Error()),
		)
		return
	}
	groups, skipped := discovery.GroupByNode(pods)
	for _, skip := range skipped {
		hubLog.Debug("skipped unscheduled pod during live watch",
			slog.String("session_id", sessionID),
			slog.String("pod", skip.Pod.GetName()),
		)
	}

	desired := make(map[string]discovery.NodeGroup, len(groups))
	desiredUIDs := make(map[string]*snifferv1.PodRef)
	for _, group := range groups {
		desired[group.Node] = group
		for _, target := range group.Targets {
			desiredUIDs[target.GetUid()] = target
		}
	}

	current := sess.currentTargets()
	for uid, ref := range current {
		if _, ok := desiredUIDs[uid]; ok {
			continue
		}
		hubLog.Info("pod detached",
			slog.String("session_id", sessionID),
			slog.String("pod", ref.GetName()),
			slog.String("node", ref.GetNode()),
		)
		sess.emit(&snifferv1.SessionEvent{
			SessionId: sessionID,
			Severity:  snifferv1.Severity_SEVERITY_INFO,
			Message:   fmt.Sprintf("detached pod %s from node %s", ref.GetName(), ref.GetNode()),
			Payload: &snifferv1.SessionEvent_PodDetached{
				PodDetached: &snifferv1.PodDetached{Pod: ref, Reason: "no longer matching or running"},
			},
		})
	}
	for uid, ref := range desiredUIDs {
		if _, ok := current[uid]; ok {
			continue
		}
		hubLog.Info("pod attached",
			slog.String("session_id", sessionID),
			slog.String("pod", ref.GetName()),
			slog.String("node", ref.GetNode()),
		)
		sess.emit(&snifferv1.SessionEvent{
			SessionId: sessionID,
			Severity:  snifferv1.Severity_SEVERITY_INFO,
			Message:   fmt.Sprintf("matched pod %s on node %s", ref.GetName(), ref.GetNode()),
			Payload: &snifferv1.SessionEvent_PodAttached{
				PodAttached: &snifferv1.PodAttached{Pod: ref},
			},
		})
	}

	nodes := make(map[string]struct{})
	for node := range desired {
		nodes[node] = struct{}{}
	}
	for _, node := range sess.agentNodes() {
		nodes[node] = struct{}{}
	}
	for node := range nodes {
		group, ok := desired[node]
		if !ok || len(group.Targets) == 0 {
			if err := h.removeNodeAgent(sess, node); err != nil {
				hubLog.Info("failed to remove idle agent",
					slog.String("session_id", sessionID),
					slog.String("node", node),
					slog.String("err", err.Error()),
				)
			}
			continue
		}
		if err := h.ensureNodeAgent(sess, spec, group); err != nil {
			if sess.context().Err() != nil {
				return
			}
			hubLog.Info("failed to update agent for node",
				slog.String("session_id", sessionID),
				slog.String("node", node),
				slog.String("err", err.Error()),
			)
			sess.emit(&snifferv1.SessionEvent{
				SessionId: sessionID,
				Severity:  snifferv1.Severity_SEVERITY_WARNING,
				Message:   fmt.Sprintf("live agent update on node %s: %v", node, err),
				Payload: &snifferv1.SessionEvent_Error{
					Error: &snifferv1.CaptureError{
						Stage:     snifferv1.ErrorStage_ERROR_STAGE_AGENT_SCHEDULING,
						Reason:    snifferv1.ErrorReason_ERROR_REASON_INTERNAL,
						Detail:    err.Error(),
						Retryable: true,
						Node:      node,
					},
				},
			})
		}
	}

	desiredNodes := make([]string, 0, len(desired))
	for _, group := range groups {
		desiredNodes = append(desiredNodes, group.Node)
	}
	sess.setNodes(desiredNodes)
}

func (h *Hub) ensureNodeAgent(sess *sessionState, spec capture.Spec, group discovery.NodeGroup) error {
	sessionID := sess.proto.Id
	if existing, ok := sess.assignmentForNode(group.Node); ok {
		if assignmentTargetsEqual(existing, group) {
			return nil
		}
		updated := buildAssignment(sessionID, group, spec, existing.GetStreamId())
		sess.updateAssignment(group.Node, updated)
		hubLog.Info("agent targets updated",
			slog.String("session_id", sessionID),
			slog.String("node", group.Node),
			slog.Int("targets", len(group.Targets)),
		)
		sess.emit(&snifferv1.SessionEvent{
			SessionId: sessionID,
			Severity:  snifferv1.Severity_SEVERITY_INFO,
			Message:   fmt.Sprintf("agent targets updated on node %s", group.Node),
			Payload: &snifferv1.SessionEvent_AgentState{
				AgentState: &snifferv1.AgentStateChanged{
					Node:    group.Node,
					Phase:   snifferv1.AgentPhase_AGENT_PHASE_CAPTURING,
					Targets: targetsFromAssignment(updated),
				},
			},
		})
		return nil
	}

	if err := sess.context().Err(); err != nil {
		return err
	}
	if sess.snapshot().GetState() != snifferv1.SessionState_SESSION_STATE_RUNNING &&
		sess.snapshot().GetState() != snifferv1.SessionState_SESSION_STATE_STARTING {
		return fmt.Errorf("session not active")
	}

	requestedStreamID := uuid.NewString()
	createOpts := agent.CreateOptions{
		ActiveDeadline: spec.Duration,
		StreamID:       requestedStreamID,
	}
	pod, err := h.agents.CreateForNode(sess.context(), sessionID, group.Node, createOpts)
	if err != nil {
		return err
	}
	streamID, err := agent.StreamIDFromPod(pod)
	if err != nil {
		return err
	}
	assignment := buildAssignment(sessionID, group, spec, streamID)
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
	if sess.snapshot().GetState() != snifferv1.SessionState_SESSION_STATE_RUNNING &&
		sess.snapshot().GetState() != snifferv1.SessionState_SESSION_STATE_STARTING {
		return fmt.Errorf("session stopped while waiting for agent on node %q", group.Node)
	}

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
	return nil
}

func (h *Hub) removeNodeAgent(sess *sessionState, node string) error {
	if _, ok := sess.assignmentForNode(node); !ok {
		return nil
	}
	sessionID := sess.proto.Id
	rec, ok := sess.agentRecord(node)
	agentPod := ""
	if ok {
		agentPod = rec.podName
	}
	hubLog.Info("removing agent; last target left node",
		slog.String("session_id", sessionID),
		slog.String("node", node),
		slog.String("pod", agentPod),
	)
	sess.emit(&snifferv1.SessionEvent{
		SessionId: sessionID,
		Severity:  snifferv1.Severity_SEVERITY_INFO,
		Message:   fmt.Sprintf("removing agent on node %s", node),
		Payload: &snifferv1.SessionEvent_AgentState{
			AgentState: &snifferv1.AgentStateChanged{
				Node:     node,
				AgentPod: agentPod,
				Phase:    snifferv1.AgentPhase_AGENT_PHASE_TERMINATING,
			},
		},
	})
	if err := h.agents.DeleteAgentOnNode(sess.context(), sessionID, node); err != nil && sess.context().Err() == nil {
		return err
	}
	sess.removeAgent(node)
	sess.emit(&snifferv1.SessionEvent{
		SessionId: sessionID,
		Severity:  snifferv1.Severity_SEVERITY_INFO,
		Message:   fmt.Sprintf("agent gone on node %s", node),
		Payload: &snifferv1.SessionEvent_AgentState{
			AgentState: &snifferv1.AgentStateChanged{
				Node:     node,
				AgentPod: agentPod,
				Phase:    snifferv1.AgentPhase_AGENT_PHASE_GONE,
			},
		},
	})
	return nil
}

func (s *sessionState) agentRecord(node string) (agentRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.agents[node]
	return rec, ok
}

func assignmentTargetsEqual(assignment *snifferv1.AgentAssignment, group discovery.NodeGroup) bool {
	if assignment == nil || len(assignment.GetTargets()) != len(group.Targets) {
		return false
	}
	have := make(map[string]struct{}, len(assignment.GetTargets()))
	for _, t := range assignment.GetTargets() {
		have[t.GetPod().GetUid()] = struct{}{}
	}
	for _, p := range group.Targets {
		if _, ok := have[p.GetUid()]; !ok {
			return false
		}
	}
	return true
}
