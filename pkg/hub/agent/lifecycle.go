package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	"github.com/sthuck/k8s-sniffer/pkg/capture"
	"github.com/sthuck/k8s-sniffer/pkg/log"
)

var agentLog = log.WithComponent("agent")

// DefaultReadyTimeout is how long CreateSession waits for an agent pod to become
// Ready before failing the session.
const DefaultReadyTimeout = 2 * time.Minute

// Manager creates, watches, and deletes ephemeral agent pods for a session.
type Manager struct {
	client       kubernetes.Interface
	cfg          capture.AgentConfig
	readyTimeout time.Duration
}

// CreateOptions are optional settings for agent pod creation.
type CreateOptions struct {
	// ActiveDeadline is a hard pod lifetime when non-zero (from session duration).
	ActiveDeadline time.Duration
}

// NewManager returns a lifecycle manager. cfg is validated on each call via
// PodManifest.
func NewManager(client kubernetes.Interface, cfg capture.AgentConfig) *Manager {
	return &Manager{
		client:       client,
		cfg:          cfg.WithDefaults(),
		readyTimeout: DefaultReadyTimeout,
	}
}

// WithReadyTimeout overrides the default agent Ready wait (for tests).
func (m *Manager) WithReadyTimeout(d time.Duration) *Manager {
	m.readyTimeout = d
	return m
}

// ReadyTimeout returns the configured agent Ready wait duration.
func (m *Manager) ReadyTimeout() time.Duration {
	return m.readyTimeout
}

// SessionLabelSelector returns the label selector for all agents in a session.
func SessionLabelSelector(sessionID string) (string, error) {
	if err := validateLabelValue("session id", sessionID); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s=%s,%s=%s", LabelAppKey, LabelAppValue, LabelSessionKey, sessionID), nil
}

// SessionNodeLabelSelector returns the selector for one session agent on a node.
func SessionNodeLabelSelector(sessionID, nodeName string) (string, error) {
	base, err := SessionLabelSelector(sessionID)
	if err != nil {
		return "", err
	}
	if err := validateLabelValue("node name", nodeName); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s,%s=%s", base, LabelNodeKey, nodeName), nil
}

func validateLabelValue(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s: required", field)
	}
	if msgs := validation.IsValidLabelValue(value); len(msgs) > 0 {
		return fmt.Errorf("%s: invalid label value %q: %s", field, value, msgs[0])
	}
	return nil
}

// AgentOnNode returns an existing agent pod for sessionID on nodeName, if any.
func (m *Manager) AgentOnNode(ctx context.Context, sessionID, nodeName string) (*corev1.Pod, bool, error) {
	selector, err := SessionNodeLabelSelector(sessionID, nodeName)
	if err != nil {
		return nil, false, err
	}
	list, err := m.client.CoreV1().Pods(m.cfg.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector,
	})
	if err != nil {
		return nil, false, fmt.Errorf("list agent on node %q: %w", nodeName, err)
	}
	agentLog.Debug("listed agents on node",
		slog.String("session_id", sessionID),
		slog.String("node", nodeName),
		slog.String("selector", selector),
		slog.Int("count", len(list.Items)),
	)
	if len(list.Items) == 0 {
		return nil, false, nil
	}
	return &list.Items[0], true, nil
}

// CreateForNode builds and creates an agent pod on nodeName for sessionID. If an
// agent for the same session and node already exists it is returned (idempotent).
func (m *Manager) CreateForNode(ctx context.Context, sessionID, nodeName string, opts CreateOptions) (*corev1.Pod, error) {
	if existing, ok, err := m.AgentOnNode(ctx, sessionID, nodeName); err != nil {
		return nil, err
	} else if ok {
		agentLog.Info("reusing existing agent pod",
			slog.String("session_id", sessionID),
			slog.String("node", nodeName),
			slog.String("pod", existing.Name),
		)
		return existing, nil
	}

	pod, err := PodManifest(sessionID, nodeName, m.cfg, opts.ActiveDeadline)
	if err != nil {
		return nil, err
	}
	agentLog.Debug("creating agent pod",
		slog.String("session_id", sessionID),
		slog.String("node", nodeName),
		slog.String("namespace", m.cfg.Namespace),
	)
	created, err := m.client.CoreV1().Pods(m.cfg.Namespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("create agent pod on node %q: %w", nodeName, err)
	}
	agentLog.Info("agent pod created",
		slog.String("session_id", sessionID),
		slog.String("node", nodeName),
		slog.String("pod", created.Name),
	)
	return created, nil
}

// WaitReady blocks until pod is Running with all containers Ready or ctx/timeout
// expires.
func (m *Manager) WaitReady(ctx context.Context, sessionID string, pod *corev1.Pod) error {
	if pod == nil {
		return fmt.Errorf("pod: required")
	}
	timeout := m.readyTimeout
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	agentLog.Debug("waiting for agent pod ready",
		slog.String("session_id", sessionID),
		slog.String("pod", pod.Name),
		slog.String("namespace", pod.Namespace),
		slog.Duration("timeout", timeout),
	)

	err := wait.PollUntilContextCancel(ctx, 200*time.Millisecond, true, func(ctx context.Context) (bool, error) {
		current, err := m.client.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return false, fmt.Errorf("agent pod %s/%s not found", pod.Namespace, pod.Name)
			}
			if isRetriableAPIError(err) {
				return false, nil
			}
			return false, err
		}
		if reason := podTerminalReason(current); reason != "" {
			return false, fmt.Errorf("agent pod %s/%s: %s", pod.Namespace, pod.Name, reason)
		}
		switch current.Status.Phase {
		case corev1.PodFailed, corev1.PodSucceeded:
			return false, fmt.Errorf("agent pod %s/%s entered phase %s", pod.Namespace, pod.Name, current.Status.Phase)
		case corev1.PodRunning:
			if len(current.Status.ContainerStatuses) == 0 {
				return false, nil
			}
			for _, cs := range current.Status.ContainerStatuses {
				if !cs.Ready {
					if reason := containerTerminalReason(cs); reason != "" {
						return false, fmt.Errorf("agent pod %s/%s: %s", pod.Namespace, pod.Name, reason)
					}
					return false, nil
				}
			}
			return true, nil
		default:
			return false, nil
		}
	})
	if err != nil {
		return err
	}
	agentLog.Info("agent pod ready",
		slog.String("session_id", sessionID),
		slog.String("pod", pod.Name),
		slog.String("namespace", pod.Namespace),
	)
	return nil
}

func isRetriableAPIError(err error) bool {
	return apierrors.IsTimeout(err) ||
		apierrors.IsServerTimeout(err) ||
		apierrors.IsServiceUnavailable(err) ||
		apierrors.IsTooManyRequests(err) ||
		apierrors.IsInternalError(err)
}

func podTerminalReason(pod *corev1.Pod) string {
	for _, cond := range pod.Status.Conditions {
		if cond.Status != corev1.ConditionFalse {
			continue
		}
		switch cond.Type {
		case corev1.PodScheduled:
			return fmt.Sprintf("unschedulable: %s", cond.Message)
		case corev1.DisruptionTarget:
			return fmt.Sprintf("disrupted: %s", cond.Message)
		}
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if reason := containerTerminalReason(cs); reason != "" {
			return reason
		}
	}
	return ""
}

func containerTerminalReason(cs corev1.ContainerStatus) string {
	if w := cs.State.Waiting; w != nil {
		switch w.Reason {
		case "ImagePullBackOff", "ErrImagePull", "InvalidImageName",
			"CreateContainerConfigError", "CreateContainerError",
			"CrashLoopBackOff", "RunContainerError":
			return fmt.Sprintf("container %s: %s: %s", cs.Name, w.Reason, w.Message)
		}
	}
	if t := cs.State.Terminated; t != nil && t.ExitCode != 0 {
		return fmt.Sprintf("container %s exited (%d): %s", cs.Name, t.ExitCode, t.Reason)
	}
	return ""
}

// ListSessionAgents returns agent pods for sessionID.
func (m *Manager) ListSessionAgents(ctx context.Context, sessionID string) ([]corev1.Pod, error) {
	selector, err := SessionLabelSelector(sessionID)
	if err != nil {
		return nil, err
	}
	list, err := m.client.CoreV1().Pods(m.cfg.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector,
	})
	if err != nil {
		return nil, fmt.Errorf("list agent pods for session %q: %w", sessionID, err)
	}
	return list.Items, nil
}

// DeleteSessionAgents removes all agent pods labelled for sessionID.
func (m *Manager) DeleteSessionAgents(ctx context.Context, sessionID string) error {
	selector, err := SessionLabelSelector(sessionID)
	if err != nil {
		return err
	}
	grace := int64(0)
	propagation := metav1.DeletePropagationBackground
	deleteOpts := metav1.DeleteOptions{
		GracePeriodSeconds: &grace,
		PropagationPolicy:  &propagation,
	}
	listOpts := metav1.ListOptions{LabelSelector: selector}

	agentLog.Debug("deleting session agents",
		slog.String("session_id", sessionID),
		slog.String("selector", selector),
	)

	err = m.client.CoreV1().Pods(m.cfg.Namespace).DeleteCollection(ctx, deleteOpts, listOpts)
	if err == nil {
		remaining, listErr := m.ListSessionAgents(ctx, sessionID)
		if listErr != nil {
			return listErr
		}
		if len(remaining) == 0 {
			agentLog.Info("session agents deleted",
				slog.String("session_id", sessionID),
			)
			return nil
		}
	}

	pods, listErr := m.ListSessionAgents(ctx, sessionID)
	if listErr != nil {
		return errors.Join(err, listErr)
	}
	agentLog.Debug("delete collection incomplete, deleting individually",
		slog.String("session_id", sessionID),
		slog.Int("remaining", len(pods)),
	)
	var errs []error
	if err != nil && !apierrors.IsNotFound(err) {
		errs = append(errs, fmt.Errorf("delete collection: %w", err))
	}
	for i := range pods {
		pod := pods[i]
		if delErr := m.client.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, deleteOpts); delErr != nil && !apierrors.IsNotFound(delErr) {
			errs = append(errs, fmt.Errorf("delete agent pod %s/%s: %w", pod.Namespace, pod.Name, delErr))
		}
	}
	if joinErr := errors.Join(errs...); joinErr != nil {
		agentLog.Info("session agent delete had errors",
			slog.String("session_id", sessionID),
			slog.String("err", joinErr.Error()),
		)
		return joinErr
	}
	agentLog.Info("session agents deleted",
		slog.String("session_id", sessionID),
		slog.Int("pods", len(pods)),
	)
	return nil
}
