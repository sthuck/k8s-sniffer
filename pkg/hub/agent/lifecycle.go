package agent

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	"github.com/sthuck/k8s-sniffer/pkg/capture"
)

// DefaultReadyTimeout is how long CreateSession waits for an agent pod to become
// Ready before failing the session.
const DefaultReadyTimeout = 2 * time.Minute

// Manager creates, watches, and deletes ephemeral agent pods for a session.
type Manager struct {
	client       kubernetes.Interface
	cfg          capture.AgentConfig
	readyTimeout time.Duration
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

// SessionLabelSelector returns the label selector for all agents in a session.
func SessionLabelSelector(sessionID string) string {
	return fmt.Sprintf("%s=%s,%s=%s", LabelAppKey, LabelAppValue, LabelSessionKey, sessionID)
}

// CreateForNode builds and creates an agent pod on nodeName for sessionID.
func (m *Manager) CreateForNode(ctx context.Context, sessionID, nodeName string) (*corev1.Pod, error) {
	pod, err := PodManifest(sessionID, nodeName, m.cfg)
	if err != nil {
		return nil, err
	}
	created, err := m.client.CoreV1().Pods(m.cfg.Namespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("create agent pod on node %q: %w", nodeName, err)
	}
	return created, nil
}

// WaitReady blocks until pod is Running with all containers Ready or ctx/timeout
// expires.
func (m *Manager) WaitReady(ctx context.Context, pod *corev1.Pod) error {
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

	return wait.PollUntilContextCancel(ctx, 200*time.Millisecond, true, func(ctx context.Context) (bool, error) {
		current, err := m.client.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
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
					return false, nil
				}
			}
			return true, nil
		default:
			return false, nil
		}
	})
}

// ListSessionAgents returns agent pods for sessionID.
func (m *Manager) ListSessionAgents(ctx context.Context, sessionID string) ([]corev1.Pod, error) {
	list, err := m.client.CoreV1().Pods(m.cfg.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: SessionLabelSelector(sessionID),
	})
	if err != nil {
		return nil, fmt.Errorf("list agent pods for session %q: %w", sessionID, err)
	}
	return list.Items, nil
}

// DeleteSessionAgents removes all agent pods labelled for sessionID.
func (m *Manager) DeleteSessionAgents(ctx context.Context, sessionID string) error {
	pods, err := m.ListSessionAgents(ctx, sessionID)
	if err != nil {
		return err
	}
	var firstErr error
	for i := range pods {
		pod := pods[i]
		err := m.client.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			firstErr = fmt.Errorf("delete agent pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
	}
	return firstErr
}
