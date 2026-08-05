// Package discovery implements pod listing and filtering for capture sessions.
package discovery

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	"github.com/sthuck/k8s-sniffer/pkg/capture"
	"github.com/sthuck/k8s-sniffer/pkg/log"
)

var discoveryLog = log.WithComponent("discovery")

// PodMatcher filters pods by RE2 name patterns from a capture spec.
type PodMatcher struct {
	patterns []*regexp.Regexp
}

// NewPodMatcher compiles spec.PodPatterns. Callers should pass a validated spec.
func NewPodMatcher(spec capture.Spec) (*PodMatcher, error) {
	patterns, err := spec.CompilePatterns()
	if err != nil {
		return nil, err
	}
	return &PodMatcher{patterns: patterns}, nil
}

// MatchName reports whether name matches any configured pattern. Patterns are
// unanchored RE2 regexes OR-ed together.
func (m *PodMatcher) MatchName(name string) bool {
	for _, re := range m.patterns {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// IsRunning reports whether pod is in the Running phase.
func IsRunning(pod *corev1.Pod) bool {
	return pod != nil && pod.Status.Phase == corev1.PodRunning
}

// PodRefFromPod builds a PodRef from API metadata. container_id is left empty
// until netns resolution (T1.10).
func PodRefFromPod(pod corev1.Pod) *snifferv1.PodRef {
	return &snifferv1.PodRef{
		Namespace: pod.Namespace,
		Name:      pod.Name,
		Uid:       string(pod.UID),
		Node:      pod.Spec.NodeName,
	}
}

// ListMatchingPods lists pods in namespace and returns Running pods whose names
// match the matcher. Non-Running and non-matching pods are excluded.
func ListMatchingPods(ctx context.Context, client kubernetes.Interface, namespace string, matcher *PodMatcher) ([]corev1.Pod, error) {
	if matcher == nil {
		return nil, fmt.Errorf("matcher: required")
	}
	if namespace == "" {
		return nil, fmt.Errorf("namespace: required")
	}

	list, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods in namespace %q: %w", namespace, err)
	}

	discoveryLog.Debug("listed namespace pods",
		slog.String("namespace", namespace),
		slog.Int("total", len(list.Items)),
	)

	matched := make([]corev1.Pod, 0, len(list.Items))
	for i := range list.Items {
		pod := list.Items[i]
		if !IsRunning(&pod) {
			continue
		}
		if !matcher.MatchName(pod.Name) {
			continue
		}
		matched = append(matched, pod)
	}
	discoveryLog.Debug("filtered matching running pods",
		slog.String("namespace", namespace),
		slog.Int("matched", len(matched)),
	)
	return matched, nil
}
