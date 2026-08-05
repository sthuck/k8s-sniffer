package discovery

import (
	corev1 "k8s.io/api/core/v1"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
)

const (
	// SkipReasonNoNode is emitted when a matched Running pod has no nodeName yet.
	SkipReasonNoNode = "pod has no nodeName assigned"
)

// SkippedPod records a matched pod that cannot be scheduled for capture yet.
type SkippedPod struct {
	Pod    *snifferv1.PodRef
	Reason string
}

// NodeGroup is the set of capture targets on one node.
type NodeGroup struct {
	Node    string
	Targets []*snifferv1.PodRef
}

// GroupByNode maps Running matched pods to their nodeName. Pods with an empty
// nodeName are returned in skipped so the hub can emit a structured event.
func GroupByNode(pods []corev1.Pod) (groups []NodeGroup, skipped []SkippedPod) {
	byNode := make(map[string][]*snifferv1.PodRef)
	order := make([]string, 0)

	for i := range pods {
		pod := pods[i]
		ref := PodRefFromPod(pod)
		if pod.Spec.NodeName == "" {
			skipped = append(skipped, SkippedPod{Pod: ref, Reason: SkipReasonNoNode})
			continue
		}
		ref.Node = pod.Spec.NodeName
		if _, ok := byNode[pod.Spec.NodeName]; !ok {
			order = append(order, pod.Spec.NodeName)
		}
		byNode[pod.Spec.NodeName] = append(byNode[pod.Spec.NodeName], ref)
	}

	groups = make([]NodeGroup, 0, len(order))
	for _, node := range order {
		groups = append(groups, NodeGroup{
			Node:    node,
			Targets: byNode[node],
		})
	}
	return groups, skipped
}

// GroupMatchingPods filters pods with matcher, then groups by node.
func GroupMatchingPods(pods []corev1.Pod, matcher *PodMatcher) (groups []NodeGroup, skipped []SkippedPod) {
	matched := make([]corev1.Pod, 0, len(pods))
	for i := range pods {
		pod := pods[i]
		if !IsRunning(&pod) || !matcher.MatchName(pod.Name) {
			continue
		}
		matched = append(matched, pod)
	}
	return GroupByNode(matched)
}
