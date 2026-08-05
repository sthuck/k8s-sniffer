package discovery

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGroupByNode(t *testing.T) {
	pods := []corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "payments-api", Namespace: "prod", UID: "uid-1"},
			Spec:       corev1.PodSpec{NodeName: "node-a"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "checkout-web", Namespace: "prod", UID: "uid-2"},
			Spec:       corev1.PodSpec{NodeName: "node-a"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "payments-worker", Namespace: "prod", UID: "uid-3"},
			Spec:       corev1.PodSpec{NodeName: "node-b"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "payments-unscheduled", Namespace: "prod", UID: "uid-4"},
			Spec:       corev1.PodSpec{},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
	}

	groups, skipped := GroupByNode(pods)
	if len(groups) != 2 {
		t.Fatalf("got %d node groups, want 2", len(groups))
	}
	if groups[0].Node != "node-a" || len(groups[0].Targets) != 2 {
		t.Fatalf("node-a group: %+v", groups[0])
	}
	if groups[1].Node != "node-b" || len(groups[1].Targets) != 1 {
		t.Fatalf("node-b group: %+v", groups[1])
	}
	if len(skipped) != 1 {
		t.Fatalf("skipped %d pods, want 1", len(skipped))
	}
	if skipped[0].Reason != SkipReasonNoNode {
		t.Fatalf("skip reason = %q, want %q", skipped[0].Reason, SkipReasonNoNode)
	}
	if skipped[0].Pod.Name != "payments-unscheduled" {
		t.Fatalf("skipped pod = %q", skipped[0].Pod.Name)
	}
}

func TestGroupMatchingPods(t *testing.T) {
	matcher := testMatcher(t)
	pods := []corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "payments-api", Namespace: "prod", UID: "uid-1"},
			Spec:       corev1.PodSpec{NodeName: "node-a"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "billing-api", Namespace: "prod", UID: "uid-2"},
			Spec:       corev1.PodSpec{NodeName: "node-a"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "payments-pending", Namespace: "prod", UID: "uid-3"},
			Spec:       corev1.PodSpec{NodeName: "node-a"},
			Status:     corev1.PodStatus{Phase: corev1.PodPending},
		},
	}

	groups, skipped := GroupMatchingPods(pods, matcher)
	if len(groups) != 1 || groups[0].Node != "node-a" || len(groups[0].Targets) != 1 {
		t.Fatalf("groups = %+v", groups)
	}
	if len(skipped) != 0 {
		t.Fatalf("skipped = %+v", skipped)
	}
}
