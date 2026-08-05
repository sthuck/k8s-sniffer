package discovery

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/sthuck/k8s-sniffer/pkg/capture"
)

func testMatcher(t *testing.T) *PodMatcher {
	t.Helper()
	matcher, err := NewPodMatcher(capture.Spec{
		Namespace:   "prod",
		PodPatterns: []string{"payments-.*", "checkout-.*"},
		TLSMode:     capture.TLSModeOff,
	})
	if err != nil {
		t.Fatalf("NewPodMatcher: %v", err)
	}
	return matcher
}

func TestPodMatcherMatchName(t *testing.T) {
	matcher := testMatcher(t)

	tests := []struct {
		name  string
		pod   string
		match bool
	}{
		{name: "payments prefix", pod: "payments-api", match: true},
		{name: "checkout prefix", pod: "checkout-web", match: true},
		{name: "no match", pod: "billing-api", match: false},
		{name: "partial overlap", pod: "api-payments", match: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matcher.MatchName(tt.pod); got != tt.match {
				t.Fatalf("MatchName(%q) = %v, want %v", tt.pod, got, tt.match)
			}
		})
	}
}

func TestIsRunning(t *testing.T) {
	if !IsRunning(&corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning}}) {
		t.Fatal("expected Running pod to match")
	}
	for _, phase := range []corev1.PodPhase{corev1.PodPending, corev1.PodSucceeded, corev1.PodFailed, corev1.PodUnknown} {
		if IsRunning(&corev1.Pod{Status: corev1.PodStatus{Phase: phase}}) {
			t.Fatalf("phase %q should not match", phase)
		}
	}
}

func TestListMatchingPods(t *testing.T) {
	matcher := testMatcher(t)
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "payments-api", Namespace: "prod", UID: "uid-1"},
			Spec:       corev1.PodSpec{NodeName: "node-a"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "checkout-web", Namespace: "prod", UID: "uid-2"},
			Spec:       corev1.PodSpec{NodeName: "node-b"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "billing-api", Namespace: "prod", UID: "uid-3"},
			Spec:       corev1.PodSpec{NodeName: "node-a"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "payments-old", Namespace: "prod", UID: "uid-4"},
			Spec:       corev1.PodSpec{NodeName: "node-a"},
			Status:     corev1.PodStatus{Phase: corev1.PodSucceeded},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "payments-pending", Namespace: "prod", UID: "uid-5"},
			Spec:       corev1.PodSpec{NodeName: "node-a"},
			Status:     corev1.PodStatus{Phase: corev1.PodPending},
		},
	)

	got, err := ListMatchingPods(context.Background(), client, "prod", matcher)
	if err != nil {
		t.Fatalf("ListMatchingPods: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("matched %d pods, want 2", len(got))
	}

	names := map[string]struct{}{}
	for _, pod := range got {
		names[pod.Name] = struct{}{}
	}
	for _, want := range []string{"payments-api", "checkout-web"} {
		if _, ok := names[want]; !ok {
			t.Fatalf("missing matched pod %q", want)
		}
	}
}

func TestPodRefFromPod(t *testing.T) {
	ref := PodRefFromPod(corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "prod",
			Name:      "payments-api",
			UID:       "uid-1",
		},
		Spec: corev1.PodSpec{NodeName: "node-a"},
	})
	if ref.Namespace != "prod" || ref.Name != "payments-api" || ref.Uid != "uid-1" || ref.Node != "node-a" {
		t.Fatalf("unexpected PodRef: %+v", ref)
	}
	if ref.ContainerId != "" {
		t.Fatalf("container_id should be empty before T1.10, got %q", ref.ContainerId)
	}
}
