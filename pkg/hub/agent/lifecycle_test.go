package agent

import (
	"context"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/sthuck/k8s-sniffer/pkg/capture"
)

const lifecycleTestImage = "example.com/agent@sha256:0000000000000000000000000000000000000000000000000000000000000000"

func testAgentConfig() capture.AgentConfig {
	cfg := capture.DefaultAgentConfig()
	cfg.Image = lifecycleTestImage
	cfg.HubIngestAddr = "127.0.0.1:50051"
	return cfg
}

// newTestClient returns a fake clientset that assigns names from generateName,
// matching apiserver behaviour enough for lifecycle tests.
func newTestClient(objects ...runtime.Object) *fake.Clientset {
	client := fake.NewSimpleClientset(objects...)
	var seq int
	client.PrependReactor("create", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
		create := action.(ktesting.CreateAction)
		pod := create.GetObject().(*corev1.Pod).DeepCopy()
		if pod.Labels != nil && pod.Labels[LabelSessionKey] != "" {
			if pod.Name == "" && pod.GenerateName != "" {
				seq++
				pod.Name = fmt.Sprintf("%s%04d", pod.GenerateName, seq)
			}
		} else if pod.Name == "" && pod.GenerateName != "" {
			seq++
			pod.Name = fmt.Sprintf("%s%04d", pod.GenerateName, seq)
		}
		if err := client.Tracker().Add(pod); err != nil {
			return true, nil, err
		}
		return true, pod, nil
	})
	return client
}

func TestManagerCreateForNode(t *testing.T) {
	client := newTestClient()
	mgr := NewManager(client, testAgentConfig())

	pod, err := mgr.CreateForNode(context.Background(), "sess-1", "node-a", CreateOptions{})
	if err != nil {
		t.Fatalf("CreateForNode: %v", err)
	}
	if pod.Name == "" {
		t.Fatal("expected generated pod name")
	}
	if pod.Spec.NodeName != "node-a" {
		t.Fatalf("nodeName = %q", pod.Spec.NodeName)
	}
	if pod.Labels[LabelSessionKey] != "sess-1" {
		t.Fatalf("session label = %q", pod.Labels[LabelSessionKey])
	}
	if pod.Labels[LabelNodeKey] != "node-a" {
		t.Fatalf("node label = %q", pod.Labels[LabelNodeKey])
	}

	selector, err := SessionLabelSelector("sess-1")
	if err != nil {
		t.Fatalf("SessionLabelSelector: %v", err)
	}
	list, err := client.CoreV1().Pods(cfgNamespace()).List(context.Background(), metav1.ListOptions{
		LabelSelector: selector,
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("listed %d pods, want 1", len(list.Items))
	}
}

func TestCreateForNodeIdempotentPerNode(t *testing.T) {
	client := newTestClient()
	mgr := NewManager(client, testAgentConfig())

	first, err := mgr.CreateForNode(context.Background(), "sess-1", "node-a", CreateOptions{})
	if err != nil {
		t.Fatalf("first CreateForNode: %v", err)
	}
	second, err := mgr.CreateForNode(context.Background(), "sess-1", "node-a", CreateOptions{})
	if err != nil {
		t.Fatalf("second CreateForNode: %v", err)
	}
	if second.Name != first.Name {
		t.Fatalf("duplicate create returned %q, want %q", second.Name, first.Name)
	}
	agents, err := mgr.ListSessionAgents(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("ListSessionAgents: %v", err)
	}
	if len(agents) != 1 {
		t.Fatalf("listed %d agents, want 1", len(agents))
	}
}

func TestManagerWaitReady(t *testing.T) {
	client := newTestClient()
	mgr := NewManager(client, testAgentConfig()).WithReadyTimeout(5 * time.Second)

	pod, err := mgr.CreateForNode(context.Background(), "sess-1", "node-a", CreateOptions{})
	if err != nil {
		t.Fatalf("CreateForNode: %v", err)
	}

	ready := make(chan error, 1)
	go func() {
		ready <- mgr.WaitReady(context.Background(), "sess-1", pod)
	}()

	waitUntil(t, func() bool {
		pod.Status.Phase = corev1.PodRunning
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name:  AgentContainerName,
			Ready: true,
		}}
		_, err := client.CoreV1().Pods(pod.Namespace).Update(context.Background(), pod, metav1.UpdateOptions{})
		return err == nil
	})

	if err := <-ready; err != nil {
		t.Fatalf("WaitReady: %v", err)
	}
}

func TestWaitReadyFailsOnImagePullBackOff(t *testing.T) {
	client := newTestClient()
	mgr := NewManager(client, testAgentConfig()).WithReadyTimeout(2 * time.Second)

	pod, err := mgr.CreateForNode(context.Background(), "sess-1", "node-a", CreateOptions{})
	if err != nil {
		t.Fatalf("CreateForNode: %v", err)
	}

	ready := make(chan error, 1)
	go func() {
		ready <- mgr.WaitReady(context.Background(), "sess-1", pod)
	}()

	waitUntil(t, func() bool {
		pod.Status.Phase = corev1.PodPending
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name: AgentContainerName,
			State: corev1.ContainerState{
				Waiting: &corev1.ContainerStateWaiting{
					Reason:  "ImagePullBackOff",
					Message: "Back-off pulling image",
				},
			},
		}}
		_, err := client.CoreV1().Pods(pod.Namespace).Update(context.Background(), pod, metav1.UpdateOptions{})
		return err == nil
	})

	err = <-ready
	if err == nil {
		t.Fatal("expected error for ImagePullBackOff")
	}
}

func TestWaitReadyFailsOnTerminalPhase(t *testing.T) {
	client := newTestClient()
	mgr := NewManager(client, testAgentConfig()).WithReadyTimeout(2 * time.Second)

	pod, err := mgr.CreateForNode(context.Background(), "sess-1", "node-a", CreateOptions{})
	if err != nil {
		t.Fatalf("CreateForNode: %v", err)
	}

	ready := make(chan error, 1)
	go func() {
		ready <- mgr.WaitReady(context.Background(), "sess-1", pod)
	}()

	waitUntil(t, func() bool {
		pod.Status.Phase = corev1.PodFailed
		_, err := client.CoreV1().Pods(pod.Namespace).Update(context.Background(), pod, metav1.UpdateOptions{})
		return err == nil
	})

	if err := <-ready; err == nil {
		t.Fatal("expected error for Failed phase")
	}
}

func TestManagerDeleteSessionAgents(t *testing.T) {
	client := newTestClient()
	mgr := NewManager(client, testAgentConfig())

	for _, node := range []string{"node-a", "node-b"} {
		if _, err := mgr.CreateForNode(context.Background(), "sess-1", node, CreateOptions{}); err != nil {
			t.Fatalf("CreateForNode(%s): %v", node, err)
		}
	}

	if err := mgr.DeleteSessionAgents(context.Background(), "sess-1"); err != nil {
		t.Fatalf("DeleteSessionAgents: %v", err)
	}

	remaining, err := mgr.ListSessionAgents(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("ListSessionAgents: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("%d agent pods remain after delete", len(remaining))
	}

	if err := mgr.DeleteSessionAgents(context.Background(), "sess-1"); err != nil {
		t.Fatalf("second DeleteSessionAgents: %v", err)
	}
}

func TestSessionLabelSelectorRejectsInvalidSessionID(t *testing.T) {
	if _, err := SessionLabelSelector("bad,id"); err == nil {
		t.Fatal("expected error for invalid label value")
	}
}

func cfgNamespace() string {
	return testAgentConfig().Namespace
}

func waitUntil(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}
