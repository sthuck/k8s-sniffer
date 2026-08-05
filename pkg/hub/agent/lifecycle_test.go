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
		if pod.Name == "" && pod.GenerateName != "" {
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

	pod, err := mgr.CreateForNode(context.Background(), "sess-1", "node-a")
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

	list, err := client.CoreV1().Pods(cfgNamespace()).List(context.Background(), metav1.ListOptions{
		LabelSelector: SessionLabelSelector("sess-1"),
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("listed %d pods, want 1", len(list.Items))
	}
}

func TestManagerWaitReady(t *testing.T) {
	client := newTestClient()
	mgr := NewManager(client, testAgentConfig()).WithReadyTimeout(5 * time.Second)

	pod, err := mgr.CreateForNode(context.Background(), "sess-1", "node-a")
	if err != nil {
		t.Fatalf("CreateForNode: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- mgr.WaitReady(context.Background(), pod)
	}()

	time.Sleep(300 * time.Millisecond)
	pod.Status.Phase = corev1.PodRunning
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name:  AgentContainerName,
		Ready: true,
	}}
	if _, err := client.CoreV1().Pods(pod.Namespace).Update(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update pod status: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WaitReady: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("WaitReady timed out")
	}
}

func TestManagerDeleteSessionAgents(t *testing.T) {
	client := newTestClient()
	mgr := NewManager(client, testAgentConfig())

	for _, node := range []string{"node-a", "node-b"} {
		if _, err := mgr.CreateForNode(context.Background(), "sess-1", node); err != nil {
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
}

func cfgNamespace() string {
	return testAgentConfig().Namespace
}
