//go:build integration

package hub_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	"github.com/sthuck/k8s-sniffer/pkg/capture"
	"github.com/sthuck/k8s-sniffer/pkg/hub"
	"github.com/sthuck/k8s-sniffer/pkg/hub/agent"
)

// IT1.1 — CreateSession creates agent Pod objects against a real apiserver
// (envtest); StopSession deletes them. envtest has no kubelet, so a background
// marker patches agent pod status to Ready so WaitReady can succeed.

func TestIT1_1_CreateSessionSchedulesAndStopDeletesAgents(t *testing.T) {
	client := startEnvtest(t)
	cancelMarker := startAgentReadyMarker(t, client, capture.DefaultAgentNamespace)
	t.Cleanup(cancelMarker)

	mustCreateNamespace(t, client, "prod")
	mustCreateNamespace(t, client, capture.DefaultAgentNamespace)
	mustCreateWorkloadPods(t, client, "prod",
		workloadPod("payments-api", "node-a"),
		workloadPod("checkout-web", "node-b"),
	)

	hubClient, cleanup := startEnvtestHub(t, client)
	t.Cleanup(cleanup)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	created, err := hubClient.CreateSession(ctx, &snifferv1.CreateSessionRequest{
		Spec: &snifferv1.CaptureSpec{
			Namespace:   "prod",
			PodPatterns: []string{"payments-.*", "checkout-.*"},
			TlsMode:     snifferv1.TlsMode_TLS_MODE_OFF,
		},
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	session := created.GetSession()
	if session.GetId() == "" {
		t.Fatal("expected session id")
	}
	if session.GetState() != snifferv1.SessionState_SESSION_STATE_RUNNING {
		t.Fatalf("state = %s, want RUNNING (failure=%q)", session.GetState(), session.GetFailureReason())
	}
	if len(session.GetNodes()) != 2 {
		t.Fatalf("nodes = %v, want 2", session.GetNodes())
	}

	selector, err := agent.SessionLabelSelector(session.GetId())
	if err != nil {
		t.Fatalf("SessionLabelSelector: %v", err)
	}
	agents, err := client.CoreV1().Pods(capture.DefaultAgentNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector,
	})
	if err != nil {
		t.Fatalf("list agents: %v", err)
	}
	if len(agents.Items) != 2 {
		t.Fatalf("created %d agent pods, want 2", len(agents.Items))
	}

	stopped, err := hubClient.StopSession(ctx, &snifferv1.StopSessionRequest{SessionId: session.GetId()})
	if err != nil {
		t.Fatalf("StopSession: %v", err)
	}
	if stopped.GetSession().GetState() != snifferv1.SessionState_SESSION_STATE_STOPPED {
		t.Fatalf("state = %s, want STOPPED", stopped.GetSession().GetState())
	}

	remaining, err := client.CoreV1().Pods(capture.DefaultAgentNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector,
	})
	if err != nil {
		t.Fatalf("list agents after stop: %v", err)
	}
	if len(remaining.Items) != 0 {
		names := make([]string, 0, len(remaining.Items))
		for _, p := range remaining.Items {
			names = append(names, p.Name)
		}
		t.Fatalf("%d agent pods remain after StopSession: %v", len(remaining.Items), names)
	}
}

func startEnvtest(t *testing.T) *kubernetes.Clientset {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Fatal("KUBEBUILDER_ASSETS is unset; run via `make integration-test` (setup-envtest)")
	}

	testEnv := &envtest.Environment{}
	cfg, err := testEnv.Start()
	if err != nil {
		t.Fatalf("envtest start: %v", err)
	}
	t.Cleanup(func() {
		if err := testEnv.Stop(); err != nil {
			t.Errorf("envtest stop: %v", err)
		}
	})

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("kubernetes client: %v", err)
	}
	return client
}

func startEnvtestHub(t *testing.T, client kubernetes.Interface) (snifferv1.HubServiceClient, func()) {
	t.Helper()
	cfg := capture.DefaultAgentConfig()
	cfg.Image = "example.com/agent@sha256:0000000000000000000000000000000000000000000000000000000000000000"
	cfg.HubIngestAddr = "127.0.0.1:50051"

	h, err := hub.New(hub.Options{
		Kubernetes:   client,
		Agent:        cfg,
		ReadyTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("hub.New: %v", err)
	}

	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	snifferv1.RegisterHubServiceServer(server, h)
	snifferv1.RegisterAgentIngestServiceServer(server, h)
	go func() { _ = server.Serve(listener) }()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	cleanup := func() {
		_ = conn.Close()
		server.Stop()
		_ = h.StopAll(context.Background())
	}
	return snifferv1.NewHubServiceClient(conn), cleanup
}

func startAgentReadyMarker(t *testing.T, client kubernetes.Interface, namespace string) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				markPendingAgentsReady(ctx, client, namespace)
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

func markPendingAgentsReady(ctx context.Context, client kubernetes.Interface, namespace string) {
	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", agent.LabelAppKey, agent.LabelAppValue),
	})
	if err != nil {
		return
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		// envtest has no kubelet to finish pod deletion. Clear finalizers and
		// force-delete so StopSession's waitSessionAgentsGone can observe removal.
		if pod.DeletionTimestamp != nil {
			if len(pod.Finalizers) > 0 {
				fresh, err := client.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
				if err == nil {
					fresh.Finalizers = nil
					_, _ = client.CoreV1().Pods(fresh.Namespace).Update(ctx, fresh, metav1.UpdateOptions{})
				}
			}
			grace := int64(0)
			_ = client.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{
				GracePeriodSeconds: &grace,
			})
			continue
		}
		if agentPodReady(pod) {
			continue
		}
		pod.Status.Phase = corev1.PodRunning
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name:  agent.AgentContainerName,
			Ready: true,
			State: corev1.ContainerState{
				Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()},
			},
		}}
		_, _ = client.CoreV1().Pods(pod.Namespace).UpdateStatus(ctx, pod, metav1.UpdateOptions{})
	}
}

func agentPodReady(pod *corev1.Pod) bool {
	if pod.Status.Phase != corev1.PodRunning {
		return false
	}
	if len(pod.Status.ContainerStatuses) == 0 {
		return false
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if !cs.Ready {
			return false
		}
	}
	return true
}

func mustCreateNamespace(t *testing.T, client kubernetes.Interface, name string) {
	t.Helper()
	_, err := client.CoreV1().Namespaces().Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create namespace %q: %v", name, err)
	}
}

func workloadPod(name, node string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "prod",
			UID:       "", // apiserver assigns
		},
		Spec: corev1.PodSpec{
			NodeName: node,
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "example.com/app:test",
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func mustCreateWorkloadPods(t *testing.T, client kubernetes.Interface, namespace string, pods ...*corev1.Pod) {
	t.Helper()
	for _, pod := range pods {
		pod.Namespace = namespace
		created, err := client.CoreV1().Pods(namespace).Create(context.Background(), pod, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("create pod %s/%s: %v", namespace, pod.Name, err)
		}
		// Status is stripped on create; patch Running so discovery's Running-only filter matches.
		created.Status.Phase = corev1.PodRunning
		if _, err := client.CoreV1().Pods(namespace).UpdateStatus(context.Background(), created, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("update pod status %s/%s: %v", namespace, pod.Name, err)
		}
	}
}
