//go:build integration

package hub_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	"github.com/sthuck/k8s-sniffer/pkg/capture"
	"github.com/sthuck/k8s-sniffer/pkg/hub"
	"github.com/sthuck/k8s-sniffer/pkg/hub/agent"
)

// IT1.1 — CreateSession creates agent Pod objects against a real apiserver
// (envtest); StopSession deletes them. envtest has no kubelet, so a fakeKubelet
// marks agents Ready and finishes pod GC after Hub stamps DeletionTimestamp.

func TestIT1_1_CreateSessionSchedulesAndStopDeletesAgents(t *testing.T) {
	client := startEnvtest(t)
	fk := startFakeKubelet(t, client, capture.DefaultAgentNamespace)
	t.Cleanup(fk.stop)

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
	assertAgentsPinnedToSessionNodes(t, session.GetNodes(), agents.Items)

	// Pause GC so we can observe Hub-issued deletion before fake kubelet removes pods.
	fk.setGC(false)
	stopErr := make(chan error, 1)
	go func() {
		_, err := hubClient.StopSession(ctx, &snifferv1.StopSessionRequest{SessionId: session.GetId()})
		stopErr <- err
	}()

	waitUntil(t, 10*time.Second, func() bool {
		list, err := client.CoreV1().Pods(capture.DefaultAgentNamespace).List(ctx, metav1.ListOptions{
			LabelSelector: selector,
		})
		if err != nil || len(list.Items) != 2 {
			return false
		}
		for _, pod := range list.Items {
			if pod.DeletionTimestamp == nil {
				return false
			}
		}
		return true
	})

	fk.setGC(true)
	if err := <-stopErr; err != nil {
		t.Fatalf("StopSession: %v", err)
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

func assertAgentsPinnedToSessionNodes(t *testing.T, sessionNodes []string, agents []corev1.Pod) {
	t.Helper()
	want := map[string]struct{}{}
	for _, n := range sessionNodes {
		want[n] = struct{}{}
	}
	got := map[string]struct{}{}
	for _, pod := range agents {
		nodeLabel := pod.Labels[agent.LabelNodeKey]
		if nodeLabel == "" {
			t.Fatalf("agent %s missing %s label", pod.Name, agent.LabelNodeKey)
		}
		if pod.Spec.NodeName != nodeLabel {
			t.Fatalf("agent %s nodeName=%q label=%q", pod.Name, pod.Spec.NodeName, nodeLabel)
		}
		if _, ok := want[nodeLabel]; !ok {
			t.Fatalf("agent %s on unexpected node %q (session nodes %v)", pod.Name, nodeLabel, sessionNodes)
		}
		got[nodeLabel] = struct{}{}
	}
	for n := range want {
		if _, ok := got[n]; !ok {
			t.Fatalf("no agent pod for session node %q (agents cover %v)", n, keys(got))
		}
	}
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
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

// fakeKubelet stands in for the missing envtest kubelet: Ready status + GC of
// Terminating agent pods after Hub issues delete.
type fakeKubelet struct {
	mu       sync.Mutex
	gc       bool
	client   kubernetes.Interface
	ns       string
	cancel   context.CancelFunc
	done     chan struct{}
	lastErr  error
	errCount int
}

func startFakeKubelet(t *testing.T, client kubernetes.Interface, namespace string) *fakeKubelet {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	fk := &fakeKubelet{
		gc:     true,
		client: client,
		ns:     namespace,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go func() {
		defer close(fk.done)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := fk.tick(ctx); err != nil && !apierrors.IsNotFound(err) && ctx.Err() == nil {
					fk.mu.Lock()
					fk.lastErr = err
					fk.errCount++
					fk.mu.Unlock()
					t.Logf("fake kubelet: %v", err)
				}
			}
		}
	}()
	t.Cleanup(func() {
		fk.mu.Lock()
		n, err := fk.errCount, fk.lastErr
		fk.mu.Unlock()
		if n > 0 && err != nil {
			t.Logf("fake kubelet recorded %d errors; last: %v", n, err)
		}
	})
	return fk
}

func (fk *fakeKubelet) setGC(enabled bool) {
	fk.mu.Lock()
	fk.gc = enabled
	fk.mu.Unlock()
}

func (fk *fakeKubelet) stop() {
	fk.cancel()
	<-fk.done
}

func (fk *fakeKubelet) tick(ctx context.Context) error {
	fk.mu.Lock()
	gc := fk.gc
	fk.mu.Unlock()

	pods, err := fk.client.CoreV1().Pods(fk.ns).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", agent.LabelAppKey, agent.LabelAppValue),
	})
	if err != nil {
		return fmt.Errorf("list agents: %w", err)
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.DeletionTimestamp != nil {
			if !gc {
				continue
			}
			if err := fk.finishDelete(ctx, pod); err != nil {
				return err
			}
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
		if _, err := fk.client.CoreV1().Pods(pod.Namespace).UpdateStatus(ctx, pod, metav1.UpdateOptions{}); err != nil {
			if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("mark ready %s/%s: %w", pod.Namespace, pod.Name, err)
		}
	}
	return nil
}

func (fk *fakeKubelet) finishDelete(ctx context.Context, pod *corev1.Pod) error {
	if len(pod.Finalizers) > 0 {
		fresh, err := fk.client.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}
			return fmt.Errorf("get terminating %s/%s: %w", pod.Namespace, pod.Name, err)
		}
		fresh.Finalizers = nil
		if _, err := fk.client.CoreV1().Pods(fresh.Namespace).Update(ctx, fresh, metav1.UpdateOptions{}); err != nil {
			if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
				return nil
			}
			return fmt.Errorf("clear finalizers %s/%s: %w", fresh.Namespace, fresh.Name, err)
		}
	}
	grace := int64(0)
	if err := fk.client.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{
		GracePeriodSeconds: &grace,
	}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("force delete %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	return nil
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
		created.Status.Phase = corev1.PodRunning
		if _, err := client.CoreV1().Pods(namespace).UpdateStatus(context.Background(), created, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("update pod status %s/%s: %v", namespace, pod.Name, err)
		}
	}
}

func waitUntil(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}
