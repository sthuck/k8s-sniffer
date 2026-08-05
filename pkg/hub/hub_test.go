package hub_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	"github.com/sthuck/k8s-sniffer/pkg/capture"
	"github.com/sthuck/k8s-sniffer/pkg/hub"
	"github.com/sthuck/k8s-sniffer/pkg/hub/agent"
)

const testImage = "example.com/agent@sha256:0000000000000000000000000000000000000000000000000000000000000000"

func testAgentConfig() capture.AgentConfig {
	cfg := capture.DefaultAgentConfig()
	cfg.Image = testImage
	return cfg
}

func newTestKubernetes(objects ...runtime.Object) *fake.Clientset {
	client := fake.NewSimpleClientset(objects...)
	var seq int
	client.PrependReactor("create", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
		create := action.(ktesting.CreateAction)
		pod := create.GetObject().(*corev1.Pod).DeepCopy()
		if pod.Labels != nil && pod.Labels[agent.LabelSessionKey] != "" {
			if pod.Name == "" && pod.GenerateName != "" {
				seq++
				pod.Name = fmt.Sprintf("%s%04d", pod.GenerateName, seq)
			}
			pod.Status.Phase = corev1.PodRunning
			pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
				Name:  agent.AgentContainerName,
				Ready: true,
			}}
		}
		if err := client.Tracker().Add(pod); err != nil {
			return true, nil, err
		}
		return true, pod, nil
	})
	return client
}

func testWorkloadPods() []runtime.Object {
	return []runtime.Object{
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
	}
}

func startTestHub(t *testing.T, client *fake.Clientset) (snifferv1.HubServiceClient, func()) {
	t.Helper()
	h, err := hub.New(hub.Options{
		Kubernetes:   client,
		Agent:        testAgentConfig(),
		ReadyTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
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

func TestCreateSessionSchedulesAgents(t *testing.T) {
	client := newTestKubernetes(testWorkloadPods()...)
	hubClient, cleanup := startTestHub(t, client)
	defer cleanup()

	ctx := context.Background()
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
		t.Fatalf("state = %s, want RUNNING", session.GetState())
	}
	if len(session.GetNodes()) != 2 {
		t.Fatalf("nodes = %v, want 2", session.GetNodes())
	}

	agents, err := client.CoreV1().Pods("k8s-sniffer").List(ctx, metav1.ListOptions{
		LabelSelector: agent.SessionLabelSelector(session.GetId()),
	})
	if err != nil {
		t.Fatalf("list agents: %v", err)
	}
	if len(agents.Items) != 2 {
		t.Fatalf("created %d agent pods, want 2", len(agents.Items))
	}
}

func TestStopSessionDeletesAgents(t *testing.T) {
	client := newTestKubernetes(testWorkloadPods()...)
	hubClient, cleanup := startTestHub(t, client)
	defer cleanup()

	ctx := context.Background()
	created, err := hubClient.CreateSession(ctx, &snifferv1.CreateSessionRequest{
		Spec: &snifferv1.CaptureSpec{
			Namespace:   "prod",
			PodPatterns: []string{"payments-.*"},
			TlsMode:     snifferv1.TlsMode_TLS_MODE_OFF,
		},
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	sessionID := created.GetSession().GetId()

	stopped, err := hubClient.StopSession(ctx, &snifferv1.StopSessionRequest{SessionId: sessionID})
	if err != nil {
		t.Fatalf("StopSession: %v", err)
	}
	if stopped.GetSession().GetState() != snifferv1.SessionState_SESSION_STATE_STOPPED {
		t.Fatalf("state = %s, want STOPPED", stopped.GetSession().GetState())
	}

	remaining, err := client.CoreV1().Pods("k8s-sniffer").List(ctx, metav1.ListOptions{
		LabelSelector: agent.SessionLabelSelector(sessionID),
	})
	if err != nil {
		t.Fatalf("list agents: %v", err)
	}
	if len(remaining.Items) != 0 {
		t.Fatalf("%d agent pods remain after StopSession", len(remaining.Items))
	}
}

func TestCreateSessionRejectsInvalidSpec(t *testing.T) {
	client := newTestKubernetes()
	hubClient, cleanup := startTestHub(t, client)
	defer cleanup()

	_, err := hubClient.CreateSession(context.Background(), &snifferv1.CreateSessionRequest{
		Spec: &snifferv1.CaptureSpec{Namespace: "", PodPatterns: []string{"api-.*"}},
	})
	if err == nil {
		t.Fatal("expected InvalidArgument for empty namespace")
	}
}

func TestWatchTargetsDeliversAssignment(t *testing.T) {
	client := newTestKubernetes(testWorkloadPods()...)
	listener := bufconn.Listen(1 << 20)
	h, err := hub.New(hub.Options{Kubernetes: client, Agent: testAgentConfig(), ReadyTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	server := grpc.NewServer()
	snifferv1.RegisterHubServiceServer(server, h)
	snifferv1.RegisterAgentIngestServiceServer(server, h)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	ctx := context.Background()
	hubClient := snifferv1.NewHubServiceClient(conn)
	ingestClient := snifferv1.NewAgentIngestServiceClient(conn)

	created, err := hubClient.CreateSession(ctx, &snifferv1.CreateSessionRequest{
		Spec: &snifferv1.CaptureSpec{
			Namespace:   "prod",
			PodPatterns: []string{"payments-.*"},
			TlsMode:     snifferv1.TlsMode_TLS_MODE_OFF,
		},
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	node := created.GetSession().GetNodes()[0]

	stream, err := ingestClient.WatchTargets(ctx, &snifferv1.WatchTargetsRequest{
		SessionId: created.GetSession().GetId(),
		Node:      node,
		AgentPod:  "k8s-sniffer-0001",
	})
	if err != nil {
		t.Fatalf("WatchTargets: %v", err)
	}
	assignment, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv assignment: %v", err)
	}
	if assignment.GetSessionId() != created.GetSession().GetId() {
		t.Fatalf("session id = %q", assignment.GetSessionId())
	}
	if assignment.GetStreamId() == "" {
		t.Fatal("expected stream_id")
	}
	if _, err := uuid.Parse(assignment.GetStreamId()); err != nil {
		t.Fatalf("stream_id not a uuid: %v", err)
	}
	if len(assignment.GetTargets()) != 1 {
		t.Fatalf("targets = %d, want 1", len(assignment.GetTargets()))
	}
	if assignment.GetTargets()[0].GetPod().GetName() != "payments-api" {
		t.Fatalf("target pod = %q", assignment.GetTargets()[0].GetPod().GetName())
	}
}
