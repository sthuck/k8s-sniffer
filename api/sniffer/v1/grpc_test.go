package snifferv1_test

import (
	"context"
	"io"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
)

// The generated Unimplemented* types must satisfy the server interfaces so the
// hub can embed them while methods land task by task.
var (
	_ snifferv1.HubServiceServer         = (*snifferv1.UnimplementedHubServiceServer)(nil)
	_ snifferv1.AgentIngestServiceServer = (*snifferv1.UnimplementedAgentIngestServiceServer)(nil)
)

// stubHub implements just enough of HubService to prove the generated unary and
// server-streaming stubs are wired correctly.
type stubHub struct {
	snifferv1.UnimplementedHubServiceServer
}

func (stubHub) CreateSession(_ context.Context, req *snifferv1.CreateSessionRequest) (*snifferv1.CreateSessionResponse, error) {
	return &snifferv1.CreateSessionResponse{Session: &snifferv1.Session{
		Id:    "sess-1",
		Spec:  req.GetSpec(),
		State: snifferv1.SessionState_SESSION_STATE_PENDING,
	}}, nil
}

func (stubHub) SubscribePackets(req *snifferv1.SubscribePacketsRequest, stream snifferv1.HubService_SubscribePacketsServer) error {
	for i := range 2 {
		frame := &snifferv1.PacketFrame{
			Pod:      &snifferv1.PodRef{Name: "api-0", Namespace: "prod"},
			Source:   snifferv1.PacketSource_PACKET_SOURCE_WIRE,
			Sequence: uint64(i),
		}
		if err := stream.Send(frame); err != nil {
			return err
		}
	}
	return nil
}

func TestHubServiceStubs(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	snifferv1.RegisterHubServiceServer(server, stubHub{})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	client := snifferv1.NewHubServiceClient(conn)
	ctx := context.Background()

	created, err := client.CreateSession(ctx, &snifferv1.CreateSessionRequest{
		Spec: &snifferv1.CaptureSpec{Namespace: "prod", PodPatterns: []string{"api-.*"}},
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if created.GetSession().GetId() != "sess-1" {
		t.Fatalf("session id = %q, want sess-1", created.GetSession().GetId())
	}
	if got := created.GetSession().GetSpec().GetNamespace(); got != "prod" {
		t.Fatalf("spec namespace = %q, want prod", got)
	}

	stream, err := client.SubscribePackets(ctx, &snifferv1.SubscribePacketsRequest{SessionId: "sess-1"})
	if err != nil {
		t.Fatalf("SubscribePackets: %v", err)
	}
	var received int
	for {
		frame, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		if frame.GetPod().GetName() != "api-0" {
			t.Fatalf("frame pod = %q, want api-0", frame.GetPod().GetName())
		}
		received++
	}
	if received != 2 {
		t.Fatalf("received %d frames, want 2", received)
	}
}

func TestUnimplementedMethodsReturnError(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	snifferv1.RegisterHubServiceServer(server, stubHub{})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if _, err := snifferv1.NewHubServiceClient(conn).StopSession(context.Background(),
		&snifferv1.StopSessionRequest{SessionId: "sess-1"}); err == nil {
		t.Fatal("StopSession on stub = nil error, want Unimplemented")
	}
}
