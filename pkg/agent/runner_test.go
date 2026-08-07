package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	"github.com/sthuck/k8s-sniffer/pkg/agent/netns"
)

func TestRunnerCancelsCapturesWhenSenderFails(t *testing.T) {
	pod := &snifferv1.PodRef{Namespace: "prod", Name: "api", Uid: "uid-1", Node: "node-a"}
	stream := &fakeCaptureStream{ctx: context.Background(), sendErr: errors.New("ingest failed")}
	runner := testRunner(t, []*snifferv1.PodRef{pod}, stream, &blockingCapturer{})

	done := make(chan error, 1)
	go func() {
		done <- runner.Run(context.Background())
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "ingest failed") {
			t.Fatalf("Run error = %v, want ingest failure", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run hung after ingest failure")
	}
}

func TestRunnerSequencesAreUniqueAcrossTargets(t *testing.T) {
	pods := []*snifferv1.PodRef{
		{Namespace: "prod", Name: "api", Uid: "uid-1", Node: "node-a"},
		{Namespace: "prod", Name: "worker", Uid: "uid-2", Node: "node-a"},
	}
	stream := &fakeCaptureStream{ctx: context.Background()}
	runner := testRunner(t, pods, stream, finiteCapturer{})
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	stream.mu.Lock()
	defer stream.mu.Unlock()
	var sequences []uint64
	for _, batch := range stream.batches {
		for _, record := range batch.GetRecords() {
			sequences = append(sequences, record.GetWireFrame().GetSequence())
		}
	}
	if len(sequences) != 2 || sequences[0] == sequences[1] ||
		(sequences[0] != 1 && sequences[1] != 1) ||
		(sequences[0] != 2 && sequences[1] != 2) {
		t.Fatalf("sequences = %v, want unique 1 and 2", sequences)
	}
}

func TestRunnerDeliversFramesBeforeCancel(t *testing.T) {
	pod := &snifferv1.PodRef{Namespace: "prod", Name: "api", Uid: "uid-1", Node: "node-a"}
	stream := &fakeCaptureStream{ctx: context.Background()}
	const packets = 3
	ready := make(chan struct{})
	runner := testRunner(t, []*snifferv1.PodRef{pod}, stream, &partialThenBlockCapturer{n: packets, ready: ready})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()

	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		cancel()
		<-done
		t.Fatal("timed out waiting for capturer to emit packets")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		stream.mu.Lock()
		got := 0
		for _, batch := range stream.batches {
			got += len(batch.GetRecords())
		}
		stream.mu.Unlock()
		if got >= packets {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("timed out waiting for frames before cancel; got %d", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Run error = %v, want cancel or nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run hung after cancel")
	}
}

func testRunner(
	t *testing.T,
	pods []*snifferv1.PodRef,
	stream *fakeCaptureStream,
	capturer Capturer,
) *Runner {
	t.Helper()
	resolver := netns.NewMapResolver()
	targets := make([]*snifferv1.Target, 0, len(pods))
	for _, pod := range pods {
		resolver.Set(pod, "/proc/1/ns/net")
		targets = append(targets, &snifferv1.Target{Pod: pod, Snaplen: 65535})
	}
	cfg := Config{
		SessionID: "session-a",
		Node:      "node-a",
		AgentPod:  "agent-a",
		StreamID:  "stream-a",
		HubAddr:   "hub:50051",
		CRISocket: "/run/containerd/containerd.sock",
	}
	client := &fakeHubClient{
		assignment: &snifferv1.AgentAssignment{
			SessionId: cfg.SessionID,
			Node:      cfg.Node,
			StreamId:  cfg.StreamID,
			Targets:   targets,
		},
		stream: stream,
	}
	return NewRunner(RunnerOptions{
		Config:   cfg,
		Resolver: resolver,
		Tcpdump:  capturer,
		Dial: func(context.Context, string) (HubClient, error) {
			return client, nil
		},
	})
}

type fakeHubClient struct {
	assignment *snifferv1.AgentAssignment
	stream     snifferv1.AgentIngestService_StreamCaptureClient
}

func (c *fakeHubClient) WatchTargets(context.Context, string, string, string, string) (*snifferv1.AgentAssignment, error) {
	return c.assignment, nil
}

func (c *fakeHubClient) StreamCapture(context.Context, string, string) (snifferv1.AgentIngestService_StreamCaptureClient, error) {
	return c.stream, nil
}

func (c *fakeHubClient) ReportStatus(context.Context, *snifferv1.ReportStatusRequest, string) error {
	return nil
}

func (c *fakeHubClient) Close() error { return nil }

type fakeCaptureStream struct {
	ctx     context.Context
	sendErr error
	mu      sync.Mutex
	batches []*snifferv1.CaptureBatch
}

func (s *fakeCaptureStream) Send(batch *snifferv1.CaptureBatch) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batches = append(s.batches, proto.Clone(batch).(*snifferv1.CaptureBatch))
	return nil
}

func (s *fakeCaptureStream) CloseAndRecv() (*snifferv1.StreamCaptureSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var records uint64
	for _, batch := range s.batches {
		records += uint64(len(batch.GetRecords()))
	}
	return &snifferv1.StreamCaptureSummary{RecordsAccepted: records}, nil
}

func (s *fakeCaptureStream) Header() (metadata.MD, error) { return nil, nil }
func (s *fakeCaptureStream) Trailer() metadata.MD         { return nil }
func (s *fakeCaptureStream) CloseSend() error             { return nil }
func (s *fakeCaptureStream) Context() context.Context     { return s.ctx }
func (s *fakeCaptureStream) SendMsg(any) error            { return nil }
func (s *fakeCaptureStream) RecvMsg(any) error            { return nil }

var _ grpc.ClientStream = (*fakeCaptureStream)(nil)

type finiteCapturer struct{}

func (finiteCapturer) Start(context.Context, string, uint32, string, []string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(testPCAP(1))), nil
}

type blockingCapturer struct{}

func (*blockingCapturer) Start(ctx context.Context, _ string, _ uint32, _ string, _ []string) (io.ReadCloser, error) {
	reader, writer := io.Pipe()
	go func() {
		_, _ = writer.Write(testPCAP(defaultBatchSize))
		<-ctx.Done()
		_ = writer.CloseWithError(ctx.Err())
	}()
	return reader, nil
}

// partialThenBlockCapturer emits n packets (below a full batch) then blocks until
// ctx is cancelled — models short e2e captures ended by session stop.
type partialThenBlockCapturer struct {
	n     int
	ready chan struct{}
}

func (c *partialThenBlockCapturer) Start(ctx context.Context, _ string, _ uint32, _ string, _ []string) (io.ReadCloser, error) {
	reader, writer := io.Pipe()
	go func() {
		_, _ = writer.Write(testPCAP(c.n))
		if c.ready != nil {
			close(c.ready)
		}
		<-ctx.Done()
		_ = writer.CloseWithError(ctx.Err())
	}()
	return reader, nil
}

func testPCAP(packetCount int) []byte {
	var buf bytes.Buffer
	writer := pcapgo.NewWriter(&buf)
	_ = writer.WriteFileHeader(65535, layers.LinkTypeEthernet)
	for i := 0; i < packetCount; i++ {
		payload := []byte{byte(i)}
		_ = writer.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Unix(int64(i+1), 0),
			CaptureLength: len(payload),
			Length:        len(payload),
		}, payload)
	}
	return buf.Bytes()
}
