package hubclient

import (
	"context"
	"fmt"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	sharedcapture "github.com/sthuck/k8s-sniffer/pkg/capture"
)

// Client talks to the hub AgentIngestService.
type Client struct {
	conn   *grpc.ClientConn
	ingest snifferv1.AgentIngestServiceClient
}

// Dial connects to hubAddr (host:port, no scheme).
func Dial(ctx context.Context, hubAddr string) (*Client, error) {
	conn, err := grpc.NewClient(hubAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("dial hub %q: %w", hubAddr, err)
	}
	return &Client{
		conn:   conn,
		ingest: snifferv1.NewAgentIngestServiceClient(conn),
	}, nil
}

func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// WatchTargets blocks until the first assignment arrives or ctx is cancelled.
func (c *Client) WatchTargets(ctx context.Context, sessionID, node, agentPod, streamID string) (*snifferv1.AgentAssignment, error) {
	ctx = metadata.AppendToOutgoingContext(ctx, sharedcapture.AgentStreamMetadataKey, streamID)
	stream, err := c.ingest.WatchTargets(ctx, &snifferv1.WatchTargetsRequest{
		SessionId: sessionID,
		Node:      node,
		AgentPod:  agentPod,
	})
	if err != nil {
		return nil, fmt.Errorf("watch targets: %w", err)
	}
	assignment, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("receive assignment: %w", err)
	}
	return assignment, nil
}

func (c *Client) ReportStatus(ctx context.Context, req *snifferv1.ReportStatusRequest) error {
	if _, err := c.ingest.ReportStatus(ctx, req); err != nil {
		return fmt.Errorf("report status: %w", err)
	}
	return nil
}

// StreamCapture opens the ingest stream.
func (c *Client) StreamCapture(ctx context.Context) (snifferv1.AgentIngestService_StreamCaptureClient, error) {
	stream, err := c.ingest.StreamCapture(ctx)
	if err != nil {
		return nil, fmt.Errorf("stream capture: %w", err)
	}
	return stream, nil
}

// SendBatch writes one CaptureBatch to the open stream.
func SendBatch(stream snifferv1.AgentIngestService_StreamCaptureClient, batch *snifferv1.CaptureBatch) error {
	if err := stream.Send(batch); err != nil {
		return fmt.Errorf("send capture batch: %w", err)
	}
	return nil
}

// CloseCapture sends EOF and returns the hub summary.
func CloseCapture(stream snifferv1.AgentIngestService_StreamCaptureClient) (*snifferv1.StreamCaptureSummary, error) {
	summary, err := stream.CloseAndRecv()
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("capture summary: %w", err)
	}
	return summary, nil
}
