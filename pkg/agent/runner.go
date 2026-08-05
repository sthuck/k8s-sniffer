package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	"github.com/sthuck/k8s-sniffer/pkg/agent/capture"
	"github.com/sthuck/k8s-sniffer/pkg/agent/hubclient"
	"github.com/sthuck/k8s-sniffer/pkg/agent/netns"
	"github.com/sthuck/k8s-sniffer/pkg/log"
)

var agentLog = log.WithComponent("agent")

const defaultBatchSize = 32

// RunnerOptions configure capture for one agent incarnation.
type RunnerOptions struct {
	Config   Config
	Resolver netns.Resolver
	Tcpdump  capture.Tcpdump
}

// Runner connects to the hub, captures targets, and streams frames.
type Runner struct {
	opts RunnerOptions
}

func NewRunner(opts RunnerOptions) *Runner {
	return &Runner{opts: opts}
}

// Run blocks until ctx is cancelled or all captures finish.
func (r *Runner) Run(ctx context.Context) error {
	cfg := r.opts.Config
	client, err := hubclient.Dial(ctx, cfg.HubAddr)
	if err != nil {
		return err
	}
	defer client.Close()

	assignment, err := client.WatchTargets(ctx, cfg.SessionID, cfg.Node, cfg.AgentPod)
	if err != nil {
		return err
	}
	agentLog.Info("assignment received",
		slog.String("session_id", cfg.SessionID),
		slog.String("stream_id", assignment.GetStreamId()),
		slog.Int("targets", len(assignment.GetTargets())),
	)

	stream, err := client.StreamCapture(ctx)
	if err != nil {
		return err
	}

	batchCh := make(chan *snifferv1.CaptureBatch, 8)
	senderDone := make(chan error, 1)
	go func() {
		senderDone <- r.sendBatches(ctx, stream, batchCh)
	}()

	var captureWG sync.WaitGroup
	errCh := make(chan error, len(assignment.GetTargets()))
	for _, target := range assignment.GetTargets() {
		target := target
		captureWG.Add(1)
		go func() {
			defer captureWG.Done()
			if err := r.captureTarget(ctx, assignment, target, batchCh); err != nil && !errors.Is(err, context.Canceled) {
				errCh <- fmt.Errorf("target %s/%s: %w", target.GetPod().GetNamespace(), target.GetPod().GetName(), err)
			}
		}()
	}

	captureWG.Wait()
	close(batchCh)
	if err := <-senderDone; err != nil && !errors.Is(err, context.Canceled) {
		errCh <- err
	}
	close(errCh)

	var errs []error
	for err := range errCh {
		errs = append(errs, err)
	}

	summary, closeErr := hubclient.CloseCapture(stream)
	if closeErr != nil {
		errs = append(errs, closeErr)
	} else if summary != nil {
		agentLog.Info("capture stream closed",
			slog.String("session_id", cfg.SessionID),
			slog.Uint64("records_accepted", summary.GetRecordsAccepted()),
		)
	}
	return errors.Join(errs...)
}

func (r *Runner) sendBatches(ctx context.Context, stream snifferv1.AgentIngestService_StreamCaptureClient, batchCh <-chan *snifferv1.CaptureBatch) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case batch, ok := <-batchCh:
			if !ok {
				return nil
			}
			if err := hubclient.SendBatch(stream, batch); err != nil {
				return err
			}
		}
	}
}

func (r *Runner) captureTarget(ctx context.Context, assignment *snifferv1.AgentAssignment, target *snifferv1.Target, batchCh chan<- *snifferv1.CaptureBatch) error {
	pod := target.GetPod()
	netnsPath, err := r.opts.Resolver.Resolve(ctx, pod)
	if err != nil {
		return err
	}
	agentLog.Debug("resolved netns",
		slog.String("session_id", assignment.GetSessionId()),
		slog.String("pod", pod.GetName()),
		slog.String("netns", netnsPath),
	)

	snaplen := target.GetSnaplen()
	if snaplen == 0 {
		snaplen = 262144
	}
	pcapStream, err := r.opts.Tcpdump.Start(ctx, netnsPath, snaplen, target.GetBpfFilter(), target.GetInterfaces())
	if err != nil {
		return err
	}
	defer pcapStream.Close()

	reader, err := capture.NewPCAPReader(pcapStream)
	if err != nil {
		return err
	}

	batch := &snifferv1.CaptureBatch{
		SessionId: assignment.GetSessionId(),
		Node:      assignment.GetNode(),
		StreamId:  assignment.GetStreamId(),
	}
	for {
		frame, err := reader.ReadFrame(pod)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		batch.Records = append(batch.Records, &snifferv1.CaptureRecord{
			Record: &snifferv1.CaptureRecord_WireFrame{WireFrame: frame},
		})
		if len(batch.Records) >= defaultBatchSize {
			batchCh <- cloneBatch(batch)
			batch.Records = batch.Records[:0]
		}
	}
	if len(batch.Records) > 0 {
		batchCh <- cloneBatch(batch)
	}
	return nil
}

func cloneBatch(b *snifferv1.CaptureBatch) *snifferv1.CaptureBatch {
	out := &snifferv1.CaptureBatch{
		SessionId: b.GetSessionId(),
		Node:      b.GetNode(),
		StreamId:  b.GetStreamId(),
		Dropped:   b.GetDropped(),
		Records:   make([]*snifferv1.CaptureRecord, len(b.GetRecords())),
	}
	copy(out.Records, b.GetRecords())
	return out
}
