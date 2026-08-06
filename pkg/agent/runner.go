package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

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
	Tcpdump  Capturer
	Dial     func(context.Context, string) (HubClient, error)
}

type Capturer interface {
	Start(context.Context, string, uint32, string, []string) (io.ReadCloser, error)
}

type HubClient interface {
	WatchTargets(context.Context, string, string, string, string) (*snifferv1.AgentAssignment, error)
	StreamCapture(context.Context) (snifferv1.AgentIngestService_StreamCaptureClient, error)
	ReportStatus(context.Context, *snifferv1.ReportStatusRequest) error
	Close() error
}

// Runner connects to the hub, captures targets, and streams frames.
type Runner struct {
	opts RunnerOptions
}

func NewRunner(opts RunnerOptions) *Runner {
	if opts.Dial == nil {
		opts.Dial = func(ctx context.Context, addr string) (HubClient, error) {
			return hubclient.Dial(ctx, addr)
		}
	}
	return &Runner{opts: opts}
}

// Run blocks until ctx is cancelled or all captures finish.
func (r *Runner) Run(ctx context.Context) error {
	cfg := r.opts.Config
	if err := cfg.Validate(); err != nil {
		return err
	}
	if r.opts.Resolver == nil {
		return fmt.Errorf("resolver: required")
	}
	if r.opts.Tcpdump == nil {
		return fmt.Errorf("capturer: required")
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	client, err := r.opts.Dial(ctx, cfg.HubAddr)
	if err != nil {
		return err
	}
	defer client.Close()

	assignment, err := client.WatchTargets(runCtx, cfg.SessionID, cfg.Node, cfg.AgentPod, cfg.StreamID)
	if err != nil {
		return err
	}
	if err := validateAssignment(cfg, assignment); err != nil {
		return err
	}
	agentLog.Info("assignment received",
		slog.String("session_id", cfg.SessionID),
		slog.String("stream_id", assignment.GetStreamId()),
		slog.Int("targets", len(assignment.GetTargets())),
	)

	stream, err := client.StreamCapture(runCtx)
	if err != nil {
		return err
	}

	batchCh := make(chan *snifferv1.CaptureBatch, 8)
	senderDone := make(chan error, 1)
	go func() {
		senderDone <- r.sendBatches(runCtx, stream, batchCh)
	}()

	var captureWG sync.WaitGroup
	captureErrs := make(chan error, len(assignment.GetTargets()))
	for _, target := range assignment.GetTargets() {
		target := target
		captureWG.Add(1)
		go func() {
			defer captureWG.Done()
			if err := r.captureTarget(runCtx, assignment, target, batchCh); err != nil &&
				!errors.Is(err, context.Canceled) {
				targetErr := fmt.Errorf("target %s/%s: %w", target.GetPod().GetNamespace(), target.GetPod().GetName(), err)
				captureErrs <- targetErr
				r.reportCaptureError(runCtx, client, assignment, cfg.AgentPod, target, err)
			}
		}()
	}

	capturesDone := make(chan struct{})
	go func() {
		captureWG.Wait()
		close(batchCh)
		close(captureErrs)
		close(capturesDone)
	}()

	senderErr := <-senderDone
	if senderErr != nil {
		cancel()
	}
	<-capturesDone
	var errs []error
	for err := range captureErrs {
		errs = append(errs, err)
	}
	if senderErr != nil && !errors.Is(senderErr, context.Canceled) {
		errs = append(errs, senderErr)
	}

	if senderErr == nil {
		summary, closeErr := hubclient.CloseCapture(stream)
		if closeErr != nil {
			errs = append(errs, closeErr)
		} else if summary != nil {
			agentLog.Info("capture stream closed",
				slog.String("session_id", cfg.SessionID),
				slog.Uint64("records_accepted", summary.GetRecordsAccepted()),
			)
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.Join(errs...)
}

func (r *Runner) sendBatches(ctx context.Context, stream snifferv1.AgentIngestService_StreamCaptureClient, batchCh <-chan *snifferv1.CaptureBatch) error {
	var sequence uint64
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case batch, ok := <-batchCh:
			if !ok {
				return nil
			}
			for _, record := range batch.GetRecords() {
				if frame := record.GetWireFrame(); frame != nil {
					sequence++
					frame.Sequence = sequence
				}
			}
			if err := hubclient.SendBatch(stream, batch); err != nil {
				return err
			}
		}
	}
}

func (r *Runner) captureTarget(
	ctx context.Context,
	assignment *snifferv1.AgentAssignment,
	target *snifferv1.Target,
	batchCh chan<- *snifferv1.CaptureBatch,
) (returnErr error) {
	pod := target.GetPod()
	netnsPath, err := r.opts.Resolver.Resolve(ctx, pod)
	if err != nil {
		return newCaptureFailure(snifferv1.ErrorStage_ERROR_STAGE_NETNS_RESOLVE, snifferv1.ErrorReason_ERROR_REASON_NOT_FOUND, err)
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
		return newCaptureFailure(snifferv1.ErrorStage_ERROR_STAGE_CAPTURE_START, snifferv1.ErrorReason_ERROR_REASON_TOOL_FAILED, err)
	}
	defer func() {
		closeErr := pcapStream.Close()
		if ctx.Err() != nil {
			returnErr = ctx.Err()
			return
		}
		if closeErr != nil {
			returnErr = errors.Join(returnErr, newCaptureFailure(
				snifferv1.ErrorStage_ERROR_STAGE_CAPTURE_STREAM,
				snifferv1.ErrorReason_ERROR_REASON_TOOL_FAILED,
				closeErr,
			))
		}
	}()

	reader, err := capture.NewPCAPReader(pcapStream)
	if err != nil {
		return newCaptureFailure(snifferv1.ErrorStage_ERROR_STAGE_CAPTURE_START, snifferv1.ErrorReason_ERROR_REASON_TOOL_FAILED, err)
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
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return newCaptureFailure(snifferv1.ErrorStage_ERROR_STAGE_CAPTURE_STREAM, snifferv1.ErrorReason_ERROR_REASON_TOOL_FAILED, err)
		}
		batch.Records = append(batch.Records, &snifferv1.CaptureRecord{
			Record: &snifferv1.CaptureRecord_WireFrame{WireFrame: frame},
		})
		if len(batch.Records) >= defaultBatchSize {
			if err := sendBatch(ctx, batchCh, cloneBatch(batch)); err != nil {
				return err
			}
			batch.Records = batch.Records[:0]
		}
	}
	if len(batch.Records) > 0 {
		if err := sendBatch(ctx, batchCh, cloneBatch(batch)); err != nil {
			return err
		}
	}
	return nil
}

func validateAssignment(cfg Config, assignment *snifferv1.AgentAssignment) error {
	if assignment == nil {
		return fmt.Errorf("assignment: required")
	}
	if assignment.GetSessionId() != cfg.SessionID {
		return fmt.Errorf("assignment session_id mismatch")
	}
	if assignment.GetNode() != cfg.Node {
		return fmt.Errorf("assignment node mismatch")
	}
	if assignment.GetStreamId() == "" || assignment.GetStreamId() != cfg.StreamID {
		return fmt.Errorf("assignment stream_id mismatch")
	}
	return nil
}

type captureFailure struct {
	stage  snifferv1.ErrorStage
	reason snifferv1.ErrorReason
	err    error
}

func newCaptureFailure(stage snifferv1.ErrorStage, reason snifferv1.ErrorReason, err error) error {
	return &captureFailure{stage: stage, reason: reason, err: err}
}

func (e *captureFailure) Error() string { return e.err.Error() }
func (e *captureFailure) Unwrap() error { return e.err }

func (r *Runner) reportCaptureError(
	ctx context.Context,
	client HubClient,
	assignment *snifferv1.AgentAssignment,
	agentPod string,
	target *snifferv1.Target,
	err error,
) {
	stage := snifferv1.ErrorStage_ERROR_STAGE_CAPTURE_STREAM
	reason := snifferv1.ErrorReason_ERROR_REASON_INTERNAL
	var failure *captureFailure
	if errors.As(err, &failure) {
		stage = failure.stage
		reason = failure.reason
	}
	reportCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	reportErr := client.ReportStatus(reportCtx, &snifferv1.ReportStatusRequest{
		SessionId: assignment.GetSessionId(),
		Node:      assignment.GetNode(),
		StreamId:  assignment.GetStreamId(),
		Payload: &snifferv1.ReportStatusRequest_Error{
			Error: &snifferv1.CaptureError{
				Stage:     stage,
				Reason:    reason,
				Detail:    err.Error(),
				Retryable: false,
				Pod:       target.GetPod(),
				Node:      assignment.GetNode(),
				AgentPod:  agentPod,
				StreamId:  assignment.GetStreamId(),
			},
		},
	})
	if reportErr != nil && ctx.Err() == nil {
		agentLog.Info("capture error report failed",
			slog.String("session_id", assignment.GetSessionId()),
			slog.String("pod", target.GetPod().GetName()),
			slog.String("err", reportErr.Error()),
		)
	}
}

func sendBatch(ctx context.Context, batchCh chan<- *snifferv1.CaptureBatch, batch *snifferv1.CaptureBatch) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case batchCh <- batch:
		return nil
	}
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
