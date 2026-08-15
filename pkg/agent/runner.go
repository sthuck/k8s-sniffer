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
	"github.com/sthuck/k8s-sniffer/pkg/agent/tlsworker"
	"github.com/sthuck/k8s-sniffer/pkg/log"
)

var agentLog = log.WithComponent("agent")

// defaultBatchSize is 1 so short sessions (e2e curls) deliver frames before
// session stop. Larger batches can be reintroduced with an idle flush timer.
const defaultBatchSize = 1

// RunnerOptions configure capture for one agent incarnation.
type RunnerOptions struct {
	Config   Config
	Resolver netns.Resolver
	Tcpdump  Capturer
	TLS      tlsworker.Attacher
	Dial     func(context.Context, string) (HubClient, error)
}

type Capturer interface {
	Start(context.Context, string, uint32, string, []string) (io.ReadCloser, error)
}

// AssignmentWatcher is a WatchTargets stream that yields target list updates.
type AssignmentWatcher interface {
	Recv() (*snifferv1.AgentAssignment, error)
}

type HubClient interface {
	WatchTargets(context.Context, string, string, string, string) (AssignmentWatcher, error)
	StreamCapture(context.Context, string, string) (snifferv1.AgentIngestService_StreamCaptureClient, error)
	ReportStatus(context.Context, *snifferv1.ReportStatusRequest, string) error
	Close() error
}

// Runner connects to the hub, captures targets, and streams frames.
type Runner struct {
	opts RunnerOptions
}

func NewRunner(opts RunnerOptions) *Runner {
	if opts.Dial == nil {
		opts.Dial = func(ctx context.Context, addr string) (HubClient, error) {
			c, err := hubclient.Dial(ctx, addr)
			if err != nil {
				return nil, err
			}
			return &grpcHubClient{inner: c}, nil
		}
	}
	return &Runner{opts: opts}
}

type grpcHubClient struct {
	inner *hubclient.Client
}

func (c *grpcHubClient) WatchTargets(ctx context.Context, sessionID, node, agentPod, streamID string) (AssignmentWatcher, error) {
	return c.inner.WatchTargets(ctx, sessionID, node, agentPod, streamID)
}

func (c *grpcHubClient) StreamCapture(ctx context.Context, agentPod, streamID string) (snifferv1.AgentIngestService_StreamCaptureClient, error) {
	return c.inner.StreamCapture(ctx, agentPod, streamID)
}

func (c *grpcHubClient) ReportStatus(ctx context.Context, req *snifferv1.ReportStatusRequest, agentPod string) error {
	return c.inner.ReportStatus(ctx, req, agentPod)
}

func (c *grpcHubClient) Close() error {
	return c.inner.Close()
}

// Run blocks until ctx is cancelled or the target watch ends.
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

	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	client, err := r.opts.Dial(runCtx, cfg.HubAddr)
	if err != nil {
		return err
	}
	defer client.Close()

	watch, err := client.WatchTargets(runCtx, cfg.SessionID, cfg.Node, cfg.AgentPod, cfg.StreamID)
	if err != nil {
		return err
	}
	assignment, err := watch.Recv()
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

	captureCtx, captureCancel := context.WithCancel(runCtx)
	defer captureCancel()
	streamCtx, streamCancel := context.WithCancel(context.Background())
	defer streamCancel()

	stream, err := client.StreamCapture(streamCtx, cfg.AgentPod, cfg.StreamID)
	if err != nil {
		return err
	}

	batchCh := make(chan *snifferv1.CaptureBatch, 8)
	senderDone := make(chan error, 1)
	go func() {
		senderDone <- r.sendBatches(stream, batchCh, captureCancel)
	}()

	type runningCapture struct {
		cancel context.CancelFunc
		done   chan struct{}
	}
	var capturesMu sync.Mutex
	captures := make(map[string]*runningCapture)
	var captureErrMu sync.Mutex
	var captureErrs []error

	startTarget := func(asg *snifferv1.AgentAssignment, target *snifferv1.Target) {
		uid := target.GetPod().GetUid()
		capturesMu.Lock()
		if _, ok := captures[uid]; ok {
			capturesMu.Unlock()
			return
		}
		tctx, tcancel := context.WithCancel(captureCtx)
		rt := &runningCapture{cancel: tcancel, done: make(chan struct{})}
		captures[uid] = rt
		capturesMu.Unlock()
		go func() {
			defer close(rt.done)
			err := r.captureTarget(tctx, client, asg, target, batchCh)
			if err == nil || errors.Is(err, context.Canceled) {
				return
			}
			pod := target.GetPod()
			agentLog.Info("capture failed",
				slog.String("session_id", cfg.SessionID),
				slog.String("namespace", pod.GetNamespace()),
				slog.String("pod", pod.GetName()),
				slog.String("err", err.Error()),
			)
			captureErrMu.Lock()
			captureErrs = append(captureErrs, fmt.Errorf("target %s/%s: %w", pod.GetNamespace(), pod.GetName(), err))
			captureErrMu.Unlock()
			if ctx.Err() == nil {
				r.reportCaptureError(context.WithoutCancel(ctx), client, asg, cfg.AgentPod, target, err)
			}
		}()
	}
	stopTarget := func(uid string) {
		capturesMu.Lock()
		rt, ok := captures[uid]
		if ok {
			delete(captures, uid)
		}
		capturesMu.Unlock()
		if !ok {
			return
		}
		rt.cancel()
		<-rt.done
	}
	apply := func(asg *snifferv1.AgentAssignment) {
		if err := validateAssignment(cfg, asg); err != nil {
			agentLog.Info("invalid assignment update",
				slog.String("session_id", cfg.SessionID),
				slog.String("err", err.Error()),
			)
			return
		}
		desired := make(map[string]*snifferv1.Target, len(asg.GetTargets()))
		for _, target := range asg.GetTargets() {
			desired[target.GetPod().GetUid()] = target
		}
		capturesMu.Lock()
		var removed []string
		for uid := range captures {
			if _, ok := desired[uid]; !ok {
				removed = append(removed, uid)
			}
		}
		capturesMu.Unlock()
		for _, uid := range removed {
			agentLog.Info("stopping capture for detached target",
				slog.String("session_id", cfg.SessionID),
				slog.String("pod_uid", uid),
			)
			stopTarget(uid)
		}
		for _, target := range desired {
			startTarget(asg, target)
		}
	}

	apply(assignment)

	watchDone := make(chan error, 1)
	go func() {
		for {
			next, err := watch.Recv()
			if err != nil {
				watchDone <- err
				return
			}
			agentLog.Info("assignment updated",
				slog.String("session_id", cfg.SessionID),
				slog.Int("targets", len(next.GetTargets())),
			)
			apply(next)
		}
	}()

	select {
	case <-ctx.Done():
	case <-watchDone:
	case <-captureCtx.Done():
	}
	captureCancel()

	capturesMu.Lock()
	remaining := make([]*runningCapture, 0, len(captures))
	for _, rt := range captures {
		remaining = append(remaining, rt)
	}
	capturesMu.Unlock()
	for _, rt := range remaining {
		rt.cancel()
		<-rt.done
	}
	close(batchCh)
	senderErr := <-senderDone

	captureErrMu.Lock()
	errs := append([]error(nil), captureErrs...)
	captureErrMu.Unlock()
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
	streamCancel()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.Join(errs...)
}

func (r *Runner) sendBatches(
	stream snifferv1.AgentIngestService_StreamCaptureClient,
	batchCh <-chan *snifferv1.CaptureBatch,
	onSendErr func(),
) error {
	var sequence uint64
	var sendErr error
	for batch := range batchCh {
		if sendErr != nil {
			continue
		}
		for _, record := range batch.GetRecords() {
			if frame := record.GetWireFrame(); frame != nil {
				sequence++
				frame.Sequence = sequence
			}
		}
		if err := hubclient.SendBatch(stream, batch); err != nil {
			sendErr = err
			if onSendErr != nil {
				onSendErr()
			}
		}
	}
	return sendErr
}

func (r *Runner) captureTarget(
	ctx context.Context,
	client HubClient,
	assignment *snifferv1.AgentAssignment,
	target *snifferv1.Target,
	batchCh chan<- *snifferv1.CaptureBatch,
) (returnErr error) {
	pod := target.GetPod()
	agentLog.Info("resolving netns",
		slog.String("session_id", assignment.GetSessionId()),
		slog.String("namespace", pod.GetNamespace()),
		slog.String("pod", pod.GetName()),
	)
	netnsPath, err := r.opts.Resolver.Resolve(ctx, pod)
	if err != nil {
		return newCaptureFailure(snifferv1.ErrorStage_ERROR_STAGE_NETNS_RESOLVE, snifferv1.ErrorReason_ERROR_REASON_NOT_FOUND, err)
	}
	agentLog.Info("resolved netns",
		slog.String("session_id", assignment.GetSessionId()),
		slog.String("pod", pod.GetName()),
		slog.String("netns", netnsPath),
	)

	var tlsWG sync.WaitGroup
	if r.opts.TLS != nil && tlsworker.WantsAttach(target.GetTlsMode()) {
		tlsWG.Add(1)
		go func() {
			defer tlsWG.Done()
			r.runTLS(ctx, client, assignment, target, tlsworker.PIDFromNetnsPath(netnsPath), batchCh)
		}()
	}
	defer tlsWG.Wait()

	snaplen := target.GetSnaplen()
	if snaplen == 0 {
		snaplen = 262144
	}
	agentLog.Info("starting tcpdump",
		slog.String("session_id", assignment.GetSessionId()),
		slog.String("pod", pod.GetName()),
		slog.String("netns", netnsPath),
		slog.Uint64("snaplen", uint64(snaplen)),
	)
	pcapStream, err := r.opts.Tcpdump.Start(ctx, netnsPath, snaplen, target.GetBpfFilter(), target.GetInterfaces())
	if err != nil {
		return newCaptureFailure(snifferv1.ErrorStage_ERROR_STAGE_CAPTURE_START, snifferv1.ErrorReason_ERROR_REASON_TOOL_FAILED, err)
	}
	defer func() {
		closeErr := pcapStream.Close()
		if ctx.Err() != nil {
			// Keep a flush/send failure over a plain cancel so callers see it.
			if returnErr == nil || errors.Is(returnErr, context.Canceled) {
				returnErr = ctx.Err()
			}
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
	agentLog.Info("tcpdump streaming",
		slog.String("session_id", assignment.GetSessionId()),
		slog.String("pod", pod.GetName()),
	)

	batch := &snifferv1.CaptureBatch{
		SessionId: assignment.GetSessionId(),
		Node:      assignment.GetNode(),
		StreamId:  assignment.GetStreamId(),
	}
	flush := func() error {
		if len(batch.Records) == 0 {
			return nil
		}
		// Session stop cancels captureCtx; still deliver the last partial batch
		// while the ingest stream is kept open by Run.
		flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		n := len(batch.Records)
		if err := sendBatch(flushCtx, batchCh, cloneBatch(batch)); err != nil {
			return err
		}
		agentLog.Info("flushed capture batch",
			slog.String("session_id", assignment.GetSessionId()),
			slog.String("pod", pod.GetName()),
			slog.Int("records", n),
		)
		batch.Records = batch.Records[:0]
		return nil
	}
	for {
		frame, err := reader.ReadFrame(pod)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if ctx.Err() != nil {
				if flushErr := flush(); flushErr != nil {
					return flushErr
				}
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
	return flush()
}

func (r *Runner) runTLS(
	ctx context.Context,
	client HubClient,
	assignment *snifferv1.AgentAssignment,
	target *snifferv1.Target,
	pid int,
	batchCh chan<- *snifferv1.CaptureBatch,
) {
	pod := target.GetPod()
	events, statuses, err := r.opts.TLS.Attach(ctx, tlsworker.Target{
		Pod:       pod,
		PID:       pid,
		Mode:      target.GetTlsMode(),
		SessionID: assignment.GetSessionId(),
	})
	if err != nil {
		agentLog.Info("tls attach failed",
			slog.String("session_id", assignment.GetSessionId()),
			slog.String("pod", pod.GetName()),
			slog.String("err", err.Error()),
		)
		r.reportTLSStatus(ctx, client, assignment, target, tlsworker.Status{
			Status: snifferv1.TlsStatus_TLS_STATUS_UNSUPPORTED,
			Detail: err.Error(),
		})
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case st, ok := <-statuses:
			if !ok {
				statuses = nil
				if events == nil {
					return
				}
				continue
			}
			agentLog.Info("tls status",
				slog.String("session_id", assignment.GetSessionId()),
				slog.String("pod", pod.GetName()),
				slog.String("status", st.Status.String()),
				slog.String("detail", st.Detail),
			)
			r.reportTLSStatus(ctx, client, assignment, target, st)
		case ev, ok := <-events:
			if !ok {
				events = nil
				if statuses == nil {
					return
				}
				continue
			}
			batch := &snifferv1.CaptureBatch{
				SessionId: assignment.GetSessionId(),
				Node:      assignment.GetNode(),
				StreamId:  assignment.GetStreamId(),
				Records: []*snifferv1.CaptureRecord{{
					Record: &snifferv1.CaptureRecord_TlsEvent{TlsEvent: ev},
				}},
			}
			if err := sendBatch(ctx, batchCh, batch); err != nil {
				return
			}
		}
	}
}

func (r *Runner) reportTLSStatus(
	ctx context.Context,
	client HubClient,
	assignment *snifferv1.AgentAssignment,
	target *snifferv1.Target,
	st tlsworker.Status,
) {
	if client == nil || st.Status == snifferv1.TlsStatus_TLS_STATUS_UNSPECIFIED {
		return
	}
	reportCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	err := client.ReportStatus(reportCtx, &snifferv1.ReportStatusRequest{
		SessionId: assignment.GetSessionId(),
		Node:      assignment.GetNode(),
		StreamId:  assignment.GetStreamId(),
		Payload: &snifferv1.ReportStatusRequest_TlsState{
			TlsState: &snifferv1.TlsStateChanged{
				Pod:    target.GetPod(),
				Status: st.Status,
				Detail: st.Detail,
			},
		},
	}, r.opts.Config.AgentPod)
	if err != nil && ctx.Err() == nil {
		agentLog.Info("tls status report failed",
			slog.String("session_id", assignment.GetSessionId()),
			slog.String("pod", target.GetPod().GetName()),
			slog.String("err", err.Error()),
		)
	}
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
	if len(assignment.GetTargets()) == 0 {
		return fmt.Errorf("assignment targets: at least one required")
	}
	for i, target := range assignment.GetTargets() {
		if target.GetPod().GetNamespace() == "" || target.GetPod().GetName() == "" || target.GetPod().GetUid() == "" {
			return fmt.Errorf("assignment targets[%d]: complete pod identity required", i)
		}
		if target.GetPod().GetNode() != cfg.Node {
			return fmt.Errorf("assignment targets[%d]: pod node mismatch", i)
		}
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
	}, agentPod)
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
