package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	"github.com/sthuck/k8s-sniffer/pkg/capture"
	"github.com/sthuck/k8s-sniffer/pkg/hub"
	"github.com/sthuck/k8s-sniffer/pkg/k8s"
	"github.com/sthuck/k8s-sniffer/pkg/log"
	"github.com/sthuck/k8s-sniffer/pkg/sink"
)

var cliLog = log.WithComponent("cli")

// CaptureOptions configures a capture session from CLI flags.
type CaptureOptions struct {
	Spec        capture.Spec
	Sink        capture.SinkSpec
	Agent       capture.AgentConfig
	Kube        k8s.ClientConfig
	HubListen   string
	HubIngest   string
	EventWriter io.Writer
	// OnSessionReady is called after CreateSession succeeds and capture can begin.
	OnSessionReady func()
}

// RunCapture starts an in-process hub, creates a session, and writes PCAP output
// until the session stops, duration elapses, or ctx is cancelled.
func RunCapture(ctx context.Context, opts CaptureOptions) error {
	spec := opts.Spec.WithDefaults()
	if err := spec.Validate(); err != nil {
		return fmt.Errorf("capture spec: %w", err)
	}
	sinkSpec := opts.Sink.WithDefaults()
	if err := sinkSpec.Validate(); err != nil {
		return fmt.Errorf("sink: %w", err)
	}

	kclient, err := k8s.New(opts.Kube)
	if err != nil {
		return fmt.Errorf("kubernetes client: %w", err)
	}

	agentCfg := opts.Agent.WithDefaults()
	listenAddr := opts.HubListen
	if listenAddr == "" {
		listenAddr = "0.0.0.0:0"
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("hub listen: %w", err)
	}
	defer ln.Close()

	ingestAddr := opts.HubIngest
	if ingestAddr == "" {
		ingestAddr, err = defaultHubIngestAddr(ln.Addr())
		if err != nil {
			return err
		}
	}
	agentCfg.HubIngestAddr = ingestAddr
	if err := agentCfg.Validate(); err != nil {
		return fmt.Errorf("agent config: %w", err)
	}

	h, err := hub.New(hub.Options{
		Kubernetes: kclient.Clientset,
		Agent:      agentCfg,
	})
	if err != nil {
		return fmt.Errorf("hub: %w", err)
	}

	server := grpc.NewServer()
	snifferv1.RegisterHubServiceServer(server, h)
	snifferv1.RegisterAgentIngestServiceServer(server, h)
	go func() {
		_ = server.Serve(ln)
	}()
	defer func() {
		server.GracefulStop()
		_ = h.StopAll(context.Background())
	}()

	conn, err := grpc.NewClient(ln.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("hub dial: %w", err)
	}
	defer conn.Close()
	hubClient := snifferv1.NewHubServiceClient(conn)

	cliLog.Info("hub listening for agents",
		slog.String("listen", ln.Addr().String()),
		slog.String("ingest_addr", ingestAddr),
	)

	pcapWriter, err := sink.OpenPCAP(sinkSpec.Out)
	if err != nil {
		return fmt.Errorf("pcap sink: %w", err)
	}
	defer pcapWriter.Close()

	// Bootstrap (discovery + agent Ready) is not bounded by --duration; the CLI
	// owns the hard stop after the session is running.
	hubSpec := spec.ToProto()
	hubSpec.Duration = nil

	createResp, err := hubClient.CreateSession(ctx, &snifferv1.CreateSessionRequest{
		Spec: hubSpec,
	})
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	session := createResp.GetSession()
	sessionID := session.GetId()
	cliLog.Info("session created",
		slog.String("session_id", sessionID),
		slog.String("state", session.GetState().String()),
	)
	if session.GetState() == snifferv1.SessionState_SESSION_STATE_FAILED {
		return fmt.Errorf("session failed: %s", session.GetFailureReason())
	}

	subscribeCtx, subscribeCancel := context.WithCancel(context.Background())
	defer subscribeCancel()

	eventDone := make(chan struct{})
	go func() {
		defer close(eventDone)
		_ = watchEvents(subscribeCtx, hubClient, sessionID, opts.EventWriter)
	}()

	// Subscribe before OnSessionReady: WatchTargets withholds assignments until a
	// packet subscriber exists, so traffic generators must not start earlier.
	packetErrCh := make(chan error, 1)
	var packetWG sync.WaitGroup
	packetWG.Add(1)
	go func() {
		defer packetWG.Done()
		packetErrCh <- subscribePackets(subscribeCtx, hubClient, sessionID, pcapWriter)
	}()
	waitCtx, waitCancel := context.WithTimeout(ctx, 30*time.Second)
	err = h.WaitForPacketSubscriber(waitCtx, sessionID)
	waitCancel()
	if err != nil {
		subscribeCancel()
		packetWG.Wait()
		return fmt.Errorf("wait for packet subscriber: %w", err)
	}

	if opts.OnSessionReady != nil {
		opts.OnSessionReady()
	}

	stopOnce := sync.Once{}
	stopSession := func(reason string) {
		stopOnce.Do(func() {
			cliLog.Info("stopping session",
				slog.String("session_id", sessionID),
				slog.String("reason", reason),
			)
			stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer stopCancel()
			if _, err := hubClient.StopSession(stopCtx, &snifferv1.StopSessionRequest{SessionId: sessionID}); err != nil {
				cliLog.Info("stop session failed",
					slog.String("session_id", sessionID),
					slog.String("err", err.Error()),
				)
			}
			subscribeCancel()
		})
	}

	if spec.Duration > 0 {
		time.AfterFunc(spec.Duration, func() { stopSession("duration") })
	}

	sigCtx, stopSignals := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()

	select {
	case <-sigCtx.Done():
		if errors.Is(sigCtx.Err(), context.Canceled) {
			stopSession("signal")
		} else {
			stopSession("context ended")
		}
	case err := <-packetErrCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			stopSession("packet stream error")
			packetWG.Wait()
			return err
		}
		stopSession("packet stream ended")
	}

	packetWG.Wait()
	<-eventDone

	cliLog.Info("capture finished",
		slog.String("session_id", sessionID),
		slog.Uint64("packets", pcapWriter.PacketCount()),
	)
	return nil
}

func subscribePackets(
	ctx context.Context,
	client snifferv1.HubServiceClient,
	sessionID string,
	writer *sink.PCAPWriter,
) error {
	stream, err := client.SubscribePackets(ctx, &snifferv1.SubscribePacketsRequest{
		SessionId: sessionID,
		Kinds:     []snifferv1.RecordKind{snifferv1.RecordKind_RECORD_KIND_WIRE_FRAME},
	})
	if err != nil {
		return fmt.Errorf("subscribe packets: %w", err)
	}
	for {
		rec, err := stream.Recv()
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
				return ctx.Err()
			}
			return err
		}
		if err := writer.WriteRecord(rec); err != nil {
			return err
		}
	}
}

func watchEvents(ctx context.Context, client snifferv1.HubServiceClient, sessionID string, w io.Writer) error {
	if w == nil {
		w = os.Stderr
	}
	stream, err := client.WatchEvents(ctx, &snifferv1.WatchEventsRequest{
		SessionId:     sessionID,
		ReplayHistory: true,
	})
	if err != nil {
		return err
	}
	for {
		ev, err := stream.Recv()
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "event: %s\n", ev.GetMessage())
	}
}

// defaultHubIngestAddr picks an address cluster agents can dial to reach the
// CLI's ingest listener. kind pods reach the host via the docker bridge gateway.
func defaultHubIngestAddr(lnAddr net.Addr) (string, error) {
	tcpAddr, ok := lnAddr.(*net.TCPAddr)
	if !ok {
		return "", fmt.Errorf("hub ingest address: unsupported listener type %T", lnAddr)
	}
	port := tcpAddr.Port
	if port == 0 {
		return "", fmt.Errorf("hub ingest address: listener has no assigned port")
	}

	if host, ok := hostReachableFromCluster(); ok {
		return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
	}
	return "", fmt.Errorf("hub ingest address: set --hub-ingest-addr (agents must reach the CLI from cluster nodes)")
}

func hostReachableFromCluster() (string, bool) {
	if v := os.Getenv("K8S_SNIFFER_HUB_INGEST_HOST"); v != "" {
		return v, true
	}
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", false
	}
	defer conn.Close()
	if udpAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok && !udpAddr.IP.IsLoopback() {
		return udpAddr.IP.String(), true
	}
	return "", false
}
