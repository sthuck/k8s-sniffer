package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sthuck/k8s-sniffer/pkg/capture"
	"github.com/sthuck/k8s-sniffer/pkg/k8s"
)

// NewCaptureCommand returns the `capture` subcommand.
func NewCaptureCommand(ctx context.Context, version string, run func(context.Context, CaptureOptions) error) *cobra.Command {
	var (
		namespace       string
		podPatterns     []string
		outPath         string
		bpfFilter       string
		duration        time.Duration
		snaplen         uint32
		kubeconfig      string
		kubeContext     string
		agentNamespace  string
		agentImage      string
		criSocket       string
		allowMutableImg bool
		hubListen       string
		hubIngest       string
		logLevel        string
	)

	cmd := &cobra.Command{
		Use:   "capture",
		Short: "Capture pod network traffic to PCAP",
		Long: `Match Running pods in a namespace by name regex, schedule node-local
capture agents, and write wire traffic to a PCAP or PCAPng file.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			spec := capture.Spec{
				Namespace:   namespace,
				PodPatterns: append([]string(nil), podPatterns...),
				BPFFilter:   bpfFilter,
				Duration:    duration,
				Snaplen:     snaplen,
				TLSMode:     capture.TLSModeOff,
			}
			agentCfg := capture.DefaultAgentConfig()
			agentCfg.Namespace = agentNamespace
			agentCfg.Image = agentImage
			agentCfg.CRISocketHostPath = criSocket
			agentCfg.AllowMutableImage = allowMutableImg
			agentCfg.LogLevel = logLevel

			return run(ctx, CaptureOptions{
				Spec: spec,
				Sink: capture.SinkSpec{Out: outPath},
				Agent: agentCfg,
				Kube: k8s.ClientConfig{
					Kubeconfig: kubeconfig,
					Context:    kubeContext,
					Namespace:  namespace,
					UserAgent:  "k8s-sniffer/" + version,
				},
				HubListen: hubListen,
				HubIngest: hubIngest,
			})
		},
	}

	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace of pods to capture (required)")
	cmd.Flags().StringArrayVar(&podPatterns, "pod", nil, "Pod name regex (repeatable)")
	cmd.Flags().StringVarP(&outPath, "out", "o", "capture.pcapng", "Output PCAP path, or \"-\" for stdout")
	cmd.Flags().StringVar(&bpfFilter, "bpf", "", "tcpdump BPF filter")
	cmd.Flags().DurationVar(&duration, "duration", 0, "Hard stop after duration (0 = until interrupted)")
	cmd.Flags().Uint32Var(&snaplen, "snaplen", 0, "Per-packet snaplen (0 = default)")
	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig (default: standard search paths)")
	cmd.Flags().StringVar(&kubeContext, "context", "", "Kubeconfig context override")
	cmd.Flags().StringVar(&agentNamespace, "agent-namespace", capture.DefaultAgentNamespace, "Namespace for ephemeral agent pods")
	cmd.Flags().StringVar(&agentImage, "agent-image", capture.DefaultAgentImage(), "Agent container image (digest-pinned in release builds)")
	cmd.Flags().StringVar(&criSocket, "cri-socket", capture.DefaultCRISocketPath, "Node CRI socket host path mounted into agents")
	cmd.Flags().BoolVar(&allowMutableImg, "allow-mutable-agent-image", false, "Allow tag-based agent image references (development/e2e)")
	cmd.Flags().StringVar(&hubListen, "hub-listen", "", "Hub gRPC listen address (default: 0.0.0.0:ephemeral)")
	cmd.Flags().StringVar(&hubIngest, "hub-ingest-addr", "", "Address agents dial for ingest (default: auto-detect host IP)")
	_ = cmd.Flags().MarkHidden("hub-listen")

	_ = cmd.MarkFlagRequired("namespace")
	_ = cmd.MarkFlagRequired("pod")

	return cmd
}

// ParsePodPatterns splits comma-separated patterns from a single flag value.
func ParsePodPatterns(values []string) ([]string, error) {
	var out []string
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one --pod pattern is required")
	}
	return out, nil
}
