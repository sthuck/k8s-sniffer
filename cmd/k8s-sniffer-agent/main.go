// Command k8s-sniffer-agent runs in the per-node agent pod. It receives an
// AgentAssignment, captures each target netns, and streams frames to the hub.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/sthuck/k8s-sniffer/pkg/agent"
	"github.com/sthuck/k8s-sniffer/pkg/agent/capture"
	"github.com/sthuck/k8s-sniffer/pkg/agent/netns"
	"github.com/sthuck/k8s-sniffer/pkg/log"
)

var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	logLevel := flag.String("log-level", "", "log verbosity: info (default) or debug")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	level, err := log.ResolveLevel(*logLevel, os.Getenv(log.EnvLevel))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --log-level: %v\n", err)
		os.Exit(2)
	}
	log.Init(log.Config{Level: level})

	cliLog := log.WithComponent("agent")
	cliLog.Info("k8s-sniffer-agent starting", slog.String("version", version))

	cfg, err := agent.ConfigFromEnv()
	if err != nil {
		cliLog.Info("invalid configuration", slog.String("err", err.Error()))
		os.Exit(2)
	}

	resolver, err := netns.NewCRIResolver(context.Background(), "unix://"+cfg.CRISocket)
	if err != nil {
		cliLog.Info("cri resolver init failed", slog.String("err", err.Error()))
		os.Exit(1)
	}
	defer resolver.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	runner := agent.NewRunner(agent.RunnerOptions{
		Config:   cfg,
		Resolver: resolver,
		Tcpdump:  capture.Tcpdump{},
	})
	if err := runner.Run(ctx); err != nil && err != context.Canceled {
		cliLog.Info("agent exited with error", slog.String("err", err.Error()))
		os.Exit(1)
	}
}
