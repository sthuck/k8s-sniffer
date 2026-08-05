// Command k8s-sniffer-agent runs in the per-node agent pod. It receives an
// AgentAssignment, captures each target netns, and streams frames to the hub.
//
// Placeholder: bootstrap and capture land with T1.9-T1.12.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

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

	agentLog := log.WithComponent("agent")
	agentLog.Info("k8s-sniffer-agent starting", slog.String("version", version))
	agentLog.Debug("logging configured", slog.String("level", string(level)))

	fmt.Fprintf(os.Stderr, `k8s-sniffer-agent %s

The agent capture pipeline is not implemented yet (tasks T1.9-T1.12).
`, version)
	os.Exit(1)
}
