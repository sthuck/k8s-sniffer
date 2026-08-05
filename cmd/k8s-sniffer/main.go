// Command k8s-sniffer is the client entry point: it builds a CaptureSpec from
// flags, drives a hub, and writes PCAP to a sink.
//
// Placeholder: the capture command lands with T1.14.
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

	cliLog := log.WithComponent("cli")
	cliLog.Info("k8s-sniffer starting", slog.String("version", version))
	cliLog.Debug("logging configured", slog.String("level", string(level)))

	fmt.Fprintf(os.Stderr, `k8s-sniffer %s

Usage:
  k8s-sniffer capture -n NAMESPACE --pod REGEX [-o out.pcapng]

The capture command is not implemented yet (task T1.14). This build only
carries the shared API and capture spec.
`, version)
	os.Exit(1)
}
