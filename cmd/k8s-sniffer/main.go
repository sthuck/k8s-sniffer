// Command k8s-sniffer is the client entry point: it builds a CaptureSpec from
// flags, drives a hub, and writes PCAP to a sink.
//
// Placeholder: the capture command lands with T1.14.
package main

import (
	"flag"
	"fmt"
	"os"
)

var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	fmt.Fprintf(os.Stderr, `k8s-sniffer %s

Usage:
  k8s-sniffer capture -n NAMESPACE --pod REGEX [-o out.pcapng]

The capture command is not implemented yet (task T1.14). This build only
carries the shared API and capture spec.
`, version)
	os.Exit(1)
}
