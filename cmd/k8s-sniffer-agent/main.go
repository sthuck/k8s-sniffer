// Command k8s-sniffer-agent runs in the per-node agent pod. It receives an
// AgentAssignment, captures each target netns, and streams frames to the hub.
//
// Placeholder: bootstrap and capture land with T1.9-T1.12.
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

	fmt.Fprintf(os.Stderr, `k8s-sniffer-agent %s

The agent capture pipeline is not implemented yet (tasks T1.9-T1.12).
`, version)
	os.Exit(1)
}
