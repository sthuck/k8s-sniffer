// Package agent runs inside the per-node agent pod: it resolves each target
// container's network namespace, runs tcpdump there, and streams framed
// packets back to the hub.
package agent
