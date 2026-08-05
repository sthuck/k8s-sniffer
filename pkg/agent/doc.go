// Package agent runs inside the per-node agent pod: it resolves each target
// container's network namespace, runs tcpdump there, and streams framed
// packets back to the hub.
//
// Placeholder: implementation lands with T1.9-T1.12.
package agent
