// Package tlsworker supervises per-target TLS plaintext capture (ecapture).
package tlsworker

import (
	"context"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
)

// Target is the process the worker should attach to.
type Target struct {
	Pod       *snifferv1.PodRef
	PID       int
	Mode      snifferv1.TlsMode
	SessionID string
}

// Status is a per-pod TLS outcome for ReportStatus / WatchEvents.
type Status struct {
	Status snifferv1.TlsStatus
	Detail string
}

// Attacher starts (and later stops, via ctx) TLS capture for one target.
// Implementations must not fail the wire capture path: report Status instead.
type Attacher interface {
	Attach(ctx context.Context, target Target) (<-chan *snifferv1.TlsPlaintextEvent, <-chan Status, error)
}

// WantsAttach reports whether this TLS mode should start a worker.
func WantsAttach(mode snifferv1.TlsMode) bool {
	return mode == snifferv1.TlsMode_TLS_MODE_EBPF ||
		mode == snifferv1.TlsMode_TLS_MODE_AUTO ||
		mode == snifferv1.TlsMode_TLS_MODE_KEYLOG
}
