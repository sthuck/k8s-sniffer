package tlsworker

import (
	"context"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
)

// Fake reports a fixed status and optionally emits canned events (IT3.1).
type Fake struct {
	Status Status
	Events []*snifferv1.TlsPlaintextEvent
	Err    error
}

func (f Fake) Attach(ctx context.Context, target Target) (<-chan *snifferv1.TlsPlaintextEvent, <-chan Status, error) {
	if f.Err != nil {
		return nil, nil, f.Err
	}
	events := make(chan *snifferv1.TlsPlaintextEvent, len(f.Events)+1)
	statuses := make(chan Status, 2)
	go func() {
		defer close(events)
		defer close(statuses)
		st := f.Status
		if st.Status == snifferv1.TlsStatus_TLS_STATUS_UNSPECIFIED {
			st.Status = snifferv1.TlsStatus_TLS_STATUS_UNSUPPORTED
			st.Detail = "fake tls worker"
		}
		statuses <- st
		for _, ev := range f.Events {
			clone := ev
			if clone.GetPod() == nil {
				clone.Pod = target.Pod
			}
			select {
			case events <- clone:
			case <-ctx.Done():
				return
			}
		}
		<-ctx.Done()
	}()
	return events, statuses, nil
}
