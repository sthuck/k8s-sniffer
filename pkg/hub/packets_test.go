package hub

import (
	"testing"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
)

func TestPacketLogFanOut(t *testing.T) {
	log := newPacketLog()
	id, ch := log.subscribe()
	defer log.unsubscribe(id)

	rec := &snifferv1.CaptureRecord{
		Record: &snifferv1.CaptureRecord_WireFrame{
			WireFrame: &snifferv1.PacketFrame{
				Pod:     &snifferv1.PodRef{Name: "api"},
				Payload: []byte{1, 2, 3},
			},
		},
	}
	log.publish(rec)

	got := <-ch
	if got.GetWireFrame().GetPod().GetName() != "api" {
		t.Fatalf("pod = %q", got.GetWireFrame().GetPod().GetName())
	}
}
