package hub

import (
	"context"
	"testing"
	"time"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
)

func TestPacketLogFanOut(t *testing.T) {
	log := newPacketLog()
	id, ch, _ := log.subscribe()
	defer log.unsubscribe(id)

	rec := &snifferv1.CaptureRecord{
		Record: &snifferv1.CaptureRecord_WireFrame{
			WireFrame: &snifferv1.PacketFrame{
				Pod:     &snifferv1.PodRef{Name: "api"},
				Payload: []byte{1, 2, 3},
			},
		},
	}
	if err := log.publish(context.Background(), rec); err != nil {
		t.Fatalf("publish: %v", err)
	}

	got := <-ch
	if got.GetWireFrame().GetPod().GetName() != "api" {
		t.Fatalf("pod = %q", got.GetWireFrame().GetPod().GetName())
	}
}

func TestPacketLogWaitsForFirstSubscriber(t *testing.T) {
	log := newPacketLog()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	rec := &snifferv1.CaptureRecord{
		Record: &snifferv1.CaptureRecord_WireFrame{
			WireFrame: &snifferv1.PacketFrame{Payload: []byte{1}},
		},
	}
	published := make(chan error, 1)
	go func() {
		published <- log.publish(ctx, rec)
	}()

	select {
	case err := <-published:
		t.Fatalf("publish completed without subscriber: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	id, ch, _ := log.subscribe()
	defer log.unsubscribe(id)
	if err := <-published; err != nil {
		t.Fatalf("publish: %v", err)
	}
	if got := <-ch; len(got.GetWireFrame().GetPayload()) != 1 {
		t.Fatalf("unexpected record: %+v", got)
	}
}
