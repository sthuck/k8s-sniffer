package hub

import (
	"context"
	"testing"
	"time"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
)

func TestPacketLogFanOut(t *testing.T) {
	log := newPacketLog()
	id, ch, _, err := log.subscribe()
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
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

	id, ch, _, err := log.subscribe()
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer log.unsubscribe(id)
	if err := <-published; err != nil {
		t.Fatalf("publish: %v", err)
	}
	if got := <-ch; len(got.GetWireFrame().GetPayload()) != 1 {
		t.Fatalf("unexpected record: %+v", got)
	}
}

func TestPacketLogRetriesWhenOnlySubscriberDisconnects(t *testing.T) {
	log := newPacketLog()
	id, _, _, err := log.subscribe()
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	rec := &snifferv1.CaptureRecord{
		Record: &snifferv1.CaptureRecord_WireFrame{
			WireFrame: &snifferv1.PacketFrame{Payload: []byte{1}},
		},
	}
	for i := 0; i < 256; i++ {
		if err := log.publish(context.Background(), rec); err != nil {
			t.Fatalf("fill subscriber buffer: %v", err)
		}
	}
	published := make(chan error, 1)
	go func() {
		published <- log.publish(context.Background(), rec)
	}()
	waitForActivePublishes(t, log, 1)
	log.unsubscribe(id)
	waitForActivePublishes(t, log, 0)

	select {
	case err := <-published:
		t.Fatalf("publish completed without a live subscriber: %v", err)
	default:
	}

	replacementID, replacement, _, err := log.subscribe()
	if err != nil {
		t.Fatalf("replacement subscribe: %v", err)
	}
	defer log.unsubscribe(replacementID)
	if err := <-published; err != nil {
		t.Fatalf("publish to replacement: %v", err)
	}
	if got := <-replacement; got.GetWireFrame() == nil {
		t.Fatalf("unexpected replacement record: %+v", got)
	}
}

func TestPacketLogClosePreservesBufferedRecords(t *testing.T) {
	log := newPacketLog()
	_, ch, done, err := log.subscribe()
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	rec := &snifferv1.CaptureRecord{
		Record: &snifferv1.CaptureRecord_WireFrame{
			WireFrame: &snifferv1.PacketFrame{Payload: []byte{1}},
		},
	}
	for i := 0; i < 3; i++ {
		if err := log.publish(context.Background(), rec); err != nil {
			t.Fatalf("publish: %v", err)
		}
	}
	if err := log.close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	<-done
	for i := 0; i < 3; i++ {
		if got := <-ch; got.GetWireFrame() == nil {
			t.Fatalf("buffered record %d missing", i)
		}
	}
	if len(ch) != 0 {
		t.Fatalf("buffer contains %d unexpected records", len(ch))
	}
}

func waitForActivePublishes(t *testing.T, log *packetLog, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		log.mu.Lock()
		active := log.active
		log.mu.Unlock()
		if active == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("active publishes = %d, want %d", active, want)
		}
		time.Sleep(time.Millisecond)
	}
}
