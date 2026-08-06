package hub

import (
	"context"
	"errors"
	"sync"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	"google.golang.org/protobuf/proto"
)

var errPacketLogClosed = errors.New("packet log closed")

type packetSubscriber struct {
	ch   chan *snifferv1.CaptureRecord
	done chan struct{}
}

// packetLog fans CaptureRecords out to SubscribePackets clients.
type packetLog struct {
	mu      sync.Mutex
	subs    map[int]*packetSubscriber
	nextID  int
	closed  bool
	changed chan struct{}
}

func newPacketLog() *packetLog {
	return &packetLog{
		subs:    make(map[int]*packetSubscriber),
		changed: make(chan struct{}),
	}
}

func (l *packetLog) publish(ctx context.Context, rec *snifferv1.CaptureRecord) error {
	for {
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return errPacketLogClosed
		}
		if len(l.subs) == 0 {
			changed := l.changed
			l.mu.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-changed:
				continue
			}
		}
		subs := make([]*packetSubscriber, 0, len(l.subs))
		for _, sub := range l.subs {
			subs = append(subs, sub)
		}
		l.mu.Unlock()

		for _, sub := range subs {
			clone := proto.Clone(rec).(*snifferv1.CaptureRecord)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-sub.done:
			case sub.ch <- clone:
			}
		}
		return nil
	}
}

func (l *packetLog) subscribe() (int, <-chan *snifferv1.CaptureRecord, <-chan struct{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	sub := &packetSubscriber{
		ch:   make(chan *snifferv1.CaptureRecord, 256),
		done: make(chan struct{}),
	}
	id := l.nextID
	l.nextID++
	l.subs[id] = sub
	l.notifyLocked()
	return id, sub.ch, sub.done
}

func (l *packetLog) unsubscribe(id int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if sub, ok := l.subs[id]; ok {
		delete(l.subs, id)
		close(sub.done)
		l.notifyLocked()
	}
}

func (l *packetLog) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	l.closed = true
	for id, sub := range l.subs {
		delete(l.subs, id)
		close(sub.done)
	}
	l.notifyLocked()
}

func (l *packetLog) notifyLocked() {
	close(l.changed)
	l.changed = make(chan struct{})
}
