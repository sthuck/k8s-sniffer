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
	active  int
	idle    chan struct{}
}

func newPacketLog() *packetLog {
	idle := make(chan struct{})
	close(idle)
	return &packetLog{
		subs:    make(map[int]*packetSubscriber),
		changed: make(chan struct{}),
		idle:    idle,
	}
}

func (l *packetLog) waitForSubscriber(ctx context.Context) error {
	for {
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return errPacketLogClosed
		}
		if len(l.subs) > 0 {
			l.mu.Unlock()
			return nil
		}
		changed := l.changed
		l.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

func (l *packetLog) publish(ctx context.Context, rec *snifferv1.CaptureRecord) error {
	for {
		if err := l.waitForSubscriber(ctx); err != nil {
			return err
		}
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return errPacketLogClosed
		}
		subs := make([]*packetSubscriber, 0, len(l.subs))
		for _, sub := range l.subs {
			subs = append(subs, sub)
		}
		if l.active == 0 {
			l.idle = make(chan struct{})
		}
		l.active++
		l.mu.Unlock()

		delivered := 0
		for _, sub := range subs {
			clone := proto.Clone(rec).(*snifferv1.CaptureRecord)
			select {
			case <-ctx.Done():
				l.finishPublish()
				return ctx.Err()
			case <-sub.done:
			case sub.ch <- clone:
				delivered++
			}
		}
		l.finishPublish()
		if delivered > 0 {
			return nil
		}
	}
}

func (l *packetLog) subscribe() (int, <-chan *snifferv1.CaptureRecord, <-chan struct{}, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return 0, nil, nil, errPacketLogClosed
	}
	sub := &packetSubscriber{
		ch:   make(chan *snifferv1.CaptureRecord, 256),
		done: make(chan struct{}),
	}
	id := l.nextID
	l.nextID++
	l.subs[id] = sub
	l.notifyLocked()
	return id, sub.ch, sub.done, nil
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

func (l *packetLog) close(ctx context.Context) error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	l.notifyLocked()
	idle := l.idle
	l.mu.Unlock()

	select {
	case <-idle:
	case <-ctx.Done():
		l.closeSubscribers()
		<-idle
		return ctx.Err()
	}
	l.closeSubscribers()
	return nil
}

func (l *packetLog) closeSubscribers() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, sub := range l.subs {
		delete(l.subs, id)
		close(sub.done)
	}
	l.notifyLocked()
}

func (l *packetLog) finishPublish() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.active--
	if l.active == 0 {
		close(l.idle)
	}
}

func (l *packetLog) notifyLocked() {
	close(l.changed)
	l.changed = make(chan struct{})
}
