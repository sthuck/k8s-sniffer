package hub

import (
	"sync"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
)

// packetLog fans CaptureRecords out to SubscribePackets clients.
type packetLog struct {
	mu     sync.RWMutex
	subs   map[int]chan *snifferv1.CaptureRecord
	nextID int
	closed bool
}

func newPacketLog() *packetLog {
	return &packetLog{subs: make(map[int]chan *snifferv1.CaptureRecord)}
}

func (l *packetLog) publish(rec *snifferv1.CaptureRecord) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	subs := make([]chan *snifferv1.CaptureRecord, 0, len(l.subs))
	for _, ch := range l.subs {
		subs = append(subs, ch)
	}
	l.mu.Unlock()
	for _, ch := range subs {
		ch := ch
		go func() { ch <- rec }()
	}
}

func (l *packetLog) subscribe() (int, <-chan *snifferv1.CaptureRecord) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ch := make(chan *snifferv1.CaptureRecord, 256)
	id := l.nextID
	l.nextID++
	l.subs[id] = ch
	return id, ch
}

func (l *packetLog) unsubscribe(id int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ch, ok := l.subs[id]; ok {
		delete(l.subs, id)
		close(ch)
	}
}

func (l *packetLog) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	l.closed = true
	for id, ch := range l.subs {
		delete(l.subs, id)
		close(ch)
	}
}
