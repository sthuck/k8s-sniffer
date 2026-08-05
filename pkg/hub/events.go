package hub

import (
	"sync"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// eventLog buffers session events for replay and live fan-out.
type eventLog struct {
	mu     sync.RWMutex
	events []*snifferv1.SessionEvent
	subs   map[int]chan *snifferv1.SessionEvent
	nextID int
	closed bool
}

func newEventLog() *eventLog {
	return &eventLog{subs: make(map[int]chan *snifferv1.SessionEvent)}
}

func (l *eventLog) append(ev *snifferv1.SessionEvent) {
	if ev.Timestamp == nil {
		ev.Timestamp = timestamppb.Now()
	}
	l.mu.Lock()
	l.events = append(l.events, ev)
	subs := make([]chan *snifferv1.SessionEvent, 0, len(l.subs))
	for _, ch := range l.subs {
		subs = append(subs, ch)
	}
	l.mu.Unlock()
	for _, ch := range subs {
		ch <- ev
	}
}

func (l *eventLog) subscribeWithReplay() (int, <-chan *snifferv1.SessionEvent, []*snifferv1.SessionEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	history := make([]*snifferv1.SessionEvent, len(l.events))
	copy(history, l.events)
	ch := make(chan *snifferv1.SessionEvent, 64)
	id := l.nextID
	l.nextID++
	l.subs[id] = ch
	return id, ch, history
}

func (l *eventLog) unsubscribe(id int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ch, ok := l.subs[id]; ok {
		delete(l.subs, id)
		close(ch)
	}
}

func (l *eventLog) close() {
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
