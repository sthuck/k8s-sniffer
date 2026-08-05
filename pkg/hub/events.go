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
	defer l.mu.Unlock()
	l.events = append(l.events, ev)
	for _, ch := range l.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (l *eventLog) history() []*snifferv1.SessionEvent {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]*snifferv1.SessionEvent, len(l.events))
	copy(out, l.events)
	return out
}

func (l *eventLog) subscribe() (int, <-chan *snifferv1.SessionEvent) {
	ch := make(chan *snifferv1.SessionEvent, 16)
	l.mu.Lock()
	defer l.mu.Unlock()
	id := l.nextID
	l.nextID++
	l.subs[id] = ch
	return id, ch
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
