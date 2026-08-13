package tlsworker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	pidCommRe = regexp.MustCompile(`(?i)PID:(\d+).*?Comm:([^\s,]+)`)
	headerRe  = regexp.MustCompile(`(?i)^(?:.*\s)?PID:\d+`)
)

// parsedEvent is a TLS plaintext record extracted from ecapture text or JSON.
type parsedEvent struct {
	PID       uint32
	Process   string
	Direction snifferv1.Direction
	Payload   []byte
	ConnID    string
	Timestamp time.Time
}

func parseStream(ctx context.Context, r io.Reader, out chan<- parsedEvent) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 2<<20)
	var cur *parsedEvent
	send := func(ev parsedEvent) bool {
		select {
		case out <- ev:
			return true
		case <-ctx.Done():
			return false
		}
	}
	flush := func() bool {
		if cur == nil || len(bytes.TrimSpace(cur.Payload)) == 0 {
			cur = nil
			return true
		}
		ok := send(*cur)
		cur = nil
		return ok
	}
	for sc.Scan() {
		if ctx.Err() != nil {
			return
		}
		line := sc.Text()
		if ev, ok := parseJSONLine(line); ok {
			if !flush() {
				return
			}
			if !send(ev) {
				return
			}
			continue
		}
		if headerRe.MatchString(line) && strings.Contains(strings.ToLower(line), "pid:") {
			if !flush() {
				return
			}
			cur = parseTextHeader(line)
			if i := strings.Index(line, "Payload:"); i >= 0 {
				rest := strings.TrimSpace(line[i+len("Payload:"):])
				if rest != "" {
					cur.Payload = []byte(rest + "\n")
				}
			}
			continue
		}
		if cur != nil {
			cur.Payload = append(cur.Payload, line...)
			cur.Payload = append(cur.Payload, '\n')
		}
	}
	_ = flush()
}

func parseJSONLine(line string) (parsedEvent, bool) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] != '{' {
		return parsedEvent{}, false
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return parsedEvent{}, false
	}
	payload := jsonPayload(raw)
	if len(payload) == 0 {
		return parsedEvent{}, false
	}
	ev := parsedEvent{
		PID:       jsonUint32(raw, "pid", "Pid", "PID"),
		Process:   jsonString(raw, "comm", "Comm", "process", "pname"),
		Payload:   payload,
		ConnID:    jsonString(raw, "tuple", "Tuple", "connection_id"),
		Direction: jsonDirection(raw),
		Timestamp: time.Now(),
	}
	return ev, true
}

func jsonPayload(raw map[string]any) []byte {
	for _, key := range []string{"payload", "Payload", "data", "Data"} {
		switch v := raw[key].(type) {
		case string:
			if v != "" {
				return []byte(v)
			}
		case []byte:
			if len(v) > 0 {
				return v
			}
		}
	}
	return nil
}

func jsonString(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		if s, ok := raw[key].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func jsonUint32(raw map[string]any, keys ...string) uint32 {
	for _, key := range keys {
		switch v := raw[key].(type) {
		case float64:
			if v > 0 {
				return uint32(v)
			}
		case string:
			n, _ := strconv.ParseUint(v, 10, 32)
			return uint32(n)
		}
	}
	return 0
}

func jsonDirection(raw map[string]any) snifferv1.Direction {
	for _, key := range []string{"eventType", "dataType", "type", "direction"} {
		switch v := raw[key].(type) {
		case float64:
			if int(v) == 1 {
				return snifferv1.Direction_DIRECTION_INBOUND
			}
			if int(v) == 0 {
				return snifferv1.Direction_DIRECTION_OUTBOUND
			}
		case string:
			s := strings.ToLower(v)
			if strings.Contains(s, "read") || s == "inbound" || s == "received" {
				return snifferv1.Direction_DIRECTION_INBOUND
			}
			if strings.Contains(s, "write") || s == "outbound" || s == "send" {
				return snifferv1.Direction_DIRECTION_OUTBOUND
			}
		}
	}
	return snifferv1.Direction_DIRECTION_UNSPECIFIED
}

func parseTextHeader(line string) *parsedEvent {
	ev := &parsedEvent{Timestamp: time.Now()}
	if m := pidCommRe.FindStringSubmatch(line); len(m) == 3 {
		n, _ := strconv.ParseUint(m[1], 10, 32)
		ev.PID = uint32(n)
		ev.Process = strings.TrimSpace(m[2])
	}
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "received") || strings.Contains(lower, "ssl_read"):
		ev.Direction = snifferv1.Direction_DIRECTION_INBOUND
	case strings.Contains(lower, "send") || strings.Contains(lower, "ssl_write"):
		ev.Direction = snifferv1.Direction_DIRECTION_OUTBOUND
	}
	if i := strings.Index(lower, "tuple:"); i >= 0 {
		rest := line[i+6:]
		if j := strings.IndexAny(rest, ", "); j >= 0 {
			ev.ConnID = strings.TrimSpace(rest[:j])
		} else {
			ev.ConnID = strings.TrimSpace(rest)
		}
	}
	return ev
}

func toProto(pod *snifferv1.PodRef, ev parsedEvent, seq uint64) *snifferv1.TlsPlaintextEvent {
	ts := ev.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	return &snifferv1.TlsPlaintextEvent{
		Pod:          pod,
		Timestamp:    timestamppb.New(ts),
		Direction:    ev.Direction,
		Payload:      ev.Payload,
		ConnectionId: ev.ConnID,
		Pid:          ev.PID,
		Process:      ev.Process,
		TlsLibrary:   "openssl",
		Sequence:     seq,
	}
}
