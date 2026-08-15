package sink

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"unicode/utf8"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
)

// JSONLWriter serializes TlsPlaintextEvent records as one JSON object per line.
type JSONLWriter struct {
	path  string
	file  *os.File
	enc   *json.Encoder
	mu    sync.Mutex
	count uint64
}

// OpenJSONL creates a JSONL writer at path. The parent directory is created if needed.
func OpenJSONL(path string) (*JSONLWriter, error) {
	if path == "" {
		return nil, fmt.Errorf("tls jsonl path: required")
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create tls-out directory: %w", err)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("open tls-out: %w", err)
	}
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	return &JSONLWriter{path: path, file: f, enc: enc}, nil
}

// TLSEventLine is the JSONL schema for --tls-out. Payload is UTF-8 when valid;
// otherwise Payload is omitted and PayloadB64 carries the bytes.
type TLSEventLine struct {
	Timestamp    string `json:"timestamp"`
	Namespace    string `json:"namespace,omitempty"`
	Pod          string `json:"pod,omitempty"`
	UID          string `json:"uid,omitempty"`
	Node         string `json:"node,omitempty"`
	Direction    string `json:"direction,omitempty"`
	PID          uint32 `json:"pid,omitempty"`
	Process      string `json:"process,omitempty"`
	TLSLibrary   string `json:"tls_library,omitempty"`
	ConnectionID string `json:"connection_id,omitempty"`
	Sequence     uint64 `json:"sequence"`
	Payload      string `json:"payload,omitempty"`
	PayloadB64   string `json:"payload_b64,omitempty"`
}

// WriteEvent appends one TLS plaintext event.
func (w *JSONLWriter) WriteEvent(ev *snifferv1.TlsPlaintextEvent) error {
	if ev == nil {
		return nil
	}
	line := TLSEventLine{
		PID:          ev.GetPid(),
		Process:      ev.GetProcess(),
		TLSLibrary:   ev.GetTlsLibrary(),
		ConnectionID: ev.GetConnectionId(),
		Sequence:     ev.GetSequence(),
		Direction:    directionName(ev.GetDirection()),
	}
	if ts := ev.GetTimestamp(); ts != nil && ts.IsValid() {
		line.Timestamp = ts.AsTime().UTC().Format("2006-01-02T15:04:05.000000000Z07:00")
	}
	if pod := ev.GetPod(); pod != nil {
		line.Namespace = pod.GetNamespace()
		line.Pod = pod.GetName()
		line.UID = pod.GetUid()
		line.Node = pod.GetNode()
	}
	payload := ev.GetPayload()
	if utf8.Valid(payload) {
		line.Payload = string(payload)
	} else if len(payload) > 0 {
		line.PayloadB64 = base64.StdEncoding.EncodeToString(payload)
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.enc.Encode(line); err != nil {
		return fmt.Errorf("write tls jsonl: %w", err)
	}
	w.count++
	return nil
}

// WriteRecord writes TLS events from a CaptureRecord envelope. Wire frames are ignored.
func (w *JSONLWriter) WriteRecord(rec *snifferv1.CaptureRecord) error {
	if rec == nil {
		return nil
	}
	return w.WriteEvent(rec.GetTlsEvent())
}

// EventCount returns the number of TLS events written.
func (w *JSONLWriter) EventCount() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.count
}

// Close flushes and closes the file.
func (w *JSONLWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

func directionName(d snifferv1.Direction) string {
	switch d {
	case snifferv1.Direction_DIRECTION_INBOUND:
		return "inbound"
	case snifferv1.Direction_DIRECTION_OUTBOUND:
		return "outbound"
	default:
		return ""
	}
}
