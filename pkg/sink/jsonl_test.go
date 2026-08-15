package sink_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	"github.com/sthuck/k8s-sniffer/pkg/sink"
)

func TestJSONLWriterRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tls.jsonl")
	w, err := sink.OpenJSONL(path)
	if err != nil {
		t.Fatalf("OpenJSONL: %v", err)
	}
	ev := &snifferv1.TlsPlaintextEvent{
		Pod:          &snifferv1.PodRef{Namespace: "prod", Name: "api", Uid: "uid-1", Node: "node-a"},
		Timestamp:    timestamppb.New(time.Unix(1_700_000_000, 0).UTC()),
		Direction:    snifferv1.Direction_DIRECTION_OUTBOUND,
		Payload:      []byte("GET /e2e-secret-token HTTP/1.1\r\n"),
		ConnectionId: "conn-1",
		Pid:          42,
		Process:      "nginx",
		TlsLibrary:   "openssl",
		Sequence:     7,
	}
	if err := w.WriteEvent(ev); err != nil {
		t.Fatalf("WriteEvent: %v", err)
	}
	if err := w.WriteRecord(&snifferv1.CaptureRecord{
		Record: &snifferv1.CaptureRecord_WireFrame{WireFrame: &snifferv1.PacketFrame{Payload: []byte{1}}},
	}); err != nil {
		t.Fatalf("WriteRecord wire: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if w.EventCount() != 1 {
		t.Fatalf("EventCount = %d, want 1", w.EventCount())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "e2e-secret-token") {
		t.Fatalf("jsonl missing plaintext marker:\n%s", data)
	}
	var line sink.TLSEventLine
	if err := json.Unmarshal(data, &line); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if line.Pod != "api" || line.Direction != "outbound" || line.Sequence != 7 || line.PID != 42 {
		t.Fatalf("line = %+v", line)
	}
}

func TestJSONLWriterBinaryPayload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tls.jsonl")
	w, err := sink.OpenJSONL(path)
	if err != nil {
		t.Fatalf("OpenJSONL: %v", err)
	}
	if err := w.WriteEvent(&snifferv1.TlsPlaintextEvent{Payload: []byte{0xff, 0xfe, 0x00}}); err != nil {
		t.Fatalf("WriteEvent: %v", err)
	}
	_ = w.Close()

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		t.Fatal("expected a jsonl line")
	}
	var line sink.TLSEventLine
	if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
		t.Fatal(err)
	}
	if line.Payload != "" || line.PayloadB64 == "" {
		t.Fatalf("binary payload should use payload_b64: %+v", line)
	}
}
