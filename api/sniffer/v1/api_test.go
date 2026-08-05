package snifferv1_test

import (
	"bytes"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
)

func TestPacketFrameRoundTrip(t *testing.T) {
	captureTime := time.Date(2026, 8, 5, 12, 0, 0, 123456000, time.UTC)
	payload := []byte{0x45, 0x00, 0x00, 0x28, 0xde, 0xad, 0xbe, 0xef}

	original := &snifferv1.PacketFrame{
		Pod: &snifferv1.PodRef{
			Namespace:   "prod",
			Name:        "payments-7d9f-abc",
			Uid:         "0d2b1c26-4f0f-4f1e-9c2b-1d6f0f9c2b1d",
			Node:        "node-1",
			ContainerId: "containerd://a1b2c3",
		},
		Source:         snifferv1.PacketSource_PACKET_SOURCE_WIRE,
		Timestamp:      timestamppb.New(captureTime),
		LinkType:       snifferv1.LinkType_LINK_TYPE_LINUX_SLL2,
		OriginalLength: 1514,
		Payload:        payload,
		Sequence:       42,
	}

	encoded, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded snifferv1.PacketFrame
	if err := proto.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if !proto.Equal(original, &decoded) {
		t.Fatalf("decoded frame differs:\n got %v\nwant %v", &decoded, original)
	}
	if got := decoded.GetPod().GetName(); got != "payments-7d9f-abc" {
		t.Errorf("pod name = %q, want payments-7d9f-abc", got)
	}
	if !decoded.GetTimestamp().AsTime().Equal(captureTime) {
		t.Errorf("timestamp = %v, want %v", decoded.GetTimestamp().AsTime(), captureTime)
	}
	if !bytes.Equal(decoded.GetPayload(), payload) {
		t.Errorf("payload = %x, want %x", decoded.GetPayload(), payload)
	}
	if decoded.GetLinkType() != snifferv1.LinkType_LINK_TYPE_LINUX_SLL2 {
		t.Errorf("link type = %v, want LINUX_SLL2", decoded.GetLinkType())
	}
}

func TestCaptureBatchRoundTripPreservesOrder(t *testing.T) {
	batch := &snifferv1.CaptureBatch{
		SessionId: "sess-1",
		Node:      "node-1",
		StreamId:  "node-1/1",
		Dropped:   7,
	}
	for i := range 3 {
		batch.Records = append(batch.Records, &snifferv1.CaptureRecord{
			Record: &snifferv1.CaptureRecord_WireFrame{WireFrame: &snifferv1.PacketFrame{
				Pod:      &snifferv1.PodRef{Name: "api-0", Node: "node-1"},
				Source:   snifferv1.PacketSource_PACKET_SOURCE_WIRE,
				Sequence: uint64(i),
				Payload:  []byte{byte(i)},
			}},
		})
	}

	encoded, err := proto.Marshal(batch)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded snifferv1.CaptureBatch
	if err := proto.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got := len(decoded.GetRecords()); got != 3 {
		t.Fatalf("records = %d, want 3", got)
	}
	for i, record := range decoded.GetRecords() {
		frame := record.GetWireFrame()
		if frame == nil {
			t.Fatalf("record %d is not a wire frame", i)
		}
		if frame.GetSequence() != uint64(i) {
			t.Fatalf("record %d sequence = %d, want %d", i, frame.GetSequence(), i)
		}
	}
	if decoded.GetDropped() != 7 {
		t.Errorf("dropped = %d, want 7", decoded.GetDropped())
	}
	// Sequence numbers are only comparable within a stream id, so the batch has
	// to carry the agent incarnation that produced them.
	if decoded.GetStreamId() != "node-1/1" {
		t.Errorf("stream id = %q, want node-1/1", decoded.GetStreamId())
	}
}

// The subscription envelope must carry either source, so Phase 3 plaintext
// needs no new stream.
func TestCaptureRecordEnvelope(t *testing.T) {
	records := []*snifferv1.CaptureRecord{
		{Record: &snifferv1.CaptureRecord_WireFrame{WireFrame: &snifferv1.PacketFrame{
			Pod:      &snifferv1.PodRef{Name: "api-0"},
			Source:   snifferv1.PacketSource_PACKET_SOURCE_WIRE,
			LinkType: snifferv1.LinkType_LINK_TYPE_ETHERNET,
			Payload:  []byte{0x01},
		}}},
		{Record: &snifferv1.CaptureRecord_TlsEvent{TlsEvent: &snifferv1.TlsPlaintextEvent{
			Pod:          &snifferv1.PodRef{Name: "api-0"},
			Timestamp:    timestamppb.New(time.Unix(1700000000, 0)),
			Direction:    snifferv1.Direction_DIRECTION_OUTBOUND,
			Payload:      []byte("GET /e2e/token HTTP/1.1\r\n\r\n"),
			ConnectionId: "conn-1",
			Pid:          4242,
			Process:      "curl",
			TlsLibrary:   "openssl",
			Sequence:     1,
		}}},
	}

	for _, record := range records {
		encoded, err := proto.Marshal(record)
		if err != nil {
			t.Fatalf("Marshal %T: %v", record.GetRecord(), err)
		}
		var decoded snifferv1.CaptureRecord
		if err := proto.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("Unmarshal %T: %v", record.GetRecord(), err)
		}
		if !proto.Equal(record, &decoded) {
			t.Fatalf("record %T did not round trip:\n got %v\nwant %v", record.GetRecord(), &decoded, record)
		}
	}

	if records[0].GetTlsEvent() != nil || records[1].GetWireFrame() != nil {
		t.Error("oneof accessors returned the wrong arm")
	}
}

func TestSessionEventOneofPayloads(t *testing.T) {
	events := []*snifferv1.SessionEvent{
		{Payload: &snifferv1.SessionEvent_SessionState{
			SessionState: &snifferv1.SessionStateChanged{State: snifferv1.SessionState_SESSION_STATE_RUNNING},
		}},
		{Payload: &snifferv1.SessionEvent_PodAttached{
			PodAttached: &snifferv1.PodAttached{Pod: &snifferv1.PodRef{Name: "api-0"}},
		}},
		{Payload: &snifferv1.SessionEvent_AgentState{
			AgentState: &snifferv1.AgentStateChanged{Node: "node-1", Phase: snifferv1.AgentPhase_AGENT_PHASE_CAPTURING},
		}},
		{Payload: &snifferv1.SessionEvent_TlsState{
			TlsState: &snifferv1.TlsStateChanged{Status: snifferv1.TlsStatus_TLS_STATUS_UNSUPPORTED},
		}},
		{Payload: &snifferv1.SessionEvent_Stats{
			Stats: &snifferv1.SessionStats{Packets: 10, Bytes: 2048, PerPod: []*snifferv1.PodCounters{{
				Pod: &snifferv1.PodRef{Name: "api-0"}, Packets: 10,
			}}},
		}},
		{Payload: &snifferv1.SessionEvent_Error{
			Error: &snifferv1.CaptureError{
				Stage:     snifferv1.ErrorStage_ERROR_STAGE_NETNS_RESOLVE,
				Reason:    snifferv1.ErrorReason_ERROR_REASON_NOT_FOUND,
				Detail:    "container 4f1e not found via CRI",
				Retryable: true,
				Pod:       &snifferv1.PodRef{Name: "api-0", Node: "node-1"},
				Node:      "node-1",
				AgentPod:  "k8s-sniffer-abcde",
				StreamId:  "node-1/1",
			},
		}},
	}

	for _, event := range events {
		event.SessionId = "sess-1"
		event.Severity = snifferv1.Severity_SEVERITY_INFO
		event.Timestamp = timestamppb.New(time.Unix(1700000000, 0))

		encoded, err := proto.Marshal(event)
		if err != nil {
			t.Fatalf("Marshal %T: %v", event.GetPayload(), err)
		}
		var decoded snifferv1.SessionEvent
		if err := proto.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("Unmarshal %T: %v", event.GetPayload(), err)
		}
		if !proto.Equal(event, &decoded) {
			t.Fatalf("payload %T did not round trip:\n got %v\nwant %v", event.GetPayload(), &decoded, event)
		}
	}
}

// Failures must be machine-readable on both the agent and client channels: a UI
// should never have to parse prose to find the affected pod or the category.
func TestFailuresAreStructuredOnBothChannels(t *testing.T) {
	captureErr := &snifferv1.CaptureError{
		Stage:  snifferv1.ErrorStage_ERROR_STAGE_CAPTURE_START,
		Reason: snifferv1.ErrorReason_ERROR_REASON_TOOL_FAILED,
		Detail: "tcpdump exited 1",
		Pod:    &snifferv1.PodRef{Name: "api-0", Node: "node-1"},
	}

	report := &snifferv1.ReportStatusRequest{
		SessionId: "sess-1",
		Node:      "node-1",
		StreamId:  "node-1/1",
		Payload:   &snifferv1.ReportStatusRequest_Error{Error: captureErr},
	}
	encoded, err := proto.Marshal(report)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded snifferv1.ReportStatusRequest
	if err := proto.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got := decoded.GetError().GetPod().GetName(); got != "api-0" {
		t.Errorf("agent error lost pod scope: %q", got)
	}
	if got := decoded.GetError().GetReason(); got != snifferv1.ErrorReason_ERROR_REASON_TOOL_FAILED {
		t.Errorf("agent error reason = %v, want TOOL_FAILED", got)
	}
}
