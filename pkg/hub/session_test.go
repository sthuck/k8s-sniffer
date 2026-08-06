package hub

import (
	"testing"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestValidateCaptureBatchDuringStartup(t *testing.T) {
	sess, batch := testCaptureSession()
	sess.setState(snifferv1.SessionState_SESSION_STATE_STARTING, "")
	if err := sess.validateCaptureBatch(batch); err != nil {
		t.Fatalf("validateCaptureBatch: %v", err)
	}
}

func TestValidateCaptureBatchRequiresStreamIdentity(t *testing.T) {
	sess, batch := testCaptureSession()
	sess.setState(snifferv1.SessionState_SESSION_STATE_RUNNING, "")
	batch.StreamId = ""
	if err := sess.validateCaptureBatch(batch); err == nil {
		t.Fatal("expected empty stream id to be rejected")
	}
}

func TestValidateCaptureBatchRejectsUnassignedPod(t *testing.T) {
	sess, batch := testCaptureSession()
	sess.setState(snifferv1.SessionState_SESSION_STATE_RUNNING, "")
	batch.Records[0].GetWireFrame().Pod.Name = "other"
	if err := sess.validateCaptureBatch(batch); err == nil {
		t.Fatal("expected unassigned pod to be rejected")
	}
}

func TestAssignmentForRequiresPodAndStream(t *testing.T) {
	sess, _ := testCaptureSession()
	if _, err := sess.assignmentFor("node-a", "agent-a", "wrong"); err == nil {
		t.Fatal("expected wrong stream id to be rejected")
	}
	if _, err := sess.assignmentFor("node-a", "wrong", "stream-a"); err == nil {
		t.Fatal("expected wrong agent pod to be rejected")
	}
	if _, err := sess.assignmentFor("node-a", "agent-a", "stream-a"); err != nil {
		t.Fatalf("assignmentFor: %v", err)
	}
}

func testCaptureSession() (*sessionState, *snifferv1.CaptureBatch) {
	pod := &snifferv1.PodRef{Namespace: "prod", Name: "api", Uid: "uid-a", Node: "node-a"}
	assignment := &snifferv1.AgentAssignment{
		SessionId: "session-a",
		Node:      "node-a",
		StreamId:  "stream-a",
		Targets:   []*snifferv1.Target{{Pod: pod}},
	}
	sess := newSessionState("session-a", &snifferv1.CaptureSpec{})
	sess.recordAgent("node-a", "agent-a", "stream-a", assignment)
	batch := &snifferv1.CaptureBatch{
		SessionId: "session-a",
		Node:      "node-a",
		StreamId:  "stream-a",
		Records: []*snifferv1.CaptureRecord{{
			Record: &snifferv1.CaptureRecord_WireFrame{
				WireFrame: &snifferv1.PacketFrame{
					Pod:            pod,
					Source:         snifferv1.PacketSource_PACKET_SOURCE_WIRE,
					Timestamp:      timestamppb.Now(),
					OriginalLength: 1,
					Payload:        []byte{1},
					Sequence:       1,
				},
			},
		}},
	}
	return sess, batch
}
