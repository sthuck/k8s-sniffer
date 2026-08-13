package hub

import (
	"testing"
	"time"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	"google.golang.org/protobuf/proto"
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

func TestValidateCaptureBatchAllowsUnassignedPod(t *testing.T) {
	sess, batch := testCaptureSession()
	sess.setState(snifferv1.SessionState_SESSION_STATE_RUNNING, "")
	pod := proto.Clone(batch.Records[0].GetWireFrame().GetPod()).(*snifferv1.PodRef)
	pod.Name = "other"
	batch.Records[0].GetWireFrame().Pod = pod
	if err := sess.validateCaptureBatch(batch); err != nil {
		t.Fatalf("in-flight unassigned record should be skipped, not rejected: %v", err)
	}
}

func TestCommitUnassignedAdvancesSequenceWithoutStats(t *testing.T) {
	sess, batch := testCaptureSession()
	unassigned := proto.Clone(batch.GetRecords()[0]).(*snifferv1.CaptureRecord)
	pod := proto.Clone(unassigned.GetWireFrame().GetPod()).(*snifferv1.PodRef)
	pod.Name = "other"
	unassigned.GetWireFrame().Pod = pod
	if err := sess.commitCaptureRecord("node-a", "stream-a", unassigned, false); err != nil {
		t.Fatalf("commit unassigned sequence: %v", err)
	}
	if stats := sess.snapshotStats(); stats.GetPackets() != 0 {
		t.Fatalf("packets = %d, want 0 after skipped record", stats.GetPackets())
	}
	assigned := batch.GetRecords()[0]
	assigned.GetWireFrame().Sequence = 2
	if err := sess.commitCaptureRecord("node-a", "stream-a", assigned, true); err != nil {
		t.Fatalf("commit assigned sequence 2: %v", err)
	}
	if stats := sess.snapshotStats(); stats.GetPackets() != 1 {
		t.Fatalf("packets = %d, want 1", stats.GetPackets())
	}
}

func TestRemainingActiveDeadline(t *testing.T) {
	if got := remainingActiveDeadline(0, time.Now()); got != 0 {
		t.Fatalf("zero duration = %v, want 0", got)
	}
	got := remainingActiveDeadline(10*time.Second, time.Now().Add(-3*time.Second))
	if got < 6*time.Second || got > 8*time.Second {
		t.Fatalf("remaining = %v, want ~7s", got)
	}
	if got := remainingActiveDeadline(time.Second, time.Now().Add(-2*time.Second)); got != 0 {
		t.Fatalf("expired duration = %v, want 0", got)
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

func TestClaimCaptureStreamRejectsConcurrentStream(t *testing.T) {
	sess, _ := testCaptureSession()
	if err := sess.claimCaptureStream("node-a", "agent-a", "stream-a"); err != nil {
		t.Fatalf("claimCaptureStream: %v", err)
	}
	if err := sess.claimCaptureStream("node-a", "agent-a", "stream-a"); err == nil {
		t.Fatal("expected concurrent capture stream to be rejected")
	}
	sess.releaseCaptureStream("node-a", "stream-a")
	if err := sess.claimCaptureStream("node-a", "agent-a", "stream-a"); err != nil {
		t.Fatalf("claim after release: %v", err)
	}
}

func TestSequenceAdvancesOnlyAfterRecordCommit(t *testing.T) {
	sess, batch := testCaptureSession()
	sess.setState(snifferv1.SessionState_SESSION_STATE_RUNNING, "")
	if err := sess.validateCaptureBatch(batch); err != nil {
		t.Fatalf("first validation: %v", err)
	}
	if err := sess.validateCaptureBatch(batch); err != nil {
		t.Fatalf("validation advanced sequence before publish: %v", err)
	}
	if err := sess.commitCaptureRecord("node-a", "stream-a", batch.GetRecords()[0], true); err != nil {
		t.Fatalf("commitCaptureRecord: %v", err)
	}
	if err := sess.validateCaptureBatch(batch); err == nil {
		t.Fatal("expected committed sequence to reject replay")
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
