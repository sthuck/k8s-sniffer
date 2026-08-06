package capture

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
)

func TestPCAPReaderReadsFrames(t *testing.T) {
	var buf bytes.Buffer
	w := pcapgo.NewWriter(&buf)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("WriteFileHeader: %v", err)
	}
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Unix(1, 0),
		CaptureLength: len(payload),
		Length:        len(payload),
	}
	if err := w.WritePacket(ci, payload); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	reader, err := NewPCAPReader(&buf)
	if err != nil {
		t.Fatalf("NewPCAPReader: %v", err)
	}
	pod := &snifferv1.PodRef{Namespace: "prod", Name: "api"}
	frame, err := reader.ReadFrame(pod)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Equal(frame.GetPayload(), payload) {
		t.Fatalf("payload = %v", frame.GetPayload())
	}
	if frame.GetPod().GetName() != "api" {
		t.Fatalf("pod = %q", frame.GetPod().GetName())
	}
	if frame.GetLinkType() != snifferv1.LinkType_LINK_TYPE_ETHERNET {
		t.Fatalf("link type = %s", frame.GetLinkType())
	}

	_, err = reader.ReadFrame(pod)
	if err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}
