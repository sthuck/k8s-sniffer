package sink_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket/pcapgo"
	"google.golang.org/protobuf/types/known/timestamppb"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	"github.com/sthuck/k8s-sniffer/pkg/sink"
)

func TestPCAPWriterRoundTripClassic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.pcap")

	w, err := sink.OpenPCAP(path)
	if err != nil {
		t.Fatalf("OpenPCAP: %v", err)
	}
	writeTestFrames(t, w)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	assertPacketCount(t, data, 2)
}

func TestPCAPWriterRoundTripPCAPng(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.pcapng")

	w, err := sink.OpenPCAP(path)
	if err != nil {
		t.Fatalf("OpenPCAP: %v", err)
	}
	writeTestFrames(t, w)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) < 32 {
		t.Fatalf("pcapng output too short: %d bytes", len(data))
	}
}

func writeTestFrames(t *testing.T, w *sink.PCAPWriter) {
	t.Helper()
	ts := time.Unix(1_700_000_000, 123)
	frames := []*snifferv1.PacketFrame{
		{
			Pod:            &snifferv1.PodRef{Namespace: "prod", Name: "api"},
			Source:         snifferv1.PacketSource_PACKET_SOURCE_WIRE,
			Timestamp:      timestamppb.New(ts),
			LinkType:       snifferv1.LinkType_LINK_TYPE_ETHERNET,
			OriginalLength: 14,
			Payload:        []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x01, 0x08, 0x00},
		},
		{
			Pod:            &snifferv1.PodRef{Namespace: "prod", Name: "api"},
			Source:         snifferv1.PacketSource_PACKET_SOURCE_WIRE,
			Timestamp:      timestamppb.New(ts.Add(time.Millisecond)),
			LinkType:       snifferv1.LinkType_LINK_TYPE_ETHERNET,
			OriginalLength: 10,
			Payload:        []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a},
		},
	}
	for _, frame := range frames {
		if err := w.WriteFrame(frame); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}
	}
	if got := w.PacketCount(); got != 2 {
		t.Fatalf("PacketCount = %d, want 2", got)
	}
}

func assertPacketCount(t *testing.T, data []byte, want int) {
	t.Helper()
	reader, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	count := 0
	for {
		if _, _, err := reader.ReadPacketData(); err != nil {
			break
		}
		count++
	}
	if count != want {
		t.Fatalf("read back %d packets, want %d", count, want)
	}
}
