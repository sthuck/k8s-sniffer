package capture

import (
	"fmt"
	"io"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"google.golang.org/protobuf/types/known/timestamppb"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
)

// PCAPReader turns a tcpdump stdout stream into PacketFrames.
type PCAPReader struct {
	reader   *pcapgo.Reader
	linkType snifferv1.LinkType
	seq      uint64
}

// NewPCAPReader parses the pcap global header from r.
func NewPCAPReader(r io.Reader) (*PCAPReader, error) {
	reader, err := pcapgo.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("pcap header: %w", err)
	}
	return &PCAPReader{
		reader:   reader,
		linkType: linkTypeFromDLT(int32(reader.LinkType())),
	}, nil
}

// ReadFrame returns the next wire frame or io.EOF when the stream ends.
func (p *PCAPReader) ReadFrame(pod *snifferv1.PodRef) (*snifferv1.PacketFrame, error) {
	data, ci, err := p.reader.ReadPacketData()
	if err != nil {
		return nil, err
	}
	p.seq++
	return &snifferv1.PacketFrame{
		Pod:            pod,
		Source:         snifferv1.PacketSource_PACKET_SOURCE_WIRE,
		Timestamp:      timestamppb.New(ci.Timestamp),
		LinkType:       p.linkType,
		OriginalLength: uint32(ci.Length),
		Payload:        data,
		Sequence:       p.seq,
	}, nil
}

func linkTypeFromDLT(dlt int32) snifferv1.LinkType {
	switch layers.LinkType(dlt) {
	case layers.LinkTypeEthernet:
		return snifferv1.LinkType_LINK_TYPE_ETHERNET
	case layers.LinkTypeRaw:
		return snifferv1.LinkType_LINK_TYPE_RAW
	case layers.LinkTypeLinuxSLL:
		return snifferv1.LinkType_LINK_TYPE_LINUX_SLL
	case layers.LinkTypeLinuxSLL2:
		return snifferv1.LinkType_LINK_TYPE_LINUX_SLL2
	default:
		return snifferv1.LinkType_LINK_TYPE_UNSPECIFIED
	}
}
