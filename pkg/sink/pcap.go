package sink

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	"github.com/sthuck/k8s-sniffer/pkg/capture"
)

// PCAPWriter serializes wire PacketFrames to PCAP or PCAPng.
type PCAPWriter struct {
	path   string
	file   *os.File
	writer io.Writer
	ng     *pcapgo.NgWriter
	classic *pcapgo.Writer
	mu     sync.Mutex
	count  uint64
}

// OpenPCAP creates a PCAP writer for path (or stdout when path is "-").
func OpenPCAP(path string) (*PCAPWriter, error) {
	if path == "" {
		return nil, fmt.Errorf("pcap path: required")
	}
	w := &PCAPWriter{path: path}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *PCAPWriter) open() error {
	var out io.Writer
	if w.path == capture.StdoutSink {
		out = os.Stdout
	} else {
		if dir := filepath.Dir(w.path); dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("create output directory: %w", err)
			}
		}
		f, err := os.Create(w.path)
		if err != nil {
			return fmt.Errorf("open pcap output: %w", err)
		}
		w.file = f
		out = f
	}
	w.writer = out
	return nil
}

func (w *PCAPWriter) usePCAPng() bool {
	if w.path == capture.StdoutSink {
		return false
	}
	ext := strings.ToLower(filepath.Ext(w.path))
	return ext == ".pcapng" || ext == ".ngpcap"
}

// WriteFrame appends one wire frame. TLS events are ignored.
func (w *PCAPWriter) WriteFrame(frame *snifferv1.PacketFrame) error {
	if frame == nil {
		return fmt.Errorf("packet frame: required")
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	ci := gopacket.CaptureInfo{
		Timestamp:      frame.GetTimestamp().AsTime(),
		CaptureLength:  len(frame.GetPayload()),
		Length:         int(frame.GetOriginalLength()),
		InterfaceIndex: 0,
	}
	if ci.Length == 0 {
		ci.Length = ci.CaptureLength
	}
	if ci.CaptureLength == 0 && len(frame.GetPayload()) == 0 {
		return nil
	}

	linkType := linkTypeToDLT(frame.GetLinkType())
	if w.ng == nil && w.classic == nil {
		if err := w.initWriter(linkType); err != nil {
			return err
		}
	}

	var err error
	if w.ng != nil {
		err = w.ng.WritePacket(ci, frame.GetPayload())
	} else {
		err = w.classic.WritePacket(ci, frame.GetPayload())
	}
	if err != nil {
		return fmt.Errorf("write pcap packet: %w", err)
	}
	w.count++
	return nil
}

// WriteRecord writes wire frames from a CaptureRecord envelope.
func (w *PCAPWriter) WriteRecord(rec *snifferv1.CaptureRecord) error {
	if rec == nil {
		return nil
	}
	if frame := rec.GetWireFrame(); frame != nil {
		return w.WriteFrame(frame)
	}
	return nil
}

func (w *PCAPWriter) initWriter(linkType layers.LinkType) error {
	if w.usePCAPng() {
		ng, err := pcapgo.NewNgWriter(w.writer, linkType)
		if err != nil {
			return fmt.Errorf("pcapng writer: %w", err)
		}
		w.ng = ng
		return nil
	}
	w.classic = pcapgo.NewWriter(w.writer)
	if err := w.classic.WriteFileHeader(65535, linkType); err != nil {
		return fmt.Errorf("pcap header: %w", err)
	}
	return nil
}

// PacketCount returns the number of frames written.
func (w *PCAPWriter) PacketCount() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.count
}

// Close flushes and closes the underlying file (stdout is left open).
func (w *PCAPWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.ng != nil {
		if err := w.ng.Flush(); err != nil {
			return err
		}
	}
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

func linkTypeToDLT(lt snifferv1.LinkType) layers.LinkType {
	switch lt {
	case snifferv1.LinkType_LINK_TYPE_ETHERNET:
		return layers.LinkTypeEthernet
	case snifferv1.LinkType_LINK_TYPE_RAW:
		return layers.LinkTypeRaw
	case snifferv1.LinkType_LINK_TYPE_LINUX_SLL:
		return layers.LinkTypeLinuxSLL
	case snifferv1.LinkType_LINK_TYPE_LINUX_SLL2:
		return layers.LinkTypeLinuxSLL2
	default:
		return layers.LinkTypeLinuxSLL
	}
}
