package capture

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
)

// Tcpdump runs tcpdump inside a target network namespace via nsenter.
type Tcpdump struct {
	NsenterPath string
	TcpdumpPath string
}

const maxStderrBytes = 64 << 10

func (t *Tcpdump) nsenter() string {
	if t.NsenterPath != "" {
		return t.NsenterPath
	}
	return "nsenter"
}

func (t *Tcpdump) tcpdump() string {
	if t.TcpdumpPath != "" {
		return t.TcpdumpPath
	}
	return "tcpdump"
}

// Start launches tcpdump writing pcap to stdout. netnsPath is a path such as
// /proc/<pid>/ns/net. Caller must wait on the returned ReadCloser's Close for
// the process to exit.
func (t *Tcpdump) Start(ctx context.Context, netnsPath string, snaplen uint32, bpf string, interfaces []string) (io.ReadCloser, error) {
	args, err := t.commandArgs(netnsPath, snaplen, bpf, interfaces)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, t.nsenter(), args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("tcpdump stdout: %w", err)
	}
	stderr := &cappedBuffer{remaining: maxStderrBytes}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start tcpdump: %w", err)
	}
	return &cmdReadCloser{cmd: cmd, r: stdout, stderr: stderr}, nil
}

func (t *Tcpdump) commandArgs(netnsPath string, snaplen uint32, bpf string, interfaces []string) ([]string, error) {
	if netnsPath == "" {
		return nil, fmt.Errorf("netns path: required")
	}
	if len(interfaces) > 1 {
		return nil, fmt.Errorf("multiple interfaces: only one supported in MVP (got %d)", len(interfaces))
	}
	iface := "any"
	if len(interfaces) > 0 && strings.TrimSpace(interfaces[0]) != "" {
		iface = interfaces[0]
	}
	bpf = strings.TrimSpace(bpf)
	if strings.HasPrefix(bpf, "-") {
		return nil, fmt.Errorf("bpf filter must not begin with '-'")
	}
	args := []string{
		"--net=" + netnsPath,
		t.tcpdump(),
		"-i", iface,
		"-U",
		"-w", "-",
		"-s", strconv.FormatUint(uint64(snaplen), 10),
		"-q",
	}
	if bpf != "" {
		args = append(args, "--", bpf)
	}
	return args, nil
}

type cmdReadCloser struct {
	cmd    *exec.Cmd
	r      io.ReadCloser
	stderr *cappedBuffer
}

func (c *cmdReadCloser) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func (c *cmdReadCloser) Close() error {
	_ = c.r.Close()
	err := c.cmd.Wait()
	if err != nil {
		if msg := strings.TrimSpace(c.stderr.String()); msg != "" {
			return fmt.Errorf("tcpdump exit: %w: %s", err, msg)
		}
		return fmt.Errorf("tcpdump exit: %w", err)
	}
	return nil
}

type cappedBuffer struct {
	buf       bytes.Buffer
	remaining int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	available := b.remaining
	if b.remaining > 0 {
		write := len(p)
		if write > b.remaining {
			write = b.remaining
		}
		_, _ = b.buf.Write(p[:write])
		b.remaining -= write
	}
	if len(p) > available {
		b.truncated = true
	}
	return n, nil
}

func (b *cappedBuffer) String() string {
	if b == nil {
		return ""
	}
	if b.truncated {
		return b.buf.String() + "\n[stderr truncated]"
	}
	return b.buf.String()
}
