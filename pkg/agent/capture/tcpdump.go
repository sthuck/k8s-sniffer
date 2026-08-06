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
		args = append(args, bpf)
	}
	cmd := exec.CommandContext(ctx, t.nsenter(), args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("tcpdump stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("tcpdump stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start tcpdump: %w", err)
	}
	return &cmdReadCloser{cmd: cmd, r: stdout, stderr: stderr}, nil
}

type cmdReadCloser struct {
	cmd    *exec.Cmd
	r      io.ReadCloser
	stderr io.Reader
}

func (c *cmdReadCloser) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func (c *cmdReadCloser) Close() error {
	_ = c.r.Close()
	var stderrBuf bytes.Buffer
	if c.stderr != nil {
		_, _ = io.Copy(&stderrBuf, c.stderr)
	}
	err := c.cmd.Wait()
	if err != nil {
		if msg := strings.TrimSpace(stderrBuf.String()); msg != "" {
			return fmt.Errorf("tcpdump exit: %w: %s", err, msg)
		}
		return fmt.Errorf("tcpdump exit: %w", err)
	}
	return nil
}
