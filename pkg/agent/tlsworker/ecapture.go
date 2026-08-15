package tlsworker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
	"github.com/sthuck/k8s-sniffer/pkg/log"
)

var tlsLog = log.WithComponent("agent")

const (
	// DefaultBinary is the ecapture executable name in the agent image.
	DefaultBinary = "ecapture"
)

// ECapture shells out to the vendored ecapture binary (T3.2 / T3.3).
type ECapture struct {
	Binary string
	// LookLibSSL finds libssl.so in the target container. Tests override this.
	LookLibSSL func(pid int) (string, error)
	// CgroupPath returns a cgroup v2 path for a pid. Tests override this.
	CgroupPath func(pid int) string
}

func (e ECapture) binary() string {
	if e.Binary != "" {
		return e.Binary
	}
	return DefaultBinary
}

// Attach starts ecapture for target, or reports a TLS status without failing
// the wire path. Keylog mode never launches eBPF.
func (e ECapture) Attach(ctx context.Context, target Target) (<-chan *snifferv1.TlsPlaintextEvent, <-chan Status, error) {
	events := make(chan *snifferv1.TlsPlaintextEvent, 64)
	statuses := make(chan Status, 1)

	switch target.Mode {
	case snifferv1.TlsMode_TLS_MODE_KEYLOG:
		statuses <- Status{Status: snifferv1.TlsStatus_TLS_STATUS_FALLBACK, Detail: "keylog mode: provide SSLKEYLOGFILE / --keylog-file for Wireshark"}
		close(events)
		close(statuses)
		return events, statuses, nil
	case snifferv1.TlsMode_TLS_MODE_EBPF, snifferv1.TlsMode_TLS_MODE_AUTO:
	default:
		close(events)
		close(statuses)
		return events, statuses, nil
	}

	if target.PID <= 0 {
		e.fail(target, statuses, events, snifferv1.TlsStatus_TLS_STATUS_UNSUPPORTED, "container pid unknown")
		return events, statuses, nil
	}

	bin := e.binary()
	if _, err := exec.LookPath(bin); err != nil {
		status := snifferv1.TlsStatus_TLS_STATUS_UNSUPPORTED
		if target.Mode == snifferv1.TlsMode_TLS_MODE_AUTO {
			status = snifferv1.TlsStatus_TLS_STATUS_FALLBACK
		}
		e.fail(target, statuses, events, status, "ecapture binary not found")
		return events, statuses, nil
	}

	look := e.LookLibSSL
	if look == nil {
		look = findLibSSLInContainer
	}
	libssl, err := look(target.PID)
	if err != nil {
		tlsLog.Info("tls attach skipped: no openssl library",
			slog.String("session_id", target.SessionID),
			slog.String("pod", podName(target)),
			slog.Int("pid", target.PID),
			slog.String("err", err.Error()),
		)
		e.fail(target, statuses, events, snifferv1.TlsStatus_TLS_STATUS_UNSUPPORTED, err.Error())
		return events, statuses, nil
	}

	// Do not pass --pid: nginx and similar servers terminate TLS in worker
	// processes, not the container init PID. Uprobes on this container's
	// libssl inode cover every process that maps it; --cgroup_path further
	// scopes events to the pod when the host cgroup is visible.
	args := []string{"tls", "-m", "text", "--libssl", libssl}
	cgroupFn := e.CgroupPath
	if cgroupFn == nil {
		cgroupFn = cgroupPath
	}
	if cg := cgroupFn(target.PID); cg != "" {
		args = append(args, "--cgroup_path", cg)
	}

	cmd := exec.Command(bin, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		e.fail(target, statuses, events, classifyExecError(target.Mode, err), err.Error())
		return events, statuses, nil
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		e.fail(target, statuses, events, classifyExecError(target.Mode, err), err.Error())
		return events, statuses, nil
	}
	if err := cmd.Start(); err != nil {
		e.fail(target, statuses, events, classifyExecError(target.Mode, err), err.Error())
		return events, statuses, nil
	}
	tlsLog.Info("tls worker started",
		slog.String("session_id", target.SessionID),
		slog.String("pod", podName(target)),
		slog.Int("pid", target.PID),
		slog.String("libssl", libssl),
	)
	tlsLog.Debug("tls worker command",
		slog.String("session_id", target.SessionID),
		slog.String("bin", bin),
		slog.String("args", strings.Join(args, " ")),
	)

	parsed := make(chan parsedEvent, 64)
	stderrBuf := &limitedBuffer{max: 4096}
	parseCtx, parseCancel := context.WithCancel(ctx)
	var parseWG sync.WaitGroup
	parseWG.Add(2)
	go func() {
		defer parseWG.Done()
		parseStream(parseCtx, stdout, parsed)
	}()
	go func() {
		defer parseWG.Done()
		parseStream(parseCtx, io.TeeReader(stderr, stderrBuf), parsed)
	}()
	go func() {
		parseWG.Wait()
		close(parsed)
	}()

	go func() {
		defer close(events)
		defer close(statuses)
		defer parseCancel()
		defer func() {
			if cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
			}
		}()

		waitDone := make(chan error, 1)
		go func() { waitDone <- cmd.Wait() }()

		activeSent := false
		var seq uint64

		stopProcess := func() {
			parseCancel()
			if cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
			}
			select {
			case <-waitDone:
			case <-time.After(3 * time.Second):
				if cmd.Process != nil {
					_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				}
				<-waitDone
			}
			if parsed != nil {
				for range parsed {
				}
			}
		}

		for {
			select {
			case <-ctx.Done():
				stopProcess()
				return
			case err := <-waitDone:
				parseCancel()
				if parsed != nil {
					for range parsed {
					}
				}
				if ctx.Err() != nil {
					return
				}
				detail := "ecapture exited"
				if err != nil {
					detail = err.Error()
				}
				if extra := strings.TrimSpace(stderrBuf.String()); extra != "" {
					detail = extra
					if err != nil {
						err = fmt.Errorf("%w: %s", err, extra)
					} else {
						err = fmt.Errorf("%s", extra)
					}
				}
				st := classifyExecError(target.Mode, err)
				tlsLog.Info("tls worker exited",
					slog.String("session_id", target.SessionID),
					slog.String("pod", podName(target)),
					slog.String("detail", detail),
				)
				sendLatestStatus(statuses, Status{Status: st, Detail: detail})
				return
			case ev, ok := <-parsed:
				if !ok {
					parsed = nil
					continue
				}
				if !activeSent {
					activeSent = true
					sendLatestStatus(statuses, Status{Status: snifferv1.TlsStatus_TLS_STATUS_ACTIVE, Detail: "ecapture attached"})
				}
				seq++
				if ev.PID == 0 {
					ev.PID = uint32(target.PID)
				}
				select {
				case events <- toProto(target.Pod, ev, seq):
				case <-ctx.Done():
					stopProcess()
					return
				}
			}
		}
	}()

	return events, statuses, nil
}

func (e ECapture) fail(_ Target, statuses chan Status, events chan *snifferv1.TlsPlaintextEvent, st snifferv1.TlsStatus, detail string) {
	statuses <- Status{Status: st, Detail: detail}
	close(events)
	close(statuses)
}

func classifyExecError(mode snifferv1.TlsMode, err error) snifferv1.TlsStatus {
	if err == nil {
		return snifferv1.TlsStatus_TLS_STATUS_UNSUPPORTED
	}
	msg := strings.ToLower(err.Error())
	denied := strings.Contains(msg, "permission") ||
		strings.Contains(msg, "operation not permitted") ||
		strings.Contains(msg, "eperm") ||
		strings.Contains(msg, "btf") ||
		strings.Contains(msg, "capability")
	if denied {
		if mode == snifferv1.TlsMode_TLS_MODE_AUTO {
			return snifferv1.TlsStatus_TLS_STATUS_FALLBACK
		}
		return snifferv1.TlsStatus_TLS_STATUS_DENIED
	}
	if mode == snifferv1.TlsMode_TLS_MODE_AUTO {
		return snifferv1.TlsStatus_TLS_STATUS_FALLBACK
	}
	return snifferv1.TlsStatus_TLS_STATUS_UNSUPPORTED
}

func podName(t Target) string {
	if t.Pod == nil {
		return ""
	}
	return t.Pod.GetName()
}

// sendLatestStatus keeps the newest status when the consumer is busy.
func sendLatestStatus(ch chan Status, st Status) {
	select {
	case ch <- st:
		return
	default:
	}
	select {
	case <-ch:
	default:
	}
	select {
	case ch <- st:
	default:
	}
}

// limitedBuffer keeps the last max bytes of writes for exit diagnostics.
type limitedBuffer struct {
	mu  sync.Mutex
	max int
	buf bytes.Buffer
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Write(p)
	if b.max > 0 && b.buf.Len() > b.max {
		overflow := b.buf.Len() - b.max
		b.buf.Next(overflow)
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
