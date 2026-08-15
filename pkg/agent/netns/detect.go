package netns

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"

	"github.com/sthuck/k8s-sniffer/pkg/capture"
)

const k8sSandboxScoreBase = 1000

type criProbeResult struct {
	HostPath string
	Score    int
}

// DetectCRIResolver probes the preferred host path and well-known CRI sockets
// under the /run bind mount. It prefers a CRI that can list Kubernetes
// sandboxes so a leftover /run/containerd/containerd.sock on k3s is skipped.
func DetectCRIResolver(ctx context.Context, preferred string) (*CRIResolver, error) {
	candidates := capture.CRISocketCandidates(preferred)
	var best *CRIResolver
	var bestResult criProbeResult
	for _, hostPath := range candidates {
		mountPath := capture.HostCRIMountPath(hostPath)
		if !isCRISocket(mountPath) {
			netnsLog.Debug("cri candidate missing",
				slog.String("path", hostPath),
				slog.String("mount", mountPath),
			)
			continue
		}
		resolver, err := NewCRIResolver(ctx, "unix://"+mountPath)
		if err != nil {
			netnsLog.Debug("cri candidate rejected",
				slog.String("path", hostPath),
				slog.String("err", err.Error()),
			)
			continue
		}
		n := resolver.k8sReadySandboxCount(ctx)
		score := 1
		if n > 0 {
			score = k8sSandboxScoreBase + n
		}
		netnsLog.Debug("probed cri socket",
			slog.String("path", hostPath),
			slog.Int("k8s_sandboxes", n),
			slog.Int("score", score),
		)
		if best == nil || score > bestResult.Score {
			if best != nil {
				_ = best.Close()
			}
			resolver.hostPath = hostPath
			best = resolver
			bestResult = criProbeResult{HostPath: hostPath, Score: score}
		} else {
			_ = resolver.Close()
		}
		if hostPath == preferred && score >= k8sSandboxScoreBase {
			break
		}
	}
	if best == nil {
		return nil, fmt.Errorf("no usable CRI socket (tried %s)", strings.Join(candidates, ", "))
	}
	netnsLog.Info("cri socket selected",
		slog.String("socket", bestResult.HostPath),
		slog.Int("score", bestResult.Score),
	)
	return best, nil
}

func isCRISocket(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeSocket != 0
}

func (r *CRIResolver) k8sReadySandboxCount(ctx context.Context) int {
	rpcCtx, cancel := r.withRPCTimeout(ctx)
	defer cancel()
	resp, err := r.runtime.ListPodSandbox(rpcCtx, &runtimeapi.ListPodSandboxRequest{
		Filter: &runtimeapi.PodSandboxFilter{
			State: &runtimeapi.PodSandboxStateValue{
				State: runtimeapi.PodSandboxState_SANDBOX_READY,
			},
		},
	})
	if err != nil {
		return -1
	}
	return countK8sSandboxes(resp.GetItems())
}

func countK8sSandboxes(items []*runtimeapi.PodSandbox) int {
	n := 0
	for _, sb := range items {
		if sb.GetLabels()["io.kubernetes.pod.name"] != "" {
			n++
			continue
		}
		meta := sb.GetMetadata()
		if meta.GetName() != "" && meta.GetNamespace() != "" {
			n++
		}
	}
	return n
}

func pickCRIProbe(results []criProbeResult) criProbeResult {
	var best criProbeResult
	for _, r := range results {
		if r.Score <= 0 {
			continue
		}
		if best.Score == 0 || r.Score > best.Score {
			best = r
		}
	}
	return best
}
