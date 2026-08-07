// Package netns resolves a Kubernetes pod to a host network namespace path.
package netns

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
)

const (
	criDialTimeout = 5 * time.Second
	criRPCTimeout  = 5 * time.Second
)

// Resolver maps pod identity to a netns path on the node (e.g. /proc/<pid>/ns/net).
type Resolver interface {
	Resolve(ctx context.Context, pod *snifferv1.PodRef) (string, error)
}

// CRIResolver uses the node CRI socket to find a running container PID.
type CRIResolver struct {
	conn    *grpc.ClientConn
	runtime runtimeapi.RuntimeServiceClient
}

// NewCRIResolver dials endpoint (unix:///path or host:port) and verifies the
// RuntimeService responds. Uses an explicit unix dialer + passthrough target so
// gRPC does not DNS-resolve socket paths (same pattern as k8s cri-client).
func NewCRIResolver(ctx context.Context, endpoint string) (*CRIResolver, error) {
	network, addr, err := parseCRIEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithAuthority("localhost"),
	}
	target := addr
	if network == "unix" {
		target = "passthrough:///" + addr
		dialOpts = append(dialOpts, grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", addr)
		}))
	}

	conn, err := grpc.NewClient(target, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("dial cri %q: %w", endpoint, err)
	}
	runtime := runtimeapi.NewRuntimeServiceClient(conn)
	if err := pingCRI(ctx, runtime); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("cri %q: %w", endpoint, err)
	}
	return &CRIResolver{
		conn:    conn,
		runtime: runtime,
	}, nil
}

func pingCRI(ctx context.Context, runtime runtimeapi.RuntimeServiceClient) error {
	pingCtx, cancel := context.WithTimeout(ctx, criDialTimeout)
	defer cancel()
	_, err := runtime.Version(pingCtx, &runtimeapi.VersionRequest{Version: "0.1.0"})
	if err != nil {
		return fmt.Errorf("version check: %w", err)
	}
	return nil
}

func parseCRIEndpoint(endpoint string) (network, addr string, err error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", "", fmt.Errorf("cri endpoint: required")
	}
	if !strings.Contains(endpoint, "://") {
		if strings.HasPrefix(endpoint, "/") {
			return "unix", endpoint, nil
		}
		return "tcp", endpoint, nil
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", "", fmt.Errorf("cri endpoint: %w", err)
	}
	switch u.Scheme {
	case "unix":
		path := u.Path
		if path == "" {
			path = u.Opaque
		}
		if path == "" {
			return "", "", fmt.Errorf("cri endpoint: unix path required")
		}
		return "unix", path, nil
	case "tcp":
		if u.Host == "" {
			return "", "", fmt.Errorf("cri endpoint: tcp host required")
		}
		return "tcp", u.Host, nil
	default:
		return "", "", fmt.Errorf("cri endpoint: unsupported scheme %q", u.Scheme)
	}
}

// Close releases the CRI connection.
func (r *CRIResolver) Close() error {
	if r.conn == nil {
		return nil
	}
	return r.conn.Close()
}

// Resolve returns the netns path for pod's primary workload container.
func (r *CRIResolver) Resolve(ctx context.Context, pod *snifferv1.PodRef) (string, error) {
	if pod == nil {
		return "", fmt.Errorf("pod: required")
	}
	if pod.GetNamespace() == "" || pod.GetName() == "" {
		return "", fmt.Errorf("pod namespace and name: required")
	}

	sandboxID, err := r.findSandbox(ctx, pod)
	if err != nil {
		return "", err
	}

	containerID, err := r.findWorkloadContainer(ctx, sandboxID, pod)
	if err != nil {
		return "", err
	}

	pid, err := r.containerPID(ctx, containerID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("/proc/%d/ns/net", pid), nil
}

func (r *CRIResolver) withRPCTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, criRPCTimeout)
}

func (r *CRIResolver) findSandbox(ctx context.Context, pod *snifferv1.PodRef) (string, error) {
	labels := map[string]string{
		"io.kubernetes.pod.name":      pod.GetName(),
		"io.kubernetes.pod.namespace": pod.GetNamespace(),
	}
	if pod.GetUid() != "" {
		labels["io.kubernetes.pod.uid"] = pod.GetUid()
	}
	rpcCtx, cancel := r.withRPCTimeout(ctx)
	defer cancel()
	resp, err := r.runtime.ListPodSandbox(rpcCtx, &runtimeapi.ListPodSandboxRequest{
		Filter: &runtimeapi.PodSandboxFilter{
			LabelSelector: labels,
			State: &runtimeapi.PodSandboxStateValue{
				State: runtimeapi.PodSandboxState_SANDBOX_READY,
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("list pod sandbox: %w", err)
	}
	candidates := resp.GetItems()
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].GetCreatedAt() > candidates[j].GetCreatedAt()
	})
	for _, sb := range candidates {
		if pod.GetUid() != "" && sb.GetMetadata().GetUid() != pod.GetUid() {
			continue
		}
		return sb.GetId(), nil
	}
	return "", fmt.Errorf("no running sandbox for pod %s/%s", pod.GetNamespace(), pod.GetName())
}

func (r *CRIResolver) findWorkloadContainer(ctx context.Context, sandboxID string, pod *snifferv1.PodRef) (string, error) {
	rpcCtx, cancel := r.withRPCTimeout(ctx)
	defer cancel()
	resp, err := r.runtime.ListContainers(rpcCtx, &runtimeapi.ListContainersRequest{
		Filter: &runtimeapi.ContainerFilter{
			PodSandboxId: sandboxID,
			State: &runtimeapi.ContainerStateValue{
				State: runtimeapi.ContainerState_CONTAINER_RUNNING,
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("list containers: %w", err)
	}
	containers := resp.GetContainers()
	if containerID := pod.GetContainerId(); containerID != "" {
		containerID = trimRuntimePrefix(containerID)
		for _, c := range containers {
			if c.GetId() == containerID {
				return c.GetId(), nil
			}
		}
		return "", fmt.Errorf("container %q not running in sandbox %s", containerID, sandboxID)
	}

	candidates := workloadContainers(containers)
	if len(candidates) == 0 {
		return "", fmt.Errorf("no running container in sandbox %s", sandboxID)
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].GetMetadata().GetName() < candidates[j].GetMetadata().GetName()
	})
	return candidates[0].GetId(), nil
}

func trimRuntimePrefix(containerID string) string {
	if _, id, ok := strings.Cut(containerID, "://"); ok {
		return id
	}
	return containerID
}

func workloadContainers(containers []*runtimeapi.Container) []*runtimeapi.Container {
	var out []*runtimeapi.Container
	for _, c := range containers {
		if c.GetMetadata().GetName() == "POD" {
			continue
		}
		out = append(out, c)
	}
	if len(out) > 0 {
		return out
	}
	return containers
}

func (r *CRIResolver) containerPID(ctx context.Context, containerID string) (int, error) {
	rpcCtx, cancel := r.withRPCTimeout(ctx)
	defer cancel()
	resp, err := r.runtime.ContainerStatus(rpcCtx, &runtimeapi.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true,
	})
	if err != nil {
		return 0, fmt.Errorf("container status: %w", err)
	}
	pid, err := parseContainerPID(resp.GetInfo())
	if err != nil {
		return 0, fmt.Errorf("container %s: %w", containerID, err)
	}
	return pid, nil
}

// parseContainerPID extracts the init PID from verbose ContainerStatus info.
// containerd nests pid inside Info["info"] JSON; CRI-O may expose Info["pid"].
func parseContainerPID(info map[string]string) (int, error) {
	if pidStr, ok := info["pid"]; ok && pidStr != "" {
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			return 0, fmt.Errorf("parse container pid %q: %w", pidStr, err)
		}
		if pid > 0 {
			return pid, nil
		}
	}
	if raw, ok := info["info"]; ok && raw != "" {
		var meta struct {
			PID int `json:"pid"`
		}
		if err := json.Unmarshal([]byte(raw), &meta); err != nil {
			return 0, fmt.Errorf("parse container info json: %w", err)
		}
		if meta.PID > 0 {
			return meta.PID, nil
		}
	}
	return 0, fmt.Errorf("pid not available from CRI")
}
