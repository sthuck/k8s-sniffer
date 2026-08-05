// Package netns resolves a Kubernetes pod to a host network namespace path.
package netns

import (
	"context"
	"fmt"
	"strconv"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
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

// NewCRIResolver dials endpoint (unix:///path or host:port).
func NewCRIResolver(_ context.Context, endpoint string) (*CRIResolver, error) {
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial cri %q: %w", endpoint, err)
	}
	return &CRIResolver{
		conn:    conn,
		runtime: runtimeapi.NewRuntimeServiceClient(conn),
	}, nil
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

	containerID, err := r.findWorkloadContainer(ctx, sandboxID)
	if err != nil {
		return "", err
	}

	pid, err := r.containerPID(ctx, containerID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("/proc/%d/ns/net", pid), nil
}

func (r *CRIResolver) findSandbox(ctx context.Context, pod *snifferv1.PodRef) (string, error) {
	resp, err := r.runtime.ListPodSandbox(ctx, &runtimeapi.ListPodSandboxRequest{
		Filter: &runtimeapi.PodSandboxFilter{
			LabelSelector: map[string]string{
				"io.kubernetes.pod.name":      pod.GetName(),
				"io.kubernetes.pod.namespace": pod.GetNamespace(),
			},
			State: &runtimeapi.PodSandboxStateValue{
				State: runtimeapi.PodSandboxState_SANDBOX_READY,
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("list pod sandbox: %w", err)
	}
	for _, sb := range resp.GetItems() {
		if pod.GetUid() != "" && sb.GetMetadata().GetUid() != pod.GetUid() {
			continue
		}
		return sb.GetId(), nil
	}
	return "", fmt.Errorf("no running sandbox for pod %s/%s", pod.GetNamespace(), pod.GetName())
}

func (r *CRIResolver) findWorkloadContainer(ctx context.Context, sandboxID string) (string, error) {
	resp, err := r.runtime.ListContainers(ctx, &runtimeapi.ListContainersRequest{
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
	for _, c := range resp.GetContainers() {
		// Skip the infra/pause container when a named workload container exists.
		if c.GetMetadata().GetName() == "POD" {
			continue
		}
		return c.GetId(), nil
	}
	// Single-container pods may only expose the sandbox container.
	for _, c := range resp.GetContainers() {
		return c.GetId(), nil
	}
	return "", fmt.Errorf("no running container in sandbox %s", sandboxID)
}

func (r *CRIResolver) containerPID(ctx context.Context, containerID string) (int, error) {
	resp, err := r.runtime.ContainerStatus(ctx, &runtimeapi.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true,
	})
	if err != nil {
		return 0, fmt.Errorf("container status: %w", err)
	}
	if pidStr, ok := resp.GetInfo()["pid"]; ok && pidStr != "" {
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			return 0, fmt.Errorf("parse container pid %q: %w", pidStr, err)
		}
		if pid > 0 {
			return pid, nil
		}
	}
	return 0, fmt.Errorf("container %s: pid not available from CRI", containerID)
}
