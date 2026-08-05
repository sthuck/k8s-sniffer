package netns

import (
	"context"
	"fmt"
	"sync"

	snifferv1 "github.com/sthuck/k8s-sniffer/api/sniffer/v1"
)

// MapResolver is an in-memory Resolver for tests.
type MapResolver struct {
	mu   sync.Mutex
	path map[string]string
}

func NewMapResolver() *MapResolver {
	return &MapResolver{path: make(map[string]string)}
}

func podKey(pod *snifferv1.PodRef) string {
	return pod.GetNamespace() + "/" + pod.GetName()
}

// Set records netnsPath for pod.
func (m *MapResolver) Set(pod *snifferv1.PodRef, netnsPath string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.path[podKey(pod)] = netnsPath
}

func (m *MapResolver) Resolve(_ context.Context, pod *snifferv1.PodRef) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	path, ok := m.path[podKey(pod)]
	if !ok {
		return "", fmt.Errorf("no netns for pod %s/%s", pod.GetNamespace(), pod.GetName())
	}
	return path, nil
}
