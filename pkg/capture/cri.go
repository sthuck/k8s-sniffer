package capture

import "strings"

const (
	// DefaultCRIOSocketPath is the usual CRI-O socket.
	DefaultCRIOSocketPath = "/run/crio/crio.sock"
	// DefaultCRIDockerdSocketPath is cri-dockerd (kubelet + Docker).
	DefaultCRIDockerdSocketPath = "/run/cri-dockerd.sock"
	// HostRunHostPath is the node directory that contains well-known CRI sockets.
	HostRunHostPath = "/run"
	// HostRunMountPath is where agents mount HostRunHostPath so they can probe
	// multiple sockets without a per-path hostPath.
	HostRunMountPath = "/host/run"
)

// WellKnownCRISocketPaths are host paths the agent probes after the configured
// hint. Order is a weak preference when scores tie.
func WellKnownCRISocketPaths() []string {
	return []string{
		DefaultK3sCRISocketPath,
		DefaultCRISocketPath,
		DefaultCRIOSocketPath,
		DefaultCRIDockerdSocketPath,
	}
}

// CRISocketCandidates returns unique host paths to probe, preferred first.
func CRISocketCandidates(preferred string) []string {
	seen := make(map[string]bool, 8)
	out := make([]string, 0, 8)
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	add(preferred)
	for _, p := range WellKnownCRISocketPaths() {
		add(p)
	}
	return out
}

// HostCRIMountPath maps a node CRI path to the path inside the agent after
// /run (and /var/run) are bind-mounted at HostRunMountPath. Paths outside
// /run are unchanged and need their own hostPath volume.
func HostCRIMountPath(hostPath string) string {
	for _, prefix := range []string{"/run/", "/var/run/"} {
		if strings.HasPrefix(hostPath, prefix) {
			return HostRunMountPath + "/" + strings.TrimPrefix(hostPath, prefix)
		}
	}
	switch hostPath {
	case "/run", "/var/run":
		return HostRunMountPath
	default:
		return hostPath
	}
}

// NeedsExtraCRISocketMount reports whether hostPath is not visible via the
// /run bind mount and must be mounted on its own.
func NeedsExtraCRISocketMount(hostPath string) bool {
	return hostPath != "" && HostCRIMountPath(hostPath) == hostPath
}

// CRISocketForRuntimeVersion picks the node CRI socket for a kubelet
// ContainerRuntimeVersion (for example "containerd://1.7.22-k3s1").
//
// An explicit non-default configured path is always kept. The default
// containerd path is replaced when the runtime version identifies k3s, RKE2,
// CRI-O, or cri-dockerd.
func CRISocketForRuntimeVersion(runtimeVersion, configured string) string {
	if configured != "" && configured != DefaultCRISocketPath {
		return configured
	}
	if socket := criSocketForRuntime(runtimeVersion); socket != "" {
		return socket
	}
	if configured == "" {
		return DefaultCRISocketPath
	}
	return configured
}

func criSocketForRuntime(runtimeVersion string) string {
	v := strings.ToLower(runtimeVersion)
	switch {
	case strings.Contains(v, "-k3s") || strings.Contains(v, "-rke2"):
		return DefaultK3sCRISocketPath
	case strings.HasPrefix(v, "cri-o://") || strings.Contains(v, "cri-o"):
		return DefaultCRIOSocketPath
	case strings.HasPrefix(v, "docker://"):
		return DefaultCRIDockerdSocketPath
	default:
		return ""
	}
}
