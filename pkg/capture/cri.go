package capture

import "strings"

// CRISocketForRuntimeVersion picks the node CRI socket for a kubelet
// ContainerRuntimeVersion (for example "containerd://1.7.22-k3s1").
//
// An explicit non-default configured path is always kept. The default
// containerd path is replaced with DefaultK3sCRISocketPath when the runtime
// version is k3s or RKE2, which embed containerd under /run/k3s.
func CRISocketForRuntimeVersion(runtimeVersion, configured string) string {
	if configured != "" && configured != DefaultCRISocketPath {
		return configured
	}
	if k3sFamilyRuntime(runtimeVersion) {
		return DefaultK3sCRISocketPath
	}
	if configured == "" {
		return DefaultCRISocketPath
	}
	return configured
}

func k3sFamilyRuntime(runtimeVersion string) bool {
	v := strings.ToLower(runtimeVersion)
	return strings.Contains(v, "-k3s") || strings.Contains(v, "-rke2")
}
