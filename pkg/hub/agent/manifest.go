// Package agent builds Kubernetes objects for ephemeral sniffer agent pods.
package agent

import (
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/sthuck/k8s-sniffer/pkg/capture"
)

const (
	// LabelAppKey identifies sniffer agent pods for list/delete RBAC.
	LabelAppKey = "app"
	// LabelAppValue is the value for LabelAppKey.
	LabelAppValue = "k8s-sniffer-agent"
	// LabelSessionKey scopes agent pods to a capture session.
	LabelSessionKey = "sniffer.session"
	// LabelNodeKey records which node the agent is pinned to (one per session+node).
	LabelNodeKey = "sniffer.node"

	// GenerateNamePrefix is the pod name prefix before the random suffix.
	GenerateNamePrefix = "k8s-sniffer-"
	// AgentContainerName is the sole container in the agent pod.
	AgentContainerName = "agent"
	// CRISocketVolumeName is the hostPath volume mounting the node CRI socket.
	CRISocketVolumeName = "cri-sock"
)

// unprivilegedCapabilities are required for netns entry and packet capture when
// securityContext.privileged is false (ARCHITECTURE §5.3).
var unprivilegedCapabilities = []corev1.Capability{
	"SYS_ADMIN",
	"NET_ADMIN",
	"NET_RAW",
	"BPF",
	"PERFMON",
}

// PodManifest returns a Pod spec for a node-local sniffer agent. The caller
// creates the object in cfg.Namespace. sessionID must be non-empty.
// activeDeadline, when positive, sets spec.activeDeadlineSeconds as a crash-
// safety backstop when the hub process cannot run StopSession.
func PodManifest(sessionID, nodeName string, cfg capture.AgentConfig, activeDeadline time.Duration) (*corev1.Pod, error) {
	cfg = cfg.WithDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("agent config: %w", err)
	}
	if sessionID == "" {
		return nil, fmt.Errorf("session id: required")
	}
	if nodeName == "" {
		return nil, fmt.Errorf("node name: required")
	}

	securityContext := agentSecurityContext(cfg)
	pullPolicy := corev1.PullIfNotPresent
	if cfg.AllowMutableImage {
		pullPolicy = corev1.PullAlways
	}
	automountToken := false

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: GenerateNamePrefix,
			Namespace:    cfg.Namespace,
			Labels: map[string]string{
				LabelAppKey:     LabelAppValue,
				LabelSessionKey: sessionID,
				LabelNodeKey:    nodeName,
			},
		},
		Spec: corev1.PodSpec{
			NodeName:                     nodeName,
			HostPID:                      true,
			RestartPolicy:                corev1.RestartPolicyNever,
			AutomountServiceAccountToken: &automountToken,
			Containers: []corev1.Container{
				{
					Name:            AgentContainerName,
					Image:           cfg.Image,
					ImagePullPolicy: pullPolicy,
					SecurityContext: securityContext,
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      CRISocketVolumeName,
							MountPath: cfg.CRISocketHostPath,
							ReadOnly:  true,
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: CRISocketVolumeName,
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: cfg.CRISocketHostPath,
							Type: hostPathType(corev1.HostPathSocket),
						},
					},
				},
			},
		},
	}
	if activeDeadline > 0 {
		secs := int64(activeDeadline.Seconds())
		if secs < 1 {
			secs = 1
		}
		pod.Spec.ActiveDeadlineSeconds = &secs
	}
	return pod, nil
}

func agentSecurityContext(cfg capture.AgentConfig) *corev1.SecurityContext {
	if cfg.Privileged() {
		privileged := true
		return &corev1.SecurityContext{Privileged: &privileged}
	}
	return &corev1.SecurityContext{
		Capabilities: &corev1.Capabilities{Add: unprivilegedCapabilities},
	}
}

func hostPathType(t corev1.HostPathType) *corev1.HostPathType { return &t }
