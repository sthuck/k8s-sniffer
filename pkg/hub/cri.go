package hub

import (
	"context"
	"log/slog"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/sthuck/k8s-sniffer/pkg/capture"
)

func resolveCRISocket(client kubernetes.Interface, configured string) string {
	if configured != "" && configured != capture.DefaultCRISocketPath {
		return configured
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	list, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		hubLog.Debug("cri socket: node list failed, keeping configured path",
			slog.String("socket", configured),
			slog.String("err", err.Error()),
		)
		return capture.CRISocketForRuntimeVersion("", configured)
	}
	for _, node := range list.Items {
		ver := node.Status.NodeInfo.ContainerRuntimeVersion
		if ver == "" {
			continue
		}
		socket := capture.CRISocketForRuntimeVersion(ver, configured)
		hubLog.Debug("cri socket from node runtime",
			slog.String("node", node.Name),
			slog.String("runtime", ver),
			slog.String("socket", socket),
		)
		return socket
	}
	return capture.CRISocketForRuntimeVersion("", configured)
}
