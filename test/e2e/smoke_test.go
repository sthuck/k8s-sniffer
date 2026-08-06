//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/gopacket/gopacket/pcapgo"

	"github.com/sthuck/k8s-sniffer/pkg/capture"
	"github.com/sthuck/k8s-sniffer/pkg/cli"
	"github.com/sthuck/k8s-sniffer/pkg/k8s"
)

func TestE2E1_1_SmokeCapture(t *testing.T) {
	kubeContext := os.Getenv("K8S_SNIFFER_E2E_KUBECONTEXT")
	if kubeContext == "" {
		t.Skip("set K8S_SNIFFER_E2E_KUBECONTEXT to run cluster e2e")
	}
	agentImage := os.Getenv("K8S_SNIFFER_E2E_AGENT_IMAGE")
	if agentImage == "" {
		t.Skip("set K8S_SNIFFER_E2E_AGENT_IMAGE to run cluster e2e")
	}
	hubIngest := os.Getenv("K8S_SNIFFER_E2E_HUB_INGEST_ADDR")
	if hubIngest == "" {
		t.Skip("set K8S_SNIFFER_E2E_HUB_INGEST_ADDR to run cluster e2e")
	}

	kclient, err := k8s.New(k8s.ClientConfig{
		Kubeconfig: kubeconfigPath(),
		Context:    kubeContext,
		UserAgent:  "k8s-sniffer/e2e",
	})
	if err != nil {
		t.Fatalf("kubernetes client: %v", err)
	}
	client := kclient.Clientset

	waitForDeployments(t, client, "e2e-fixtures", "http-echo-a", "http-echo-b")

	outPath := filepath.Join(t.TempDir(), "capture.pcapng")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	sessionReady := make(chan struct{})
	captureDone := make(chan error, 1)
	go func() {
		captureDone <- cli.RunCapture(ctx, cli.CaptureOptions{
			Spec: capture.Spec{
				Namespace:   "e2e-fixtures",
				PodPatterns: []string{`http-echo-.*`},
				Duration:    30 * time.Second,
			},
			Sink: capture.SinkSpec{Out: outPath},
			Agent: capture.AgentConfig{
				Namespace:         capture.DefaultAgentNamespace,
				Image:             agentImage,
				CRISocketHostPath: capture.DefaultCRISocketPath,
				AllowMutableImage: true,
				HubIngestAddr:     hubIngest,
			},
			Kube: k8s.ClientConfig{
				Kubeconfig: kubeconfigPath(),
				Context:    kubeContext,
				UserAgent:  "k8s-sniffer/e2e",
			},
			HubListen: "0.0.0.0:" + hubPort(hubIngest),
			HubIngest: hubIngest,
			OnSessionReady: func() {
				close(sessionReady)
			},
		})
	}()

	select {
	case <-sessionReady:
	case <-time.After(2 * time.Minute):
		t.Fatal("timed out waiting for capture session to become ready")
	}
	generateTraffic(t, kubeContext)

	if err := <-captureDone; err != nil {
		t.Fatalf("RunCapture: %v", err)
	}

	assertPCAPHasPackets(t, outPath)
	assertNoSessionAgents(t, client)
}

func kubeconfigPath() string {
	if p := os.Getenv("KUBECONFIG"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".kube", "config")
}

func hubPort(addr string) string {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[i+1:]
	}
	return "30551"
}

func waitForDeployments(t *testing.T, client kubernetes.Interface, namespace string, names ...string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		ready := 0
		for _, name := range names {
			dep, err := client.AppsV1().Deployments(namespace).Get(context.Background(), name, metav1.GetOptions{})
			if err != nil {
				continue
			}
			if dep.Status.ReadyReplicas >= 1 {
				ready++
			}
		}
		if ready == len(names) {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("deployments not ready in namespace %s", namespace)
}

func generateTraffic(t *testing.T, kubeContext string) {
	t.Helper()
	for _, target := range []string{"http-echo-a", "http-echo-b"} {
		cmd := exec.CommandContext(context.Background(), "kubectl",
			"--context", kubeContext,
			"-n", "e2e-fixtures",
			"run", "curl-"+target, "--rm", "-i", "--restart=Never",
			"--image=curlimages/curl:8.8.0",
			"--", "curl", "-fsS", "http://"+target+":5678/",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("curl %s: %v (%s)", target, err, out)
		}
	}
}

func assertPCAPHasPackets(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pcap: %v", err)
	}
	reader, err := pcapgo.NewNgReader(bytes.NewReader(data), pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatalf("pcapng reader: %v", err)
	}
	count := 0
	for {
		if _, _, err := reader.ReadPacketData(); err != nil {
			break
		}
		count++
	}
	if count == 0 {
		t.Fatal("pcapng contains no packets")
	}
}

func assertNoSessionAgents(t *testing.T, client kubernetes.Interface) {
	t.Helper()
	pods, err := client.CoreV1().Pods(capture.DefaultAgentNamespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: "app=k8s-sniffer-agent",
	})
	if err != nil {
		t.Fatalf("list agent pods: %v", err)
	}
	if len(pods.Items) > 0 {
		t.Fatalf("expected no agent pods after session stop, found %d", len(pods.Items))
	}
}
