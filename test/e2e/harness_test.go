//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"

	"github.com/gopacket/gopacket/pcapgo"

	"github.com/sthuck/k8s-sniffer/pkg/capture"
	"github.com/sthuck/k8s-sniffer/pkg/cli"
	"github.com/sthuck/k8s-sniffer/pkg/hub/agent"
	"github.com/sthuck/k8s-sniffer/pkg/k8s"
)

const (
	echoImage  = "hashicorp/http-echo:1.0"
	echoPort   = 5678
	curlImage  = "curlimages/curl:8.8.0"
	e2eTimeout = 3 * time.Minute
	readyWait  = 2 * time.Minute
)

type eventBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (e *eventBuffer) Write(p []byte) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.buf.Write(p)
}

func (e *eventBuffer) String() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.buf.String()
}

func (e *eventBuffer) contains(substr string) bool {
	return strings.Contains(e.String(), substr)
}

type e2eEnv struct {
	t           *testing.T
	kubeContext string
	agentImage  string
	hubIngest   string
	client      kubernetes.Interface
	artifactDir string
}

func requireE2EEnv(t *testing.T) *e2eEnv {
	t.Helper()
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
	return &e2eEnv{
		t:           t,
		kubeContext: kubeContext,
		agentImage:  agentImage,
		hubIngest:   hubIngest,
		client:      kclient.Clientset,
		artifactDir: os.Getenv("K8S_SNIFFER_E2E_ARTIFACT_DIR"),
	}
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

func (e *e2eEnv) captureOutPath(name string) string {
	e.t.Helper()
	outPath := filepath.Join(e.t.TempDir(), name)
	if e.artifactDir != "" {
		if err := os.MkdirAll(e.artifactDir, 0o755); err != nil {
			e.t.Fatalf("artifact dir: %v", err)
		}
		outPath = filepath.Join(e.artifactDir, name)
	}
	return outPath
}

type runningCapture struct {
	cancel       context.CancelFunc
	done         <-chan error
	ready        <-chan struct{}
	events       *eventBuffer
	outPath      string
	client       kubernetes.Interface
	artifactName string
}

func (e *e2eEnv) startCapture(namespace, podPattern, outName string) *runningCapture {
	e.t.Helper()
	outPath := e.captureOutPath(outName)
	events := &eventBuffer{}
	ctx, cancel := context.WithTimeout(context.Background(), e2eTimeout)
	ready := make(chan struct{})
	done := make(chan error, 1)

	rc := &runningCapture{
		cancel:       cancel,
		done:         done,
		ready:        ready,
		events:       events,
		outPath:      outPath,
		client:       e.client,
		artifactName: strings.TrimSuffix(outName, filepath.Ext(outName)),
	}
	e.t.Cleanup(func() {
		if e.t.Failed() && e.artifactDir != "" {
			dumpAgentLogs(e.t, e.client, filepath.Join(e.artifactDir, rc.artifactName+"-agent-logs-at-end.txt"))
			_ = os.WriteFile(filepath.Join(e.artifactDir, rc.artifactName+"-events.txt"), []byte(events.String()), 0o644)
		}
		cancel()
	})

	go func() {
		done <- cli.RunCapture(ctx, cli.CaptureOptions{
			Spec: capture.Spec{
				Namespace:   namespace,
				PodPatterns: []string{podPattern},
			},
			Sink: capture.SinkSpec{Out: outPath},
			Agent: capture.AgentConfig{
				Namespace:         capture.DefaultAgentNamespace,
				Image:             e.agentImage,
				CRISocketHostPath: capture.DefaultCRISocketPath,
				AllowMutableImage: true,
				HubIngestAddr:     e.hubIngest,
				LogLevel:          "debug",
			},
			Kube: k8s.ClientConfig{
				Kubeconfig: kubeconfigPath(),
				Context:    e.kubeContext,
				UserAgent:  "k8s-sniffer/e2e",
			},
			HubListen:   "0.0.0.0:" + hubPort(e.hubIngest),
			HubIngest:   e.hubIngest,
			EventWriter: events,
			OnSessionReady: func() {
				close(ready)
			},
		})
	}()
	return rc
}

func (rc *runningCapture) waitReady(t *testing.T) {
	t.Helper()
	select {
	case <-rc.ready:
	case err := <-rc.done:
		t.Fatalf("capture ended before session ready: %v", err)
	case <-time.After(readyWait):
		t.Fatal("timed out waiting for capture session to become ready")
	}
}

func (rc *runningCapture) stop(t *testing.T) {
	t.Helper()
	rc.cancel()
	if err := <-rc.done; err != nil {
		t.Fatalf("RunCapture: %v", err)
	}
}

func (e *e2eEnv) dumpAgents(name string) {
	if e.artifactDir == "" {
		return
	}
	dumpAgentLogs(e.t, e.client, filepath.Join(e.artifactDir, name))
}

func waitForDeployments(t *testing.T, client kubernetes.Interface, namespace string, names ...string) {
	t.Helper()
	deadline := time.Now().Add(readyWait)
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
	t.Fatalf("deployments not ready in namespace %s: %v", namespace, names)
}

func generateTraffic(t *testing.T, kubeContext, namespace string, targets ...string) {
	t.Helper()
	if len(targets) == 0 {
		targets = []string{"http-echo-a", "http-echo-b"}
	}
	for _, target := range targets {
		cmd := exec.CommandContext(context.Background(), "kubectl",
			"--context", kubeContext,
			"-n", namespace,
			"run", "curl-"+target+"-"+fmt.Sprintf("%d", time.Now().UnixNano()),
			"--rm", "-i", "--restart=Never",
			"--image="+curlImage,
			"--", "curl", "-fsS", fmt.Sprintf("http://%s:%d/", target, echoPort),
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
	if len(data) == 0 {
		t.Fatal("pcapng is empty (no frames received from agents)")
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

func pcapContainsBytes(t *testing.T, path string, marker []byte) bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pcap: %v", err)
	}
	reader, err := pcapgo.NewNgReader(bytes.NewReader(data), pcapgo.NgReaderOptions{WantMixedLinkType: true})
	if err != nil {
		t.Fatalf("pcapng reader: %v", err)
	}
	for {
		pkt, _, err := reader.ReadPacketData()
		if err != nil {
			break
		}
		if bytes.Contains(pkt, marker) {
			return true
		}
	}
	return false
}

func pcapInterfaceComments(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pcap: %v", err)
	}
	reader, err := pcapgo.NewNgReader(bytes.NewReader(data), pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatalf("pcapng reader: %v", err)
	}
	// Interfaces are registered as packets arrive; drain so late IDBs are visible.
	for {
		if _, _, err := reader.ReadPacketData(); err != nil {
			break
		}
	}
	var comments []string
	for i := 0; i < reader.NInterfaces(); i++ {
		intf, err := reader.Interface(i)
		if err != nil {
			t.Fatalf("interface %d: %v", i, err)
		}
		comments = append(comments, intf.Name+" "+intf.Comment)
	}
	return comments
}

func assertNoSessionAgents(t *testing.T, client kubernetes.Interface) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		pods, err := client.CoreV1().Pods(capture.DefaultAgentNamespace).List(context.Background(), metav1.ListOptions{
			LabelSelector: "app=k8s-sniffer-agent",
		})
		if err != nil {
			t.Fatalf("list agent pods: %v", err)
		}
		if len(pods.Items) == 0 {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("expected no agent pods after session stop")
}

func listAgentPods(t *testing.T, client kubernetes.Interface) []corev1.Pod {
	t.Helper()
	pods, err := client.CoreV1().Pods(capture.DefaultAgentNamespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: "app=" + agent.LabelAppValue,
	})
	if err != nil {
		t.Fatalf("list agent pods: %v", err)
	}
	return pods.Items
}

func schedulableNodes(t *testing.T, client kubernetes.Interface) []string {
	t.Helper()
	nodes, err := client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	var names []string
	for _, n := range nodes.Items {
		ready := false
		for _, c := range n.Status.Conditions {
			if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
				ready = true
				break
			}
		}
		if ready {
			names = append(names, n.Name)
		}
	}
	return names
}

func createNamespace(t *testing.T, client kubernetes.Interface, name string) {
	t.Helper()
	_, err := client.CoreV1().Namespaces().Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create namespace %s: %v", name, err)
	}
	t.Cleanup(func() {
		_ = client.CoreV1().Namespaces().Delete(context.Background(), name, metav1.DeleteOptions{})
	})
}

func int32Ptr(v int32) *int32 { return &v }

func createEchoWorkload(t *testing.T, client kubernetes.Interface, namespace, name, text, nodeName string) {
	t.Helper()
	labels := map[string]string{"app": name}
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: appsv1.DeploymentSpec{
			Replicas: int32Ptr(1),
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  "echo",
						Image: echoImage,
						Args:  []string{"-text=" + text},
						Ports: []corev1.ContainerPort{{ContainerPort: echoPort}},
					}},
				},
			},
		},
	}
	if nodeName != "" {
		dep.Spec.Template.Spec.NodeName = nodeName
	}
	if _, err := client.AppsV1().Deployments(namespace).Create(context.Background(), dep, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create deployment %s: %v", name, err)
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: corev1.ServiceSpec{
			Selector: labels,
			Ports:    []corev1.ServicePort{{Port: echoPort, TargetPort: intstr.FromInt(echoPort)}},
		},
	}
	if _, err := client.CoreV1().Services(namespace).Create(context.Background(), svc, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create service %s: %v", name, err)
	}
}

func deleteEchoWorkload(t *testing.T, client kubernetes.Interface, namespace, name string) {
	t.Helper()
	if err := client.AppsV1().Deployments(namespace).Delete(context.Background(), name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("delete deployment %s: %v", name, err)
	}
	if err := client.CoreV1().Services(namespace).Delete(context.Background(), name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("delete service %s: %v", name, err)
	}
}

func waitUntil(t *testing.T, timeout time.Duration, msg string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", msg)
}

func dumpAgentLogs(t *testing.T, client kubernetes.Interface, path string) {
	t.Helper()
	pods, err := client.CoreV1().Pods(capture.DefaultAgentNamespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: "app=k8s-sniffer-agent",
	})
	if err != nil {
		_ = os.WriteFile(path+".error", []byte(err.Error()), 0o644)
		return
	}
	var buf bytes.Buffer
	if len(pods.Items) == 0 {
		buf.WriteString("(no agent pods)\n")
	}
	for _, pod := range pods.Items {
		fmt.Fprintf(&buf, "=== %s/%s phase=%s node=%s ===\n", pod.Namespace, pod.Name, pod.Status.Phase, pod.Spec.NodeName)
		req := client.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{})
		stream, err := req.Stream(context.Background())
		if err != nil {
			fmt.Fprintf(&buf, "logs error: %v\n", err)
			continue
		}
		_, _ = io.Copy(&buf, stream)
		_ = stream.Close()
		buf.WriteByte('\n')
	}
	_ = os.WriteFile(path, buf.Bytes(), 0o644)
}
