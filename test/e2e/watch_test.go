//go:build e2e

package e2e_test

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// E2E2.1 — Mid-session: create a new matching pod; later packets include it.
func TestE2E2_1_LivePodAttach(t *testing.T) {
	e := requireE2EEnv(t)
	ns := fmt.Sprintf("e2e-attach-%d", time.Now().UnixNano())
	createNamespace(t, e.client, ns)
	createEchoWorkload(t, e.client, ns, "echo-a", "hello-a", "")
	waitForDeployments(t, e.client, ns, "echo-a")

	rc := e.startCapture(ns, `echo-.*`, "e2e2-1.pcapng")
	rc.waitReady(t)

	generateTraffic(t, e.kubeContext, ns, "echo-a")

	createEchoWorkload(t, e.client, ns, "echo-c", "hello-c", "")
	waitForDeployments(t, e.client, ns, "echo-c")

	waitUntil(t, 45*time.Second, "PodAttached event for echo-c", func() bool {
		return strings.Contains(rc.events.String(), "echo-c")
	})

	generateTraffic(t, e.kubeContext, ns, "echo-c")
	time.Sleep(2 * time.Second)

	e.dumpAgents("e2e2-1-agent-logs.txt")
	rc.stop(t)

	assertPCAPHasPackets(t, rc.outPath)
	if !pcapContainsBytes(t, rc.outPath, []byte("hello-c")) {
		t.Fatalf("pcap does not contain traffic from mid-session pod echo-c (marker hello-c)\nevents:\n%s", rc.events.String())
	}
	comments := strings.Join(pcapInterfaceComments(t, rc.outPath), "\n")
	if !strings.Contains(comments, "k8s.pod=") || !strings.Contains(comments, "echo-c") {
		t.Fatalf("pcapng IDBs missing k8s metadata for echo-c:\n%s", comments)
	}
	assertNoSessionAgents(t, e.client)
}

// E2E2.2 — Mid-session: delete a pod; capture continues for remaining targets.
func TestE2E2_2_LivePodDetach(t *testing.T) {
	e := requireE2EEnv(t)
	ns := fmt.Sprintf("e2e-detach-%d", time.Now().UnixNano())
	createNamespace(t, e.client, ns)
	createEchoWorkload(t, e.client, ns, "echo-keep", "hello-keep", "")
	createEchoWorkload(t, e.client, ns, "echo-drop", "hello-drop", "")
	waitForDeployments(t, e.client, ns, "echo-keep", "echo-drop")

	rc := e.startCapture(ns, `echo-.*`, "e2e2-2.pcapng")
	rc.waitReady(t)

	generateTraffic(t, e.kubeContext, ns, "echo-keep", "echo-drop")

	deleteEchoWorkload(t, e.client, ns, "echo-drop")
	waitUntil(t, 45*time.Second, "PodDetached event for echo-drop", func() bool {
		return strings.Contains(strings.ToLower(rc.events.String()), "detach") &&
			strings.Contains(rc.events.String(), "echo-drop")
	})

	generateTraffic(t, e.kubeContext, ns, "echo-keep")
	time.Sleep(2 * time.Second)

	e.dumpAgents("e2e2-2-agent-logs.txt")
	rc.stop(t)

	assertPCAPHasPackets(t, rc.outPath)
	if !pcapContainsBytes(t, rc.outPath, []byte("hello-keep")) {
		t.Fatalf("pcap lost traffic from remaining pod echo-keep after detach\nevents:\n%s", rc.events.String())
	}
	assertNoSessionAgents(t, e.client)
}

// E2E2.6 — Stats/events show packet counters > 0 after traffic.
func TestE2E2_6_SessionStats(t *testing.T) {
	e := requireE2EEnv(t)
	waitForDeployments(t, e.client, "e2e-fixtures", "http-echo-a")

	rc := e.startCapture("e2e-fixtures", `http-echo-a.*`, "e2e2-6.pcapng")
	rc.waitReady(t)

	generateTraffic(t, e.kubeContext, "e2e-fixtures", "http-echo-a")
	waitUntil(t, 20*time.Second, "session stats with packets > 0", func() bool {
		for _, line := range strings.Split(rc.events.String(), "\n") {
			if !strings.Contains(line, "packets=") {
				continue
			}
			fields := strings.Fields(line)
			for _, f := range fields {
				var n int
				if _, err := fmt.Sscanf(f, "packets=%d", &n); err == nil && n > 0 {
					return true
				}
			}
		}
		return false
	})

	e.dumpAgents("e2e2-6-agent-logs.txt")
	rc.stop(t)
	assertNoSessionAgents(t, e.client)
}
