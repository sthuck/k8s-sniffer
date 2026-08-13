//go:build e2e

package e2e_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/sthuck/k8s-sniffer/pkg/hub/agent"
)

// E2E2.3 — Pods on node A and B yield two agents; draining B's pods removes B's agent.
func TestE2E2_3_MultiNodeAgentLifecycle(t *testing.T) {
	e := requireE2EEnv(t)
	nodes := schedulableNodes(t, e.client)
	if len(nodes) < 2 {
		t.Fatalf("need 2 schedulable nodes for E2E2.3, found %v (use test/e2e/kind.yaml)", nodes)
	}
	nodeA, nodeB := nodes[0], nodes[1]

	ns := fmt.Sprintf("e2e-multinode-%d", time.Now().UnixNano())
	createNamespace(t, e.client, ns)
	createEchoWorkload(t, e.client, ns, "echo-a", "hello-a", nodeA)
	createEchoWorkload(t, e.client, ns, "echo-b", "hello-b", nodeB)
	waitForDeployments(t, e.client, ns, "echo-a", "echo-b")

	rc := e.startCapture(ns, `echo-.*`, "e2e2-3.pcapng")
	rc.waitReady(t)

	waitUntil(t, 30*time.Second, "two agents on distinct nodes", func() bool {
		agents := listAgentPods(t, e.client)
		if len(agents) != 2 {
			return false
		}
		seen := map[string]bool{}
		for _, p := range agents {
			seen[p.Spec.NodeName] = true
			if p.Labels[agent.LabelNodeKey] != p.Spec.NodeName {
				t.Fatalf("agent %s label %s=%q nodeName=%q", p.Name, agent.LabelNodeKey, p.Labels[agent.LabelNodeKey], p.Spec.NodeName)
			}
		}
		return seen[nodeA] && seen[nodeB]
	})

	generateTraffic(t, e.kubeContext, ns, "echo-a", "echo-b")

	deleteEchoWorkload(t, e.client, ns, "echo-b")
	waitUntil(t, 60*time.Second, "agent on node B removed after last target left", func() bool {
		agents := listAgentPods(t, e.client)
		if len(agents) != 1 {
			return false
		}
		return agents[0].Spec.NodeName == nodeA
	})

	generateTraffic(t, e.kubeContext, ns, "echo-a")
	time.Sleep(2 * time.Second)

	e.dumpAgents("e2e2-3-agent-logs.txt")
	rc.stop(t)

	assertPCAPHasPackets(t, rc.outPath)
	assertNoSessionAgents(t, e.client)
}
