//go:build e2e

package e2e_test

import (
	"testing"
	"time"
)

func TestE2E1_1_SmokeCapture(t *testing.T) {
	e := requireE2EEnv(t)
	waitForDeployments(t, e.client, "e2e-fixtures", "http-echo-a", "http-echo-b")

	rc := e.startCapture("e2e-fixtures", `http-echo-.*`, "capture.pcapng")
	rc.waitReady(t)

	generateTraffic(t, e.kubeContext, "e2e-fixtures", "http-echo-a", "http-echo-b")
	time.Sleep(2 * time.Second)

	e.dumpAgents("agent-logs.txt")
	rc.stop(t)

	assertPCAPHasPackets(t, rc.outPath)
	assertNoSessionAgents(t, e.client)
}
