//go:build e2e && e2e_tls

package e2e_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sthuck/k8s-sniffer/pkg/capture"
)

func TestE2E3_1_EBPFJSONLContainsSecret(t *testing.T) {
	e := requireE2EEnv(t)
	e.ensureHTTPSOpenSSL()

	rc := e.startCaptureWith(captureSettings{
		namespace:  httpsNamespace,
		podPattern: httpsName,
		outName:    "tls-ebpf.pcapng",
		tlsMode:    capture.TLSModeAuto,
		tlsOutName: "tls.jsonl",
	})
	rc.waitReady(t)
	e.httpsGETInCluster("/" + httpsMarker)
	time.Sleep(3 * time.Second)
	e.dumpAgents("tls-ebpf-agent-logs.txt")
	rc.stop(t)

	assertPCAPHasPackets(t, rc.outPath)
	b, err := os.ReadFile(rc.tlsOutPath)
	if err != nil {
		t.Fatalf("read tls-out: %v", err)
	}
	if !strings.Contains(string(b), httpsMarker) {
		t.Fatalf("JSONL missing %s:\n%s\nevents:\n%s", httpsMarker, b, rc.events.String())
	}
	assertNoSessionAgents(t, e.client)
}
