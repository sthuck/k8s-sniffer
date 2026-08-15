//go:build e2e

package e2e_test

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/sthuck/k8s-sniffer/pkg/capture"
)

func TestE2E3_4_TLSOffNoPlaintext(t *testing.T) {
	e := requireE2EEnv(t)
	e.ensureHTTPSOpenSSL()

	rc := e.startCaptureWith(captureSettings{
		namespace:  httpsNamespace,
		podPattern: httpsName,
		outName:    "tls-off.pcapng",
		tlsMode:    capture.TLSModeOff,
		tlsOutName: "tls-off.jsonl",
	})
	rc.waitReady(t)
	e.httpsGETInCluster("/" + httpsMarker)
	time.Sleep(2 * time.Second)
	e.dumpAgents("tls-off-agent-logs.txt")
	rc.stop(t)

	assertPCAPHasPackets(t, rc.outPath)
	if pcapContainsBytes(t, rc.outPath, []byte(httpsMarker)) {
		t.Fatal("wire pcap unexpectedly contains plaintext marker with --tls=off")
	}
	data, err := os.ReadFile(rc.tlsOutPath)
	if err != nil {
		t.Fatalf("tls-out: %v", err)
	}
	if strings.Contains(string(data), httpsMarker) {
		t.Fatalf("tls-out contains plaintext with --tls=off:\n%s", data)
	}
	assertNoSessionAgents(t, e.client)
}

func TestE2E3_3_KeylogFile(t *testing.T) {
	e := requireE2EEnv(t)
	e.ensureHTTPSOpenSSL()

	keylog := e.captureOutPath("sslkeys.log")
	if err := os.WriteFile(keylog, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	rc := e.startCaptureWith(captureSettings{
		namespace:  httpsNamespace,
		podPattern: httpsName,
		outName:    "tls-keylog.pcapng",
		tlsMode:    capture.TLSModeKeylog,
		keylogFile: keylog,
	})
	rc.waitReady(t)

	localPort, stopFwd := e.startPortForward(httpsName, 443)
	defer stopFwd()
	url := fmt.Sprintf("https://127.0.0.1:%d/%s", localPort, httpsMarker)
	if err := httpsGETWithKeylog(url, keylog); err != nil {
		t.Fatalf("host https GET: %v", err)
	}
	time.Sleep(2 * time.Second)
	e.dumpAgents("tls-keylog-agent-logs.txt")
	rc.stop(t)

	assertPCAPHasPackets(t, rc.outPath)

	keylogData, err := os.ReadFile(keylog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(keylogData), "CLIENT_RANDOM") && !strings.Contains(string(keylogData), "CLIENT_HANDSHAKE_TRAFFIC_SECRET") {
		t.Fatalf("keylog missing TLS secrets:\n%s", keylogData)
	}

	tshark, err := exec.LookPath("tshark")
	if err != nil {
		t.Log("tshark not installed; skipped decrypt assertion (E2E3.3 partial)")
		assertNoSessionAgents(t, e.client)
		return
	}
	cmd := exec.Command(tshark, "-r", rc.outPath, "-o", "tls.keylog_file:"+keylog, "-Y", "http")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("tshark: %s", out)
		t.Fatalf("tshark decrypt failed: %v", err)
	}
	if !strings.Contains(string(out), httpsMarker) && !strings.Contains(strings.ToLower(string(out)), "http") {
		t.Fatalf("tshark did not show decrypted HTTP:\n%s", out)
	}
	assertNoSessionAgents(t, e.client)
}

func TestE2E3_2_AutoUnsupportedKeepsWire(t *testing.T) {
	e := requireE2EEnv(t)
	waitForDeployments(t, e.client, "e2e-fixtures", "http-echo-a")

	rc := e.startCaptureWith(captureSettings{
		namespace:  "e2e-fixtures",
		podPattern: "http-echo-a",
		outName:    "tls-unsupported.pcapng",
		tlsMode:    capture.TLSModeAuto,
	})
	rc.waitReady(t)
	generateTraffic(t, e.kubeContext, "e2e-fixtures", "http-echo-a")
	time.Sleep(2 * time.Second)
	e.dumpAgents("tls-unsupported-agent-logs.txt")
	rc.stop(t)

	assertPCAPHasPackets(t, rc.outPath)
	ev := rc.events.String()
	if !strings.Contains(ev, "TLS_STATUS_UNSUPPORTED") && !strings.Contains(ev, "TLS_STATUS_FALLBACK") {
		t.Fatalf("expected tls unsupported/fallback status, events:\n%s", ev)
	}
	assertNoSessionAgents(t, e.client)
}
