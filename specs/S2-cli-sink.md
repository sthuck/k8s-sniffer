# S2 — CLI, PCAP sink, agent image, RBAC, e2e harness (Phase 1D)

**Tasks:** T1.13, T1.14, T1.15, T1.16, T1.17, T-TEST.1.

**Depends on:** [S2-agent-capture.md](./S2-agent-capture.md) (T1.9–T1.12).

---

## 1. PCAP sink (T1.13)

Package: `pkg/sink`.

`OpenPCAP(path)` writes wire `PacketFrame`s to:

| Path | Format |
|------|--------|
| `*.pcapng`, `*.ngpcap` | PCAPng via `gopacket/pcapgo.NgWriter` |
| other paths | classic PCAP |
| `-` (`capture.StdoutSink`) | classic PCAP on stdout (Wireshark pipe friendly) |

`WriteRecord` ignores TLS events (Phase 3). Link type comes from the first
frame; defaults to Linux SLL when unspecified.

Tests: `pkg/sink/pcap_test.go` (**UT1.5** round-trip).

## 2. CLI `capture` (T1.14)

Packages: `cmd/k8s-sniffer`, `pkg/cli`.

```bash
k8s-sniffer capture -n NAMESPACE --pod REGEX [--pod REGEX2] \
  [-o out.pcapng] [--bpf FILTER] [--duration 5m] \
  [--agent-image IMG] [--allow-mutable-agent-image] \
  [--hub-ingest-addr host:port] [--kubeconfig PATH]
```

Flow:

1. Build `capture.Spec`, `SinkSpec`, `AgentConfig` from flags.
2. Start in-process gRPC hub (`HubService` + `AgentIngestService`) on
   `--hub-listen` (default `0.0.0.0:ephemeral`).
3. Auto-detect `--hub-ingest-addr` from `K8S_SNIFFER_HUB_INGEST_HOST` or the
   host's outbound UDP route IP so kind agents can dial the CLI.
4. `CreateSession` → `SubscribePackets` (wait until registered) → then
   `OnSessionReady` / traffic may begin. Agents' `WatchTargets` blocks until a
   packet subscriber exists, so ready must not fire earlier.
5. `WatchEvents` lines go to stderr (`event: …`).
6. SIGINT/SIGTERM or `--duration` → `StopSession` → drain → exit.

Release builds without a pinned agent image require `--agent-image` (or
`--allow-mutable-agent-image` for dev/kind).

## 3. Agent image (T1.15)

`Dockerfile` multi-stage:

- `build` — static `k8s-sniffer` + `k8s-sniffer-agent`
- `agent` — Alpine + `tcpdump` + `util-linux` (`nsenter`) + agent binary
- `cli` — optional distroless CLI image

Makefile targets: `image-agent`, `image-cli`, `docker-build`.

Load into kind: `kind load docker-image k8s-sniffer-agent:e2e`.

## 4. RBAC (T1.16)

`deploy/rbac.yaml`:

- Namespace `k8s-sniffer`
- ServiceAccount `k8s-sniffer`
- ClusterRole: `pods` get/list/watch; `pods` create/delete; `pods/log` get

CLI mode uses the operator kubeconfig; the manifest documents the minimum verbs
and provides a ServiceAccount for Phase 4 in-cluster hub.

## 5. Kind e2e harness (T1.17, T-TEST.1)

```text
test/e2e/
  kind.yaml              # single-node kind + host port 30551
  run.sh                 # kind | test | (default: both)
  fixtures/http-echo.yaml
  smoke_test.go          //go:build e2e — E2E1.1
```

`./test/e2e/run.sh`:

1. `kind create` (if needed), `docker build --target agent`, `kind load`
2. Apply RBAC + HTTP echo fixtures
3. `go test -tags=e2e ./test/e2e/...` with env:
   - `K8S_SNIFFER_E2E_KUBECONTEXT`
   - `K8S_SNIFFER_E2E_AGENT_IMAGE`
   - `K8S_SNIFFER_E2E_HUB_INGEST_ADDR` (host-reachable from pods)

**E2E1.1** captures `http-echo-.*` pods, generates curl traffic, asserts PCAP
non-empty, asserts agent pods deleted after stop.

## 6. Tests

| Test | Layer |
|------|-------|
| `pkg/sink/pcap_test.go` | UT1.5 PCAP round-trip |
| `test/e2e/smoke_test.go` | E2E1.1 (requires kind) |

CI jobs and failure artifacts: [S2-ci-e2e.md](./S2-ci-e2e.md) (T-TEST.2 / T-TEST.7).
