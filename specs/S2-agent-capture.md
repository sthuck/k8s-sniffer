# S2 — Agent capture path (Phase 1C)

**Tasks:** T1.9, T1.10, T1.11, T1.12.

**Depends on:** [S2-in-process-hub.md](./S2-in-process-hub.md) (T1.8).

---

## 1. Agent bootstrap (T1.9)

Package: `pkg/agent`.

The agent reads configuration from environment variables injected by
`PodManifest`:

| Env | Purpose |
|-----|---------|
| `K8S_SNIFFER_SESSION_ID` | Capture session |
| `K8S_SNIFFER_NODE` | Node name |
| `K8S_SNIFFER_AGENT_POD` | Agent pod name (downward API) |
| `K8S_SNIFFER_STREAM_ID` | Random per-incarnation ingest credential |
| `K8S_SNIFFER_HUB_ADDR` | Hub gRPC dial target (`host:port`) |
| `K8S_SNIFFER_CRI_SOCKET` | Node CRI socket host path |
| `K8S_SNIFFER_LOG_LEVEL` | Optional log verbosity (`info` or `debug`) |

Flow:

1. `ConfigFromEnv()` validates configuration.
2. `hubclient.Dial` connects to `AgentIngestService`.
3. `WatchTargets` authenticates the pod and receives its `AgentAssignment`.
4. `StreamCapture` opens the ingest stream for packet batches.

The agent verifies that assignment session, node, and stream identity match its
injected configuration before resolving any target.

`capture.AgentConfig.HubIngestAddr` is required when building agent pods.

**Hub reachability (MVP):** agents dial `HubIngestAddr` from a node pod. The
Phase 1 hub runs in-process in the CLI on the operator machine, so
`127.0.0.1:…` is only valid for local integration tests — not for a real
cluster agent. T1.14 (`capture` command) will define how the CLI advertises a
node-reachable ingest address (port-forward, hostNetwork relay, or similar).
Until then, golden manifests use loopback for unit tests only.

The per-incarnation stream credential binds bootstrap and ingest to the created
agent pod, but MVP gRPC transport is still plaintext. A future node-reachable
listener must remain on a trusted/private path until Phase 4 adds mTLS.

## 2. Netns resolution (T1.10)

Package: `pkg/agent/netns`.

`CRIResolver` dials the node CRI socket (`unix://` + mounted path) and:

1. Lists READY pod sandboxes by name, namespace, and UID labels and chooses the
   newest UID match.
2. Picks a running workload container (skips `POD` infra when possible;
   sorts by name for stable choice; honors `PodRef.container_id` when set).
3. Reads the container PID from verbose `ContainerStatus` info (containerd nests
   `pid` inside `Info["info"]` JSON).
4. Returns `/proc/<pid>/ns/net`.

`MapResolver` supports unit tests without a real CRI socket.

The CRI socket is a node-level trust boundary: a read-only socket mount does not
restrict CRI RPC methods. The privileged agent image must therefore remain
digest-pinned; a least-privilege CRI proxy is a later hardening option.

## 3. tcpdump capture (T1.11)

Package: `pkg/agent/capture`.

`Tcpdump.Start` runs:

```text
nsenter --net=/proc/<pid>/ns/net tcpdump -i any -U -w - -s <snaplen> [bpf]
```

Only the first interface in `Target.interfaces` is honored; more than one
returns an error until multi-iface capture is implemented.

`-U` flushes each packet so the pcap stream can be read incrementally from
stdout. The BPF argument follows `--` so it cannot become a tcpdump option.
stderr is drained concurrently with a size cap and included in process errors.

## 4. Frame streaming (T1.12)

`PCAPReader` parses the pcap stream into `PacketFrame` records.

`Runner` (per target):

1. Resolves netns.
2. Starts tcpdump.
3. Reads frames, batches them into `CaptureBatch`.
4. Sends batches on `StreamCapture`.

Hub (`pkg/hub/packets.go`):

- `StreamCapture` validates batch `session_id`, `node`, and `stream_id` against
  the live assignment, permits only one active stream per agent incarnation,
  bounds batch size, and verifies each record's pod.
- Ingest waits for the first `SubscribePackets` client and applies backpressure
  through gRPC rather than silently dropping records.
- Session stop accepts in-flight batches while agents receive a short graceful
  termination window, then closes packet subscribers after agents are gone.
- Sequence numbers are monotonic across every target in one agent incarnation.
- Per-target failures are emitted through `ReportStatus` as structured events.
- Returns `StreamCaptureSummary.records_accepted`.

## 5. Tests

| Test | Layer |
|------|-------|
| `pkg/agent/config_test.go` | Env validation |
| `pkg/agent/capture/pcap_test.go` | PCAP → `PacketFrame` |
| `pkg/agent/capture/tcpdump_test.go` | Safe tcpdump argv and bounded stderr |
| `pkg/agent/runner_test.go` | Sender failure cancellation and stream-wide sequences |
| `pkg/agent/netns/resolver_test.go` | CRI PID parsing, workload container pick |
| `pkg/hub/packets_test.go` | Lossless fan-out and subscriber startup gate |
| `pkg/hub/hub_test.go` | Assignment auth and ingest → subscription integration |

The real curl-to-PCAP check lands with the T1.15/T1.17 kind e2e harness.
