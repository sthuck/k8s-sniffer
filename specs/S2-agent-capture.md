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
| `K8S_SNIFFER_HUB_ADDR` | Hub gRPC dial target (`host:port`) |
| `K8S_SNIFFER_CRI_SOCKET` | Node CRI socket host path |

Flow:

1. `ConfigFromEnv()` validates configuration.
2. `hubclient.Dial` connects to `AgentIngestService`.
3. `WatchTargets` receives the initial `AgentAssignment` (targets, `stream_id`).
4. `StreamCapture` opens the ingest stream for packet batches.

`capture.AgentConfig.HubIngestAddr` is required when building agent pods.

## 2. Netns resolution (T1.10)

Package: `pkg/agent/netns`.

`CRIResolver` dials the node CRI socket (`unix://` + mounted path) and:

1. Lists the pod sandbox by Kubernetes labels.
2. Picks a running workload container (skips `POD` infra when possible).
3. Reads the container PID from verbose `ContainerStatus` info.
4. Returns `/proc/<pid>/ns/net`.

`MapResolver` supports unit tests without a real CRI socket.

## 3. tcpdump capture (T1.11)

Package: `pkg/agent/capture`.

`Tcpdump.Start` runs:

```text
nsenter --net=/proc/<pid>/ns/net tcpdump -i any -U -w - -s <snaplen> [bpf]
```

`-U` flushes each packet so the pcap stream can be read incrementally from
stdout.

## 4. Frame streaming (T1.12)

`PCAPReader` parses the pcap stream into `PacketFrame` records.

`Runner` (per target):

1. Resolves netns.
2. Starts tcpdump.
3. Reads frames, batches them into `CaptureBatch`.
4. Sends batches on `StreamCapture`.

Hub (`pkg/hub/packets.go`):

- `StreamCapture` ingests batches and fans records to `SubscribePackets`
  subscribers (async per subscriber so ingest does not block on slow clients).
- Returns `StreamCaptureSummary.records_accepted`.

## 5. Tests

| Test | Layer |
|------|-------|
| `pkg/agent/config_test.go` | Env validation |
| `pkg/agent/capture/pcap_test.go` | PCAP → `PacketFrame` |
| `pkg/hub/packets_test.go` | Fan-out to subscribers |
| `pkg/hub/hub_test.go` `WatchTargets` | Assignment delivery (IT1.2 partial) |

Cluster validation (curl traffic readable in pcap) lands with T1.15/T1.17 e2e.
