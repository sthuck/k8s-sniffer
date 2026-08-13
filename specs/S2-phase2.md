# S2 — Phase 2 multi-pod polish

**Tasks:** T2.1, T2.2, T2.3, T2.5, T2.7, T-TEST.4.

**Deferred:** T2.4 (`--bpf` e2e), T2.6 (`--split-per-pod`), T2.8 (`--duration` hard stop). `--bpf` and `--duration` flags already exist from Phase 1; they are not expanded here.

**Depends on:** [S2-in-process-hub.md](./S2-in-process-hub.md), [S2-agent-capture.md](./S2-agent-capture.md), [S2-cli-sink.md](./S2-cli-sink.md).

**Tests covered:** UT2.2, IT2.1, E2E2.1, E2E2.2, E2E2.3, E2E2.6.

---

## 1. Live pod watch (T2.1–T2.3)

After `CreateSession` reaches `RUNNING`, the hub starts two goroutines per session:

1. **Pod follow** — Kubernetes `Watch` on the target namespace, with a list-poll fallback (`WatchInterval`, default 1s).
2. **Stats ticker** — emits `SessionStats` (`StatsInterval`, default 5s).

Each watch/poll event runs `reconcileSession` (serialized with `reconcileMu`):

| Desired vs current | Action |
|--------------------|--------|
| New matching Running pod on an existing node | `PodAttached`; `WatchTargets` sends an updated `AgentAssignment` (same `stream_id`) |
| New matching pod on a new node | `PodAttached`; `CreateForNode` + `WaitReady`; new assignment |
| Pod no longer matching / not Running / terminating | `PodDetached`; assignment shrinks |
| Last target left a node | `DeleteAgentOnNode`; `AgentPhase` TERMINATING then GONE |

`StopSession` cancels the session context, then takes `reconcileMu` so an in-flight `WaitReady` observes cancellation before agents are deleted.

Terminating pods (`DeletionTimestamp != nil`) are not capture targets even if still `Running`.

Empty discovery at create still fails the session. A session that later drops to zero targets stays `RUNNING` so a later match can attach.

## 2. Agent target hot-update (T2.2)

`WatchTargets` is already a stream. The hub now:

1. Authenticates the agent.
2. Waits until `RUNNING` and a packet subscriber exists.
3. Sends the current assignment, then blocks on assignment generation changes.
4. Sends the new assignment (or ends the stream when this node’s agent is removed).

The agent `Runner` keeps the watch open, maintains one tcpdump per pod UID, starts captures for added targets, and cancels captures for removed UIDs. Sequence numbers stay scoped to the agent incarnation (`stream_id`).

## 3. PCAPng metadata (T2.5)

`pkg/sink` writes one PCAPng Interface Description Block per pod UID:

| Field | Value |
|-------|--------|
| Name | `namespace/name` |
| Comment / Description | `k8s.pod=… k8s.namespace=… k8s.node=…` |

Packets set `CaptureInfo.InterfaceIndex` to that IDB. gopacket v1.3.1 cannot write per-packet comments; IDB comments are the Wireshark-visible metadata. Classic PCAP (`*.pcap` / stdout) is unchanged.

## 4. Session stats (T2.7)

The hub accumulates packets/bytes (from ingested wire frames) and drops (from `CaptureBatch.dropped`) per session and per pod UID. A ticker emits `SessionEvent.stats`; `StopSession` emits a final snapshot. The CLI prints:

```text
stats: packets=N bytes=N dropped=N
stats: pod=NAME packets=N bytes=N dropped=N
```

## 5. E2e harness (T-TEST.4)

`test/e2e/kind.yaml` is 2-node. `run.sh` recreates leftover 1-node clusters and preloads `hashicorp/http-echo` so mid-session pods do not race an image pull.

Helpers live in `test/e2e/harness_test.go` (isolated namespaces, node pinning, event buffer, PCAPng IDB reader).

## 6. Tests

| Test | Layer |
|------|-------|
| `pkg/sink/pcap_test.go` | UT2.2 IDB comments |
| `pkg/hub/hub_test.go` | live attach hot-update; spawn/remove node agent; stats events |
| `pkg/agent/runner_test.go` | hot-add target without restarting the runner |
| `pkg/hub/hub_envtest_test.go` | **IT2.1** add pod on new node → second agent; delete → agent gone |
| `test/e2e/watch_test.go` | **E2E2.1**, E2E2.2, E2E2.6 |
| `test/e2e/multinode_test.go` | **E2E2.3** |
