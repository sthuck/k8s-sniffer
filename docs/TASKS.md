# Task breakdown

Granular work items derived from [ARCHITECTURE.md](./ARCHITECTURE.md).  
Testing layers, kind/k3s matrix, and per-phase test IDs: [TESTING.md](./TESTING.md).  
Each task should be independently reviewable; dependencies are listed explicitly.

**Legend**

| Tag | Meaning |
|-----|---------|
| `size:S` | Small — one focused change, few files |
| `size:M` | Medium — one subsystem, clear boundary |
| `size:L` | Large — cross-cutting; consider splitting further if it grows |
| `depends:` | Must complete first |

---

## Phase 0 — Foundations (done / almost done)

| ID | Task | Size | Notes |
|----|------|------|-------|
| T0.1 | Architecture doc | S | Done — `docs/ARCHITECTURE.md` |
| T0.2 | Task breakdown | S | This document |
| T0.3 | Lock Phase-1 open decisions | S | Agent namespace = `k8s-sniffer` (flag override); privileged agents; containerd-first CRI path |

---

## Phase 1 — MVP wire sniffer

Goal: `k8s-sniffer capture -n NS --pod REGEX -o out.pcap` works for multiple pods, no TLS.

### 1A. Repo & API skeleton

| ID | Task | Size | Depends | Acceptance |
|----|------|------|---------|------------|
| T1.1 | Go module + layout (`cmd/`, `pkg/hub/`, `pkg/agent/`, `pkg/k8s/`, `api/`) | S | T0.3 | `go build ./...` succeeds; empty mains compile |
| T1.2 | Protobuf: `Session` / `PacketFrame` / `SessionEvent` + gRPC service stubs | M | T1.1 | Generated Go code; `CreateSession`, `StopSession`, `WatchEvents`, `SubscribePackets` defined |
| T1.3 | Shared types & config (`CaptureSpec`: namespace, regexes, bpf filter, duration, out path) | S | T1.1 | Spec validated (compile regexes, require namespace) |

### 1B. Discovery & scheduling (Hub, local)

| ID | Task | Size | Depends | Acceptance |
|----|------|------|---------|------------|
| T1.4 | Pod matcher: list pods in namespace, filter by name regex(es) | S | T1.3 | Unit tests for match/non-match; Running-only filter |
| T1.5 | Node grouping: map matched pods → `nodeName` | S | T1.4 | Empty nodeName pods skipped with event |
| T1.6 | Agent pod manifest builder (privileged, `nodeName`, labels, session id) | M | T1.5 | Golden/YAML snapshot test of generated Pod spec |
| T1.7 | Agent lifecycle: create agents, wait Ready, delete on stop / signal | M | T1.6 | Integration test vs envtest or documented kind script; Ctrl-C cleans up |
| T1.8 | In-process Hub: `CreateSession` wires T1.4–T1.7 | M | T1.2, T1.7 | Session id returned; stop deletes agents |

### 1C. Agent capture path

| ID | Task | Size | Depends | Acceptance |
|----|------|------|---------|------------|
| T1.9 | Agent bootstrap: connect to Hub (or stdin/stdout pipe for MVP), receive target list | M | T1.2 | Agent starts with env/args: session id, hub address, targets JSON |
| T1.10 | Resolve container → netns (containerd socket path configurable) | L | T1.9 | Given containerID, opens correct netns on kind/containerd |
| T1.11 | Run `tcpdump` in netns (`nsenter` or equivalent), stdout = pcap stream | M | T1.10 | Capture of known traffic (e.g. curl between pods) produces readable packets |
| T1.12 | Frame & stream packets to Hub (`PacketFrame` with pod metadata) | M | T1.9, T1.11 | Hub receives tagged frames for ≥2 pods on same or different nodes |

### 1D. Client sink & CLI

| ID | Task | Size | Depends | Acceptance |
|----|------|------|---------|------------|
| T1.13 | PCAPng/PCAP writer sink (file + stdout `-`) | M | T1.2 | Wireshark/tshark opens file; stdout pipes to `wireshark -k -i -` |
| T1.14 | CLI `capture` command (cobra): flags → in-process Hub → sink | M | T1.8, T1.13 | End-to-end on kind: multi-pod regex capture to file |
| T1.15 | Agent container image + Makefile/Dockerfile | M | T1.11 | Image builds; includes static tcpdump; documented load into kind |
| T1.16 | RBAC manifests (ClusterRole/Role for capture SA or docs for user kubeconfig) | S | T1.7 | Documented minimum verbs; example YAML |
| T1.17 | Kind smoke test script / CI job | M | T1.14, T1.15 | **E2E1.1** green (see TESTING.md); harness under `test/e2e/` |

### 1E. Testing infrastructure (Phase 1)

| ID | Task | Size | Depends | Acceptance |
|----|------|------|---------|------------|
| T-TEST.1 | E2e harness scaffold (`test/e2e`, kind config, HTTP fixtures) | M | T1.15 | `./test/e2e/run.sh kind` brings cluster, loads image, runs Go e2e package |
| T-TEST.2 | CI: unit + integration + e2e-kind workflows | M | T-TEST.1, T1.17 | PR checks run `go test ./...` and kind E2E1.1 |
| T-TEST.3 | envtest setup for Hub agent lifecycle | M | T1.7 | **IT1.1** passes without kind |
| T-TEST.7 | E2e failure artifacts (pcap, agent logs, cluster dump) | S | T-TEST.2 | Failed CI uploads artifacts |

**Phase 1 exit:** T1.14 + T1.17 + **E2E1.1** (and ideally E2E1.3) green. TLS explicitly out of scope.

---

## Phase 2 — Multi-pod polish

| ID | Task | Size | Depends | Acceptance |
|----|------|------|---------|------------|
| T2.1 | Live pod watch: attach new matches, detach deleted pods mid-session | M | T1.8 | Event stream shows attach/detach; pcap gains new pod traffic |
| T2.2 | Per-node agent target hot-update (add/remove netns captures without respawn if possible) | M | T2.1, T1.12 | Adding a pod on an existing node does not recreate agent pod |
| T2.3 | Spawn agent when first pod appears on a new node; remove agent when last target leaves | M | T2.1 | Agent count tracks active nodes |
| T2.4 | `--bpf` / capture filter passed through to tcpdump | S | T1.11 | Filter reduces captured volume in test |
| T2.5 | PCAPng packet comments / IDBs with `k8s.pod`, `k8s.namespace`, `k8s.node` | M | T1.13 | Metadata visible in Wireshark or via `capinfos`/custom reader |
| T2.6 | `--split-per-pod` optional sink mode | S | T1.13 | N files for N pods |
| T2.7 | Session stats events: packets, bytes, drops, per-pod counters | M | T1.8, T1.12 | CLI prints periodic stats; events on WatchEvents |
| T2.8 | `--duration` hard stop + graceful drain | S | T1.14 | Session ends cleanly after duration |
| T-TEST.4 | 2-node kind config + e2e helpers | S | T-TEST.1 | **E2E2.3** can schedule pods on distinct nodes |

**Phase 2 testing exit:** **E2E2.1** + **E2E2.3** + E2E2.5 required in CI (see TESTING.md).

---

## Phase 3 — TLS

| ID | Task | Size | Depends | Acceptance |
|----|------|------|---------|------------|
| T3.1 | TLS mode flags: `off` / `ebpf` / `keylog` / `auto` | S | T1.14 | Invalid mode rejected; default `auto` |
| T3.2 | Vendor/package ecapture (or chosen TLS worker) into agent image | M | T1.15 | Binary present; version pinned; license noted |
| T3.3 | Agent TLS worker supervisor: start/stop per target PID/lib | L | T3.2, T1.10 | Attaches to OpenSSL test workload; emits plaintext events |
| T3.4 | `TlsPlaintextEvent` protobuf + stream multiplex with wire frames | M | T1.2, T3.3 | Subscribe API delivers both sources |
| T3.5 | JSONL sink for TLS plaintext (`--tls-out`) | M | T3.4 | File contains request/response payloads for HTTPS test app |
| T3.6 | Per-pod TLS status events (`active` / `unsupported` / `denied` / `fallback`) | S | T3.3 | CLI shows status; `auto` continues wire capture on failure |
| T3.7 | Keylog fallback: accept `--keylog-file` and document SSLKEYLOGFILE | M | T3.1 | Wireshark decrypts with provided keylog + wire pcap |
| T3.8 | Optional: convert TLS events → synthetic PCAP for Wireshark-only users | L | T3.5 | Deferred if JSONL sufficient |
| T3.9 | Kind TLS e2e: nginx/openssl app + assert plaintext sink non-empty | M | T3.5, T-TEST.5 | **E2E3.1** green (`e2e_tls` tag) |
| T-TEST.5 | HTTPS/OpenSSL fixture + `e2e_tls` build tag | M | T-TEST.1 | Fixture emits known plaintext marker for assertions |

**Phase 3 exit:** `auto` works on a supported OpenSSL workload; **E2E3.1** (or documented CI skip + nightly) + E2E3.3/E2E3.4; unsupported stacks degrade gracefully.

---

## Phase 4 — Hub extraction

| ID | Task | Size | Depends | Acceptance |
|----|------|------|---------|------------|
| T4.1 | Hub runnable as standalone binary / Deployment | M | T1.8 | Same gRPC API as in-process |
| T4.2 | Helm chart or raw manifests (Hub + SA + RBAC + Service) | M | T4.1 | `helm install` / `kubectl apply` brings Hub up |
| T4.3 | CLI `--hub` flag: remote vs in-process | S | T4.1 | Capture works against remote Hub |
| T4.4 | Multi-subscriber: two clients SubscribePackets on one session | M | T4.1 | Both receive frames; one disconnect does not stop session |
| T4.5 | Authn stub (kubeconfig / bearer token) on Hub API | M | T4.1 | Unauthenticated rejected when auth enabled |
| T4.6 | Session list / get APIs for future UI | S | T4.1 | `ListSessions` returns active sessions |

**Phase 4 testing exit:** **E2E4.1** + E2E4.2 (remote Hub capture + multi-subscriber).

---

## Phase 5 — UI (deferred)

| ID | Task | Size | Depends | Acceptance |
|----|------|------|---------|------------|
| T5.1 | Choose UI stack + thin Hub HTTP/JSON gateway if needed | M | T4.6 | Gateway mirrors session APIs |
| T5.2 | Session create/stop views (namespace, regex, TLS mode) | M | T5.1 | Creates real Hub session |
| T5.3 | Live pod/agent health panel from WatchEvents | M | T5.2 | Reflects attach/detach |
| T5.4 | Live TLS/event feed (plaintext JSONL consumer) | L | T5.2, T3.5 | Scrollable event list |
| T5.5 | PCAP download button | S | T5.2 | Downloads same bytes as CLI `--out` |

Do not start Phase 5 until Phase 3 is usable and Phase 4 Hub is stable.

---

## Cross-phase / optional testing

| ID | Task | Phase | Size | Depends | Acceptance |
|----|------|-------|------|---------|------------|
| T-TEST.6 | Optional k3s e2e job (nightly/manual) | after 1 | M | T-TEST.1 | **E2E1.1** passes on k3s; socket path documented |

Full matrix and assertion cookbook: [TESTING.md](./TESTING.md).

---

## Suggested implementation order (first slice)

Execute in this order for the shortest path to a demoable MVP:

```text
T0.3 → T1.1 → T1.3 → T1.2
     → T1.4 → T1.5 → T1.6 → T1.7 (+ T-TEST.3) → T1.8
     → T1.9 → T1.10 → T1.11 → T1.12
     → T1.13 → T1.15 → T1.14 → T1.16
     → T-TEST.1 → T1.17 → T-TEST.2 → T-TEST.7
```

Parallelizable after T1.1:

- API protobuf (T1.2) ∥ discovery (T1.4–T1.5)
- Agent capture (T1.9–T1.11) ∥ Hub scheduling (T1.6–T1.8) once T1.2 exists
- Image/RBAC (T1.15–T1.16) ∥ CLI sink wiring (T1.13–T1.14)
- envtest (T-TEST.3) ∥ agent capture work

---

## Tracking conventions

- One PR ≈ one task ID (or a small tightly coupled pair, e.g. T1.4+T1.5).
- PR title prefix: `[T1.4] pod name regex matcher`.
- Update this table’s status in PRs that complete a task (`done` in a checkbox list below as work lands).
- Each landed slice gets an output spec in [`specs/`](../specs/README.md) describing how it was built.

### Phase 1 checklist

- [x] T1.1 Repo layout — [specs/S1-skeleton-and-api.md](../specs/S1-skeleton-and-api.md)
- [x] T1.2 Protobuf/gRPC stubs — [specs/S1-skeleton-and-api.md](../specs/S1-skeleton-and-api.md)
- [x] T1.3 CaptureSpec — [specs/S1-skeleton-and-api.md](../specs/S1-skeleton-and-api.md)
- [x] T1.4 Pod matcher — [specs/S2-pod-matcher.md](../specs/S2-pod-matcher.md)
- [x] T1.5 Node grouping — [specs/S2-node-grouping.md](../specs/S2-node-grouping.md)
- [x] T1.6 Agent manifest — [specs/S2-agent-manifest.md](../specs/S2-agent-manifest.md)
- [x] T1.7 Agent lifecycle — [specs/S2-agent-lifecycle.md](../specs/S2-agent-lifecycle.md)
- [x] T1.8 In-process Hub — [specs/S2-in-process-hub.md](../specs/S2-in-process-hub.md)
- [ ] T1.9 Agent bootstrap
- [ ] T1.10 Netns resolve
- [ ] T1.11 tcpdump in netns
- [ ] T1.12 Frame stream to Hub
- [ ] T1.13 PCAP sink
- [ ] T1.14 CLI capture
- [ ] T1.15 Agent image
- [ ] T1.16 RBAC docs/manifests
- [ ] T1.17 Kind smoke test
- [ ] T-TEST.1 E2e harness
- [ ] T-TEST.2 CI workflows — interim `unit`/`make verify` gate in [`.github/workflows/verify.yml`](../.github/workflows/verify.yml); full unit+integration+e2e still open
- [ ] T-TEST.3 envtest Hub lifecycle
- [ ] T-TEST.7 E2e artifacts
