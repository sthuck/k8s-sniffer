# S1 — Repo skeleton, capture spec, wire API

**Tasks:** T1.1 (module + layout), T1.3 (shared types & config), T1.2 (protobuf + gRPC stubs).
T0.3's locked decisions are encoded as code defaults here rather than living only in prose.

**Tests covered:** UT1.1 (spec validation), UT1.6 (frame encode/decode).

---

## 1. Layout (T1.1)

```text
api/sniffer/v1/        *.proto + generated *.pb.go / *_grpc.pb.go (source-relative)
cmd/k8s-sniffer/       client entry point (stub until T1.14)
cmd/k8s-sniffer-agent/ per-node agent entry point (stub until T1.9-T1.12)
pkg/capture/           Spec, validation, proto conversion  <- no k8s/gRPC server logic
pkg/hub/               session lifecycle (placeholder, T1.4-T1.8)
pkg/agent/             netns + tcpdump pipeline (placeholder, T1.9-T1.12)
pkg/k8s/               kubeconfig/in-cluster client construction
specs/, docs/          output specs / planning docs
Makefile               build, test, vet, proto, proto-tools
```

Module: `github.com/sthuck/k8s-sniffer`, Go 1.22.

Dependency rule to preserve: `pkg/capture` is the only package every component
imports, so it stays free of client-go clients and gRPC servers (it imports
`apimachinery/util/validation` for DNS-label checks and the generated API types
for conversion only).

Both mains are deliberately non-functional: they support `--version` and
otherwise print which task implements them and exit 1. No cobra yet — the CLI
surface belongs to T1.14, so nothing here pre-empts its flag design.

### Toolchain

`protoc` is a system dependency; plugin versions are pinned in the Makefile and
installed into `./bin`:

```make
proto-tools:  go install protoc-gen-go@v1.34.2 protoc-gen-go-grpc@v1.5.1  (GOBIN=./bin)
proto:        protoc -I api --go_out=api --go-grpc_out=api --*_opt=paths=source_relative <all protos>
```

Generated code is committed so `go build ./...` works without protoc.

---

## 2. `capture.Spec` (T1.3)

```go
type Spec struct {
    Namespace   string        // required, DNS-1123 label
    PodPatterns []string      // >=1, RE2, unanchored, OR-ed
    BPFFilter   string        // tcpdump syntax, not locally validated
    Duration    time.Duration // 0 = until stopped
    Out         string        // file path or "-" (client-side only)
    Snaplen     uint32        // 0 = DefaultSnaplen (262144)
    Agent       AgentConfig
}

type AgentConfig struct {
    Namespace, Image, CRISocket string
    Unprivileged                bool
}
```

**T0.3 decisions as constants:** `DefaultAgentNamespace = "k8s-sniffer"`,
`DefaultAgentImage`, `DefaultCRISocket = unix:///run/containerd/containerd.sock`.

**`WithDefaults()`** fills unset optional fields and returns a copy (flags →
spec → defaults → validate). **`Validate()`** collects *all* problems via
`errors.Join` so a CLI user fixes flags once instead of iterating:

```text
namespace     non-empty AND IsDNS1123Label
pod patterns  >=1; each non-empty; each regexp.Compile ok   (index reported)
duration      >= 0
out           non-empty ("-" allowed)
snaplen       0 or >= 64 (MinSnaplen keeps L2..L4 headers intact)
agent         namespace DNS label, image non-empty, cri socket non-empty
bpf filter    NOT validated — only tcpdump can compile it (documented, not silently ignored)
```

**`CompilePatterns()`** returns the compiled regexps in order; the pod matcher
(T1.4) consumes this rather than compiling its own.

### Decision: privileged is expressed negatively

`securityContext.privileged` defaults to true (T0.3), so a plain
`Privileged bool` cannot distinguish "unset" from "explicitly disabled" —
defaulting would silently re-enable an opt-out. Recorded as `Unprivileged bool`
so the zero value *is* the default, with `AgentConfig.Privileged()` for
consumers (T1.6 manifest builder). On the wire the same problem is solved with
proto3 field presence: `optional bool agent_privileged`, absent = privileged.

---

## 3. `sniffer.v1` API (T1.2)

Five files under `api/sniffer/v1`, package `sniffer.v1`, Go package `snifferv1`.

### packet.proto

```text
PodRef      { namespace, name, uid, node, container_id }   // travels with every frame/event
PacketFrame { pod, source, timestamp, link_type, original_length, payload, sequence }
PacketBatch { session_id, node, repeated frames, dropped }
enum PacketSource { WIRE, TLS_PLAINTEXT }                  // plaintext reserved for phase 3
enum LinkType     { ETHERNET=1, RAW=101, LINUX_SLL=113, LINUX_SLL2=276 }
```

Choices worth keeping:

- `LinkType` values equal libpcap DLT numbers, so a sink passes them straight
  into a pcap/pcapng writer (T1.13) with no lookup table.
- `original_length` preserves pre-snaplen length, which pcap records require.
- `sequence` is a per-agent monotonic counter → the hub can detect gaps without
  trusting timestamps; `PacketBatch.dropped` carries kernel/tcpdump drop counts
  for T2.7 stats.
- Agents send **batches**, the hub fans out single **frames**: per-frame pod
  metadata would otherwise repeat on every packet.
- `session_id` lives on the batch, not the frame: it is transport context, not
  packet data, and subscribers already know their session.

### session.proto

```text
CaptureSpec  { namespace, pod_patterns, bpf_filter, duration, tls_mode, snaplen,
               agent_namespace, agent_image, agent_cri_socket, optional agent_privileged }
Session      { id, spec, state, created_at, stopped_at, nodes[], failure_reason }
enum SessionState { PENDING, STARTING, RUNNING, STOPPING, STOPPED, FAILED }
enum TlsMode      { OFF, EBPF, KEYLOG, AUTO }   // defined now, honoured from T3.1
```

`Out` is absent from the wire spec on purpose: sinks belong to whoever
subscribes to the session. That keeps a remote hub (Phase 4) from ever needing
filesystem access on behalf of a client. `Spec.ToProto()` therefore drops `Out`,
and the round-trip test asserts it does.

### event.proto

`SessionEvent { session_id, timestamp, severity, message, oneof payload }` with
payloads `SessionStateChanged | PodAttached | PodDetached | AgentStateChanged |
TlsStateChanged | SessionStats`. `message` is the human one-liner the CLI prints;
the payload is the machine-readable form a UI consumes (architecture §9.3).
`AgentPhase` and `TlsStatus` (`active|unsupported|denied|fallback`) are enums so
T3.6 has nothing to invent. Oneof tags start at 10 to leave room for envelope
fields.

### hub.proto — client-facing

```text
service HubService {
  CreateSession, StopSession, GetSession, ListSessions      // unary
  WatchEvents      -> stream SessionEvent                    // replay_history flag
  SubscribePackets -> stream PacketFrame                     // optional source filter
}
```

`GetSession`/`ListSessions` are included now (T4.6 needs them) because adding
RPCs later is cheap but changing message shapes is not.

### agent.proto — agent-facing

```text
Target          { pod, interfaces[], bpf_filter, tls_mode, snaplen }
AgentAssignment { session_id, node, targets[] }
service AgentIngestService {
  WatchTargets -> stream AgentAssignment   // hot target update, no agent respawn (T2.2)
  StreamPackets(stream PacketBatch) -> StreamPacketsResponse{accepted}
  ReportStatus(oneof agent_state|tls_state|stats|error)
}
```

Split from `HubService` so agent and human credentials can diverge when auth
lands (T4.5). `AgentAssignment` doubles as the bootstrap payload T1.9 expects as
"targets JSON" — protojson of this message, so there is one schema instead of an
ad-hoc JSON blob.

---

## 4. `pkg/k8s`

`k8s.New(ClientConfig{Kubeconfig, Context, Namespace, UserAgent}) (*Client, error)`
using `NewNonInteractiveDeferredLoadingClientConfig`, so in-cluster credentials
(Phase 4 hub) and a developer kubeconfig (Phase 1 CLI) resolve through one path.
`Client.DefaultNamespace` is returned so the CLI can default `--namespace` to
the kubeconfig context.

---

## 5. Tests

| Test | File | Proves |
|------|------|--------|
| UT1.1 | `pkg/capture/spec_test.go` | table-driven validation: empty/invalid namespace, no/empty/bad patterns, negative duration, missing out, small snaplen, agent fields; that all errors surface at once; defaults applied and explicit values (incl. the unprivileged opt-out) preserved |
| UT1.6 | `api/sniffer/v1/api_test.go` | `PacketFrame` marshal/unmarshal preserves pod metadata, timestamp, link type, payload, sequence; batch order and drop counter; every `SessionEvent` oneof payload round-trips |
| — | `pkg/capture/proto_test.go` | `Spec` ⇄ `CaptureSpec` round trip; `Out` dropped; zero duration stays absent; TLS forced off in phase 1; privileged presence semantics |
| — | `api/sniffer/v1/grpc_test.go` | generated stubs work over `bufconn`: unary + server-streaming call, `Unimplemented*` embedding satisfies the server interfaces and unimplemented RPCs return an error |

`go build ./...`, `go vet ./...`, `go test ./...` (also `-race`) and
`staticcheck ./...` are clean; `gofmt` reports no diffs.

---

## 6. Deviations & notes for the next tasks

- Task order followed the architecture's suggested slice (T1.1 → T1.3 → T1.2)
  rather than task-ID order.
- No cobra dependency yet; T1.14 owns CLI structure.
- `TlsMode` exists in the API but `Spec.ToProto()` hard-codes `TLS_MODE_OFF`;
  T3.1 replaces that with a real flag. Phase 1 hubs should treat any other mode
  as unsupported and keep wire capture running.
- Hub/agent packages are doc-only placeholders; the first real code (T1.4 pod
  matcher) should consume `Spec.CompilePatterns()` and emit `PodRef` values.
- CI (T-TEST.2) does not exist yet; `make all` is the local gate.
