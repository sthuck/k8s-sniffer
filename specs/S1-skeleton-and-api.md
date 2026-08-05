# S1 — Repo skeleton, capture spec, wire API

**Tasks:** T1.1 (module + layout), T1.3 (shared types & config), T1.2 (protobuf + gRPC stubs).
T0.3's locked decisions are encoded as code defaults here rather than living only in prose.

**Tests covered:** UT1.1 (spec validation), UT1.6 (frame encode/decode).

Revised after review of PR #5; §8 records what changed and why.

---

## 1. Layout (T1.1)

```text
api/sniffer/v1/        *.proto + generated *.pb.go / *_grpc.pb.go (source-relative)
cmd/k8s-sniffer/       client entry point (stub until T1.14)
cmd/k8s-sniffer-agent/ per-node agent entry point (stub until T1.9-T1.12)
pkg/capture/           Spec, SinkSpec, AgentConfig, validation, proto conversion
pkg/hub/               session lifecycle (placeholder, T1.4-T1.8)
pkg/agent/             netns + tcpdump pipeline (placeholder, T1.9-T1.12)
pkg/k8s/               kubeconfig/in-cluster client construction
specs/, docs/          output specs / planning docs
Makefile               build, verify (proto-check + vet + test), proto
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

`protoc` is a system dependency (`make require-protoc` fails with install
instructions); plugin versions are pinned in the Makefile and installed into
`./bin`:

```make
proto-tools:  go install protoc-gen-go@v1.34.2 protoc-gen-go-grpc@v1.5.1  (GOBIN=./bin)
proto:        protoc -I api --go_out=api --go-grpc_out=api --*_opt=paths=source_relative <all protos>
proto-check:  generate into a scratch dir; diff against api/; fail if different
verify:       proto-check + vet + test
```

Generated code is committed so `go build ./...` works without protoc. Committed
output can drift from the schema without breaking compilation, so `proto-check`
guards it and is part of the standard gate rather than a separate ritual.

---

## 2. Three types, three trust levels (T1.3)

The capture request, the client's sink, and the agent deployment settings are
separate types because they have different trust levels. Only `Spec` crosses the
hub API.

```go
type Spec struct {              // what a client may ask for; hub-validatable as received
    Namespace   string          // required, DNS-1123 label
    PodPatterns []string        // >=1, RE2, unanchored, OR-ed
    BPFFilter   string          // tcpdump syntax, not locally validated
    Duration    time.Duration   // 0 = until stopped
    Snaplen     uint32          // 0 = DefaultSnaplen (262144)
    TLSMode     TLSMode
}

type SinkSpec struct {          // never leaves the client
    Out string                  // path or "-"
}

type AgentConfig struct {       // operator/hub config; never from a client
    Namespace, Image, CRISocketHostPath string
    Unprivileged, AllowMutableImage     bool
}
```

Each type has its own `WithDefaults()` and `Validate()`. `Spec.Validate()`
collects *all* problems via `errors.Join` so a CLI user fixes flags once instead
of iterating:

```text
namespace     non-empty AND IsDNS1123Label
pod patterns  >=1; each non-empty; each regexp.Compile ok   (index reported)
duration      >= 0
snaplen       0 or >= 64 (MinSnaplen keeps L2..L4 headers intact)
tls mode      known value; rejected unless implemented (see below)
bpf filter    NOT validated — only tcpdump can compile it (documented, not silently ignored)
```

Keeping `Out` out of `Spec` matters beyond tidiness: the natural T1.8 path is
`SpecFromProto(req.Spec).Validate()`, and a shared required-`Out` rule would
fail every valid `CreateSession` request, or push the hub into fabricating a sink
it should not own. A test asserts a spec built from the wire validates as-is.

**`CompilePatterns()`** returns the compiled regexps in order; the pod matcher
(T1.4) consumes this rather than compiling its own.

### T0.3 defaults, and the two representation traps

`DefaultAgentNamespace = "k8s-sniffer"`, `DefaultCRISocketPath =
"/run/containerd/containerd.sock"`, privileged agents.

**Privileged is expressed negatively.** `securityContext.privileged` defaults to
true, so a plain `Privileged bool` cannot distinguish "unset" from "explicitly
disabled" and defaulting would silently re-enable an opt-out. Recorded as
`Unprivileged bool` so the zero value *is* the default, with
`AgentConfig.Privileged()` for consumers (T1.6 manifest builder).

**The CRI socket is a path, not a URI.** `/run/containerd/containerd.sock` is the
`hostPath` volume source; `unix:///run/containerd/containerd.sock` is what a CRI
client dials. One field cannot be both — feeding the URI into a `hostPath`
manifest silently mounts nothing useful. Stored as `CRISocketHostPath` (validated
absolute, rejected if it contains `://`) with `CRIEndpoint()` deriving the dial
URI. Host and in-container paths coincide because the socket is mounted at the
same location.

**The agent image is not defaulted to a mutable tag.** Agents run privileged with
host and CRI access, so a `:dev`-style default means an overwritten tag changes
what executes as root on a node with no source or config change. There is no
baked-in default: `agentImageRef` is injected at link time
(`-X …/pkg/capture.agentImageRef=REF`, `make build AGENT_IMAGE=…`) with the
digest-pinned image for that release, and is empty in development builds so the
image must be passed explicitly. `Validate()` requires a digest-pinned reference
unless `AllowMutableImage` is set, which is the explicit escape hatch for kind/e2e
flows that load a locally built tag.

### TLS mode is preserved, not downgraded

`TLSMode` is an `int32` enum whose values mirror `sniffer.v1.TlsMode`, so
conversion is a plain cast in both directions and no value can be lost in
translation (a test asserts the numbering matches). `WithDefaults()` maps
unspecified to `off`. `Validate()` rejects unknown values, and rejects known but
unimplemented ones:

```text
off     -> accepted
ebpf | keylog | auto -> error "not implemented yet (T3.1); only off is supported"
```

Rejecting is the point: accepting `auto` today and quietly returning an
encrypted-only capture would look like success. T3.1 flips `Implemented()` and
the default.

---

## 3. `sniffer.v1` API (T1.2)

Six files under `api/sniffer/v1`, package `sniffer.v1`, Go package `snifferv1`.

### packet.proto

```text
PodRef      { namespace, name, uid, node, container_id }   // travels with every frame/event
PacketFrame { pod, source, timestamp, link_type, original_length, payload, sequence }
enum PacketSource { WIRE, TLS_PLAINTEXT }   // plaintext = synthetic frame (T3.8) only
enum LinkType     { ETHERNET=1, RAW=101, LINUX_SLL=113, LINUX_SLL2=276 }
```

- `LinkType` values equal libpcap DLT numbers, so a sink passes them straight
  into a pcap/pcapng writer (T1.13) with no lookup table.
- `original_length` preserves pre-snaplen length, which pcap records require.
- `sequence` is monotonic **within a stream id** (see agent.proto) — not per node
  and not per session.

### record.proto — the stream envelope

```text
TlsPlaintextEvent { pod, timestamp, direction, payload, connection_id, pid,
                    process, tls_library, sequence }
CaptureRecord     { oneof { PacketFrame wire_frame; TlsPlaintextEvent tls_event } }
enum RecordKind { WIRE_FRAME, TLS_EVENT }
enum Direction  { OUTBOUND, INBOUND }   // crypto-boundary side
```

Subscribers receive `CaptureRecord`, never a bare frame. TLS plaintext carries
things a packet frame cannot model — which side of the crypto boundary, process
and connection identity, which TLS stack was hooked — so Phase 3 would otherwise
need a breaking return-type change or a parallel subscription API with duplicate
client plumbing. Phase 1 only ever emits `wire_frame`; the envelope costs two
bytes per record now and buys additive evolution later.

### session.proto

```text
CaptureSpec  { namespace, pod_patterns, bpf_filter, duration, tls_mode, snaplen }
             reserved 7-10 (formerly agent_namespace/image/cri_socket/privileged)
Session      { id, spec, state, created_at, stopped_at, nodes[], failure_reason }
enum SessionState { PENDING, STARTING, RUNNING, STOPPING, STOPPED, FAILED }
enum TlsMode      { OFF, EBPF, KEYLOG, AUTO }   // defined now, honoured from T3.1
```

**Agent deployment settings are not session inputs.** `CreateSession` is the
capture-permission boundary; accepting an image, CRI socket path and privileged
flag there would let anyone who may start a capture run caller-chosen code as
root on a node once the hub is network-accessible (ARCHITECTURE §9) — capture
permission escalating to node-root execution. The fields are removed (numbers and
names `reserved`, which documents the removal and blocks accidental reuse) and
live in the hub's own `AgentConfig`. If per-session variation is ever needed, the
extension is an operator-defined profile id resolved server-side against the
hub's allowlist — never the values themselves. A test walks the descriptor and
fails if any of those field names reappears.

`Out` is likewise absent: sinks belong to whoever subscribes, so a remote hub
never needs filesystem access on a client's behalf.

### event.proto

`SessionEvent { session_id, timestamp, severity, message, oneof payload }` with
payloads `SessionStateChanged | PodAttached | PodDetached | AgentStateChanged |
TlsStateChanged | SessionStats | CaptureError`. `message` is the human one-liner
the CLI prints; the payload is the machine-readable form a UI consumes
(architecture §9.3).

```text
CaptureError { stage, reason, detail, retryable, pod, node, agent_pod, stream_id }
enum ErrorStage  { DISCOVERY, AGENT_SCHEDULING, NETNS_RESOLVE, CAPTURE_START,
                   CAPTURE_STREAM, TLS_ATTACH, SINK_WRITE, TEARDOWN }
enum ErrorReason { INVALID_ARGUMENT, NOT_FOUND, PERMISSION_DENIED, UNSUPPORTED,
                   TIMEOUT, RESOURCE_EXHAUSTED, TOOL_FAILED, INTERNAL }
```

Failures are the events users act on, so they are typed like everything else: a
netns-resolve or tcpdump failure names the affected pod, node and agent, carries
a stable stage/reason pair and a retryability hint, and keeps prose in `detail`.
The same message is used on the agent channel, so there is one error shape in the
system rather than a structured client event and a free-form agent string.

`AgentPhase` and `TlsStatus` (`active|unsupported|denied|fallback`) are enums so
T3.6 has nothing to invent. Oneof tags start at 10 to leave room for envelope
fields.

### hub.proto — client-facing

```text
service HubService {
  CreateSession, StopSession, GetSession, ListSessions      // unary
  WatchEvents      -> stream SessionEvent                    // replay_history flag
  SubscribePackets -> stream CaptureRecord                   // optional RecordKind filter
}
```

`GetSession`/`ListSessions` are included now (T4.6 needs them) because adding
RPCs later is cheap but changing message shapes is not.

### agent.proto — agent-facing

```text
Target          { pod, interfaces[], bpf_filter, tls_mode, snaplen }
AgentAssignment { session_id, node, stream_id, targets[] }
CaptureBatch    { session_id, node, stream_id, records[], dropped }
service AgentIngestService {
  WatchTargets  -> stream AgentAssignment   // hot target update, no agent respawn (T2.2)
  StreamCapture(stream CaptureBatch) -> StreamCaptureSummary{records_accepted}
  ReportStatus(oneof agent_state|tls_state|stats|CaptureError)
}
```

**`stream_id` identifies an agent incarnation**, minted by the hub per
assignment. T2.3 deletes and recreates agents as targets move between nodes, and
a replacement agent restarts its counters — session+node alone cannot tell a
fresh counter from a gap, nor discard records from a superseded agent whose
stream briefly overlaps its replacement. Sequence checks are scoped to
`stream_id`, which the assignment and every batch carry.

**`StreamCaptureSummary` is an end-of-stream tally only.** `StreamCapture` is
client-streaming, so its single response arrives after the agent closes its send
side and cannot inform a running agent about anything. Backpressure is gRPC flow
control, and hub-side drops are reported over `ReportStatus`/`SessionStats` while
the capture runs; the message says so rather than implying live acknowledgement.

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
| UT1.1 | `pkg/capture/spec_test.go` | table-driven validation of `Spec`, `SinkSpec` and `AgentConfig`: namespace, patterns, duration, snaplen, TLS mode (unset / unknown / unimplemented), image required + digest-pinned, CRI path absolute and not a URI; all errors surface at once; defaults applied and explicit values (including the unprivileged opt-out) preserved |
| UT1.6 | `api/sniffer/v1/api_test.go` | `PacketFrame` round trip preserves pod metadata, timestamp, link type, payload, sequence; batch order, drop counter and `stream_id`; both `CaptureRecord` arms; every `SessionEvent` oneof payload including `CaptureError`; agent-channel errors keep pod scope and reason |
| — | `pkg/capture/proto_test.go` | `Spec` ⇄ `CaptureSpec` round trip; Go/proto TLS enum numbering matches; no TLS mode (including unknown values) is lost or downgraded; zero duration stays absent; descriptor carries no agent deployment fields |
| — | `api/sniffer/v1/grpc_test.go` | generated stubs work over `bufconn`: unary + server-streaming call, `Unimplemented*` embedding satisfies the server interfaces, unimplemented RPCs return an error |

`make verify` (proto-check, vet, test), `go test -race ./...`,
`staticcheck ./...` and `gofmt` are all clean. The `proto-check` guard was
verified by hand: mutating a `.proto` without regenerating fails the target.

---

## 6. Deviations from the planning docs

- Task order followed the architecture's suggested slice (T1.1 → T1.3 → T1.2)
  rather than task-ID order.
- ARCHITECTURE §5.2 sketches `SubscribePackets -> PacketFrame stream`; it returns
  `CaptureRecord` instead, for the reason in §3. The RPC name is unchanged.
- ARCHITECTURE §7.1 puts `session_id` on `PacketFrame`; it lives on
  `CaptureBatch` instead — transport context, not packet data, and subscribers
  already know their session.
- No cobra dependency yet; T1.14 owns CLI structure.

## 7. Notes for the next tasks

- T1.4 pod matcher: consume `Spec.CompilePatterns()`, emit `PodRef` values.
- T1.6 manifest builder: use `AgentConfig.CRISocketHostPath` as the `hostPath`
  source and `AgentConfig.Privileged()` for the security context; the CLI needs
  an `--agent-image` flag because dev builds have no default.
- T1.8 hub: `SpecFromProto(req.Spec).WithDefaults().Validate()`, mint a
  `stream_id` per agent incarnation, and emit `CaptureError` rather than logging.
- T1.13 sink: read `Spec`/`SinkSpec` separately; switch on `CaptureRecord` kind
  so the Phase 3 plaintext sink slots in.
- CI (T-TEST.2) does not exist yet; `make verify` is the local gate.

## 8. Review follow-ups (PR #5)

| Finding | Resolution |
|---------|------------|
| Client-controlled agent image / CRI socket / privileged mode escalates capture permission to node-root | Removed from `CaptureSpec` (numbers + names `reserved`); moved to hub-side `AgentConfig`; descriptor test prevents regression |
| `stream PacketFrame` locks the subscription into wire-packet semantics | Added `CaptureRecord` envelope with a `TlsPlaintextEvent` arm; `SubscribePackets` and `CaptureBatch` carry records |
| Failures were a free-form string with no typed event | Added `CaptureError` (stage, reason, detail, retryable, pod/node/agent/stream scope) to both `SessionEvent` and `ReportStatusRequest` |
| Mutable `:dev` default image for a privileged agent | No baked-in default; link-time digest-pinned ref per release; validation requires a digest unless `AllowMutableImage` |
| Shared `Out` validation would reject valid wire requests | Split `SinkSpec` out of `Spec`; test asserts a wire spec validates unchanged |
| `tls_mode` silently discarded on inbound requests | `Spec.TLSMode` mirrors the proto enum numerically; unimplemented modes are rejected explicitly |
| CRI socket mixed a dial URI with a node path | `CRISocketHostPath` (validated absolute, URI rejected) + derived `CRIEndpoint()` |
| Stale committed protobuf output was undetectable | `make proto-check` regenerates into a scratch tree and diffs; part of `make verify` |
| `sequence` identity did not survive agent replacement | Hub-minted `stream_id` on `AgentAssignment`, `CaptureBatch` and `CaptureError`; sequences scoped to it |
| `StreamPackets` ack unobservable during capture | Renamed to `StreamCapture` with `StreamCaptureSummary` documented as an end-of-stream tally; live drops go over `ReportStatus`/`SessionStats` |
