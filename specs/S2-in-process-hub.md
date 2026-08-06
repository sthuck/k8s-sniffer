# S2 — In-process Hub

**Task:** T1.8.

**Depends on:** [S2-agent-lifecycle.md](./S2-agent-lifecycle.md) (T1.7).

**Tests covered:** IT1.1-style (fake clientset), foundation for IT1.2.

---

## 1. API

Package: `pkg/hub`.

```go
type Options struct {
    Kubernetes   kubernetes.Interface
    Agent        capture.AgentConfig
    ReadyTimeout time.Duration
}

func New(opts Options) (*Hub, error)
func (h *Hub) StopAll(ctx context.Context) error
```

`Hub` embeds `UnimplementedHubServiceServer` and
`UnimplementedAgentIngestServiceServer`. Register both on the same gRPC server.

## 2. CreateSession flow

1. `SpecFromProto(req.Spec).WithDefaults().Validate()` — `InvalidArgument` on failure.
2. Mint `session_id` (UUID).
3. `ListMatchingPods` → `GroupByNode`.
4. Emit warning `CaptureError` events for skipped pods (no `nodeName`).
5. Emit `PodAttached` for each matched target.
6. Per `NodeGroup`: `CreateForNode` → `WaitReady` → mint `stream_id` → store
   `AgentAssignment` (targets carry bpf/snaplen/tls from spec).
7. Transition `PENDING` → `STARTING` → `RUNNING` (or `FAILED` on error, with
   agent cleanup).

## 3. StopSession flow

`STOPPING` → `DeleteSessionAgents` → `STOPPED` → remove session from store.

`StopAll` stops every active session (for Ctrl-C before T1.14).

## 4. Session lifecycle

- Per-session `lifecycleMu` serializes `startSession` and `stopSession`.
- Session context is cancelled on stop so in-flight agent creates observe cancellation.
- `FAILED` sessions are removed from the store after emitting events.
- `snapshot()` returns `proto.Clone` of session state.

## 5. Empty discovery

`CreateSession` fails when no schedulable node groups exist (no running matches).

## 6. Notes for T1.9+

| RPC | Phase 1 behaviour |
|-----|-------------------|
| `WatchEvents` | Replay buffer + live fan-out; closes on session stop |
| `SubscribePackets` | Blocks until session stop (fan-out in T1.12) |
| `WatchTargets` | Sends initial `AgentAssignment`, blocks until stop |
| `StreamCapture` | Ingests `CaptureBatch`es; fans wire frames to `SubscribePackets` (T1.12) |
| `ReportStatus` | No-op ack |

## 5. Notes for T1.9+

- Agent bootstrap calls `WatchTargets` to receive targets + `stream_id`.
- T1.12 wires `StreamCapture` → `SubscribePackets` fan-out.
- T1.14 embeds this hub in-process over `bufconn` or loopback gRPC.
