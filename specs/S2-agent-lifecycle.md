# S2 — Agent pod lifecycle

**Task:** T1.7.

**Depends on:** [S2-agent-manifest.md](./S2-agent-manifest.md) (T1.6).

---

## 1. API

Package: `pkg/hub/agent`.

| Symbol | Role |
|--------|------|
| `NewManager(client, cfg)` | Lifecycle manager with `DefaultReadyTimeout` (2m) |
| `CreateForNode(ctx, sessionID, node)` | Build manifest + `Pods.Create` |
| `WaitReady(ctx, pod)` | Poll until Running with all containers Ready |
| `ListSessionAgents(ctx, sessionID)` | List by label selector |
| `DeleteSessionAgents(ctx, sessionID)` | Delete all session agents |
| `SessionLabelSelector(sessionID)` | `app=k8s-sniffer-agent,sniffer.session=<id>` |

## 2. Behaviour

- `CreateForNode` delegates manifest building to `PodManifest`.
- `WaitReady` fails if the pod enters Failed/Succeeded or the timeout expires.
- `DeleteSessionAgents` is idempotent (`NotFound` ignored per pod).
- `StopAll` on the hub (T1.8) calls `DeleteSessionAgents` on stop / signal.

## 3. Notes for T1.8

Hub calls `CreateForNode` + `WaitReady` per `NodeGroup`, then records the
assignment for `WatchTargets`. Cleanup uses `DeleteSessionAgents` from
`StopSession` and `StopAll`.
