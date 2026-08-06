# S2 — Agent pod lifecycle

**Task:** T1.7.

**Depends on:** [S2-agent-manifest.md](./S2-agent-manifest.md) (T1.6).

---

## 1. API

Package: `pkg/hub/agent`.

| Symbol | Role |
|--------|------|
| `NewManager(client, cfg)` | Lifecycle manager with `DefaultReadyTimeout` (2m) |
| `CreateForNode(ctx, sessionID, node, opts)` | Build manifest + `Pods.Create`; idempotent per `(session, node)` |
| `WaitReady(ctx, pod)` | Poll until Running with all containers Ready |
| `ListSessionAgents(ctx, sessionID)` | List by label selector |
| `DeleteSessionAgents(ctx, sessionID)` | `DeleteCollection` by label (fallback list+delete); grace period 0 |
| `SessionLabelSelector(sessionID)` | `app=k8s-sniffer-agent,sniffer.session=<id>` |
| `SessionNodeLabelSelector(sessionID, node)` | Session selector + `sniffer.node=<node>` |

## 2. Behaviour

- `CreateForNode` delegates manifest building to `PodManifest`.
- At most one agent per `(sessionID, nodeName)` via `sniffer.node` label + pre-check.
- `WaitReady` fails fast on terminal container reasons (`ImagePullBackOff`, etc.) and retriable API errors are retried.
- `DeleteSessionAgents` is idempotent (`NotFound` ignored per pod).
- `PodManifest` sets `activeDeadlineSeconds` when session duration is non-zero (crash-safety backstop; full ownerRef GC is Phase 4 in-cluster hub).
- `StopAll` on the hub (T1.8) calls `DeleteSessionAgents` on stop / signal.

## 3. Acceptance / testing

Unit tests cover create, idempotent re-create, wait ready, fast-fail paths, and delete.
IT1.1-style create/delete against the fake clientset lives in T1.8 `hub_test`.
Full envtest (T-TEST.3 / **IT1.1**) is in [S2-envtest-hub.md](./S2-envtest-hub.md).
`DeleteSessionAgents` uses grace period 0 (ephemeral agents).

Hub calls `CreateForNode` + `WaitReady` per `NodeGroup`, then records the
assignment for `WatchTargets`. Cleanup uses `DeleteSessionAgents` from
`StopSession` and `StopAll`.
