# Logging conventions

k8s-sniffer uses Go's standard [`log/slog`](https://pkg.go.dev/log/slog) package for structured logging. There are exactly **two** verbosity levels:

| Level | Slog constant | Purpose |
|-------|---------------|---------|
| **info** | `slog.LevelInfo` | **What happened** — outcomes a human or operator cares about |
| **debug** | `slog.LevelDebug` | **How it happened** — internals useful when diagnosing failures |

There is no separate `error` level. Return errors to callers; at operational boundaries log at **info** with an `err` attribute (or `slog.String("err", err.Error())`).

Default verbosity is **info**. Set **debug** when troubleshooting scheduling, discovery, or Kubernetes API interactions.

---

## Configuration

### Environment variable

```bash
export K8S_SNIFFER_LOG_LEVEL=debug   # info | debug (default: info)
```

Constant: `log.EnvLevel` (`K8S_SNIFFER_LOG_LEVEL`).

### CLI flag

Both binaries accept `--log-level`, which overrides the environment variable:

```bash
k8s-sniffer --log-level=debug ...
k8s-sniffer-agent --log-level=debug ...
```

**Agent pods:** the hub does not yet inject log level into agent container env (T1.9 agent bootstrap). Until then, set `K8S_SNIFFER_LOG_LEVEL` on the pod spec manually if you need debug logs from a running agent.

### JSON output

`log.Config.JSON` enables JSON-formatted logs programmatically. There is no env/flag for format yet; text on stderr is the default. JSON env/flag support (`K8S_SNIFFER_LOG_FORMAT`) is deferred until in-cluster e2e needs log scraping (Phase 1 agent path).

### Programmatic init

Library and test code should call `log.Init` before exercising components that log:

```go
import "github.com/sthuck/k8s-sniffer/pkg/log"

log.Init(log.Config{Level: log.LevelDebug}) // optional Writer, JSON
```

`log.InitFromEnv()` reads `K8S_SNIFFER_LOG_LEVEL` only (no flag) and returns a parse error for invalid values.

---

## Package layout

| Path | Role |
|------|------|
| `pkg/log` | Process-wide slog setup, level parsing, `WithComponent` helper |

Do **not** import `log/slog` only to call `slog.SetDefault` from feature code — go through `pkg/log` so level and format stay consistent.

---

## Writing log lines

### Component attribute

Every package that logs should define one package-level logger. `WithComponent` delegates to `slog.Default()` at log time, so this is safe before `Init()` in `main`:

```go
var hubLog = log.WithComponent("hub")
```

Call `log.Init` (or `InitFromEnv`) as early as possible in `main` so the default handler is configured before any work runs.

Use stable, grep-friendly names: `hub`, `agent`, `discovery`, `k8s`, `cli`.

### Info — what happened

Log durable facts and lifecycle transitions:

- Session created, running, stopped, or failed
- Agent pod created, reused, ready, or deleted
- Kubernetes client ready
- Process start (`cli`, `agent` mains)

Example:

```go
hubLog.Info("session running",
    slog.String("session_id", sessionID),
    slog.Int("nodes", len(nodes)),
)
```

When an operation fails but the RPC still returns a structured response, log at info with `err`:

```go
hubLog.Info("session create failed",
    slog.String("session_id", sessionID),
    slog.String("err", err.Error()),
)
```

### Debug — how it happened

Log steps, counts, selectors, and polling detail:

- Pod list sizes before/after filtering
- Label selectors and namespace
- Wait/poll loops (start, not every tick)
- Hub initialization parameters

Example:

```go
discoveryLog.Debug("filtered matching running pods",
    slog.String("namespace", namespace),
    slog.Int("matched", len(matched)),
)
```

### Attributes

- Prefer typed `slog` attributes (`slog.String`, `slog.Int`, `slog.Duration`, …).
- Use `snake_case` for attribute keys: `session_id`, `pod`, `node`, `selector`.
- Include `session_id` on any hub or agent log tied to a session.
- Avoid logging secrets, kubeconfig contents, or full packet payloads.

### What not to log

| Skip | Reason |
|------|--------|
| Unit tests | Noise; use `t.Log` if a test needs output |
| Generated protobuf / gRPC stubs | Not our code |
| Pure validation in `pkg/capture` | No I/O; errors return to caller |
| Per-poll lines in tight loops | Too noisy; log start/outcome at debug |

Session **events** (gRPC `WatchEvents`) remain the user-facing audit trail for a capture session. Logs complement that for operators and developers.

---

## Adding logging to new code

1. Add `var fooLog = log.WithComponent("foo")` in the package (safe at init; delegates to current default).
2. **Info** at boundaries: RPC handlers, create/delete complete, state transitions.
3. **Debug** for Kubernetes calls, matching/filtering, and retry paths.
4. Return errors; do not log and swallow unless the error is truly ancillary cleanup.
5. Call `log.Init` (or `InitFromEnv`) at the start of `main` before other work.
6. Extend this doc if you introduce a new component name or a pattern worth documenting.

---

## Examples

**Info (default):**

```text
level=INFO msg="session create started" component=hub session_id=… namespace=prod
level=INFO msg="agent pod created" component=agent session_id=… node=worker-1 pod=k8s-sniffer-abc12
level=INFO msg="session running" component=hub session_id=… nodes=2 node_names=[worker-1 worker-2]
```

**Debug:**

```text
level=DEBUG msg="listed namespace pods" component=discovery namespace=prod total=42
level=DEBUG msg="filtered matching running pods" component=discovery namespace=prod matched=3
level=DEBUG msg="waiting for agent pod ready" component=agent session_id=… pod=k8s-sniffer-abc12 namespace=k8s-sniffer timeout=2m0s
```

---

## Related docs

- [ARCHITECTURE.md](./ARCHITECTURE.md) — components that emit logs (`hub`, `agent`, `cli`)
- [TESTING.md](./TESTING.md) — tests do not require log assertions unless behavior depends on them
