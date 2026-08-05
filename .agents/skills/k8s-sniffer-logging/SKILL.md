---
name: k8s-sniffer-logging
description: Add and configure structured slog logging in k8s-sniffer using pkg/log (info = what happened, debug = how it happened). Use when adding logs, changing log level/config, instrumenting hub/agent/discovery/k8s/cli code, or when the user mentions logging, slog, or observability in this repo.
---

# k8s-sniffer logging

Use Go stdlib `log/slog` through `github.com/sthuck/k8s-sniffer/pkg/log`. Full reference: [docs/LOGGING.md](../../../docs/LOGGING.md).

## Levels (only two)

| Level | Meaning | Examples |
|-------|---------|----------|
| **info** | What happened | session created/stopped/failed, agent ready, client built |
| **debug** | How it happened | list counts, selectors, wait start, filter results |

No separate `error` level — return errors to callers; log at **info** with `err` at operational boundaries.

## Quick setup

**In `main`:** init before other work.

```go
level, err := log.ResolveLevel(*logLevelFlag, os.Getenv(log.EnvLevel))
if err != nil { /* exit 2 */ }
log.Init(log.Config{Level: level})
```

**In library packages:** one package-level logger (safe before `Init` — delegates at log time):

```go
var hubLog = log.WithComponent("hub")
```

Component names: `hub`, `agent`, `discovery`, `k8s`, `cli`.

## Writing log lines

```go
hubLog.Info("session running",
    slog.String("session_id", sessionID),
    slog.Int("nodes", len(nodes)),
)

discoveryLog.Debug("filtered matching running pods",
    slog.String("namespace", namespace),
    slog.Int("matched", len(matched)),
)
```

Rules:
- Typed attrs (`slog.String`, `slog.Int`, `slog.Duration`, …)
- `snake_case` keys: `session_id`, `pod`, `node`, `selector`
- Include `session_id` on hub/agent logs tied to a session
- Do not log secrets, kubeconfig, or packet payloads

## Where to log

| Area | Info | Debug |
|------|------|-------|
| Hub RPC / lifecycle | create/stop/run/fail outcomes | spec, counts, grouping |
| Agent lifecycle | create/reuse/ready/delete | selectors, wait start |
| Discovery | — | list totals, match counts |
| k8s client | client ready | host, user-agent |
| CLI/agent main | process start | level configured |

## Do not log

- Unit tests (use `t.Log` if needed)
- Generated protobuf/gRPC stubs
- Pure validation in `pkg/capture`
- Every poll tick in tight loops

Session gRPC events (`WatchEvents`) are the user-facing audit trail; logs are for operators/developers.

## Config surface

| Mechanism | Notes |
|-----------|-------|
| `K8S_SNIFFER_LOG_LEVEL` | `info` (default) or `debug` |
| `--log-level` | CLI flag; overrides env |
| `log.Init(Config{...})` | Tests and libraries |
| `log.InitFromEnv()` | Returns error on invalid env value |

Agent pods do **not** yet receive hub/CLI log level (T1.9). JSON output is programmatic-only (`Config.JSON`); no env/flag yet.

## Implementation notes

- `WithComponent` uses `delegateHandler` — forwards to `slog.Default()` at log time, so package `var` loggers honor post-`Init` config.
- Do not call `slog.SetDefault` from feature code; go through `pkg/log`.
- Tests that call `Init` must **not** use `t.Parallel()` (global default races).

## Checklist for new logging

- [ ] `var fooLog = log.WithComponent("foo")` in package
- [ ] Info at boundaries; debug for internals
- [ ] `session_id` on session-scoped hub/agent lines
- [ ] Return errors; don't log-and-swallow
- [ ] `log.Init` early in new `main` packages
- [ ] Update [docs/LOGGING.md](../../../docs/LOGGING.md) if adding a new component name or pattern
