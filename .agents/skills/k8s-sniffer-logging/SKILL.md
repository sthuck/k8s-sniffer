---
name: k8s-sniffer-logging
description: Add and configure structured slog logging in k8s-sniffer using pkg/log (info = what happened, debug = how it happened). Use when adding logs, changing log level/config, instrumenting hub/agent/discovery/k8s/cli code, or when the user mentions logging, slog, or observability in this repo.
---

# k8s-sniffer logging

Use Go stdlib `log/slog` through `github.com/sthuck/k8s-sniffer/pkg/log`.

**Source of truth:** [docs/LOGGING.md](../../../docs/LOGGING.md). On conflict, follow that doc (and `pkg/log`); keep this skill thin — do not duplicate its tables.

## Levels (only two)

| Level | Meaning |
|-------|---------|
| **info** | What happened (outcomes at boundaries) |
| **debug** | How it happened (counts, selectors, wait start) |

No separate `error` level — return errors to callers; log at **info** with `err` at operational boundaries.

## Quick setup

**In `main`:** init before other work (match `cmd/k8s-sniffer/main.go` / `cmd/k8s-sniffer-agent/main.go`):

```go
import (
	"fmt"
	"log/slog"
	"os"

	"github.com/sthuck/k8s-sniffer/pkg/log"
)

level, err := log.ResolveLevel(*logLevel, os.Getenv(log.EnvLevel))
if err != nil {
	fmt.Fprintf(os.Stderr, "invalid --log-level: %v\n", err)
	os.Exit(2)
}
log.Init(log.Config{Level: level})
```

**In library packages:** one package-level logger only — do **not** call `Init` from `pkg/*`. `WithComponent` delegates to `slog.Default()` at log time, so package `var` loggers are safe before `main` calls `Init`:

```go
var hubLog = log.WithComponent("hub")
```

Component names: `hub`, `agent`, `discovery`, `k8s`, `cli` (extend only if [docs/LOGGING.md](../../../docs/LOGGING.md) is updated).

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

For where/when to log (and what to skip), read [docs/LOGGING.md](../../../docs/LOGGING.md).

## Config surface (summary)

| Mechanism | Notes |
|-----------|-------|
| `K8S_SNIFFER_LOG_LEVEL` | `info` (default) or `debug` |
| `--log-level` | CLI flag; overrides env |
| `log.Init(Config{...})` | Process entrypoints (`main`) and tests that need a configured default — not library packages |
| `log.InitFromEnv()` | Env only; returns error on invalid value |

Agent pods do **not** yet receive hub/CLI log level (T1.9). JSON is programmatic-only (`Config.JSON`).

## Notes

- Do not call `slog.SetDefault` from feature code; go through `pkg/log`.
- Tests that call `Init` must **not** use `t.Parallel()` (global default races).

## Checklist for new logging

- [ ] `var fooLog = log.WithComponent("foo")` in package
- [ ] Info at boundaries; debug for internals
- [ ] `session_id` on session-scoped hub/agent lines
- [ ] Return errors; don't log-and-swallow
- [ ] `log.Init` early in new `main` packages (not from libraries)
- [ ] Update [docs/LOGGING.md](../../../docs/LOGGING.md) if adding a new component name or pattern
