# S0 — Interim CI verify gate

**Tasks:** pre–T-TEST.2 slice (not the full T-TEST.2 acceptance).

**Depends on:** none (workflow-only + pinned `PROTOC_VERSION`).

---

## 1. Workflow

[`.github/workflows/verify.yml`](../.github/workflows/verify.yml)

| Trigger | Purpose |
|---------|---------|
| `pull_request` | PR gate |
| `push` to `main` | Keep default branch covered after merge |
| `workflow_dispatch` | Manual re-run |

Concurrency: `verify-${{ github.ref }}` with `cancel-in-progress: true`.

## 2. Job layout

| Job | Command | Notes |
|-----|---------|-------|
| `unit` | `make verify` | proto-check + vet + `go test ./...`; `timeout-minutes: 10` |
| `integration` | — | Reserved for T-TEST.2 / T-TEST.3 |
| `e2e-kind` | — | Reserved for T-TEST.2 / T1.17 |

## 3. protoc pin

`Makefile` `PROTOC_VERSION` (currently `27.1`). CI downloads that release binary
instead of apt’s floating `protobuf-compiler`. Regenerated stubs embed the pinned
protoc version in their headers; `proto-check` fails if CI and committed output
diverge.

`@actions/*` actions stay on major tags; only third-party actions require SHA
pins.

## 4. Out of scope (T-TEST.2)

- Separate `integration` job with `-tags=integration` / envtest
- kind e2e (`./test/e2e/run.sh`)
- Failure artifact upload (T-TEST.7)
