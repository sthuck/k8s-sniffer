# S2 — CI workflows + e2e failure artifacts (Phase 1E)

**Tasks:** T-TEST.2, T-TEST.7.

**Depends on:** [S2-cli-sink.md](./S2-cli-sink.md) (T1.17 / T-TEST.1), [S2-envtest-hub.md](./S2-envtest-hub.md) (T-TEST.3), [S0-ci-verify.md](./S0-ci-verify.md).

---

## 1. Workflow jobs

[`.github/workflows/verify.yml`](../.github/workflows/verify.yml)

| Job | Command | Notes |
|-----|---------|-------|
| `unit` | `make verify` | Unchanged from S0 |
| `integration` | `make integration-test` | envtest IT1.1 (T-TEST.3) |
| `e2e-kind` | `./test/e2e/run.sh` | Installs kind v0.24.0; runs E2E1.1 |

Triggers, concurrency, and `contents: read` permissions match S0.

## 2. Failure artifacts (T-TEST.7)

`K8S_SNIFFER_E2E_ARTIFACT_DIR` (default `test/e2e/artifacts`):

| Artifact | Source |
|----------|--------|
| `capture.pcapng` | E2E1.1 writes PCAP into the artifact dir when set |
| `agent-logs.txt` | Go test cleanup on failure (`kubectl` logs via client-go) |
| `cluster-dump.txt` | `run.sh` on test failure: pods, agent YAML, fixture describe |

CI uploads `test/e2e/artifacts/` with `actions/upload-artifact@v4` when
`e2e-kind` fails (`if-no-files-found: ignore`, 7-day retention).

## 3. Out of scope

- k3s nightly (T-TEST.6)
- `e2e_tls` / multi-node kind (Phase 2+)
- Flake retries (optional later)
