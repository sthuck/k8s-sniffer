# S2 — envtest Hub lifecycle (IT1.1)

**Tasks:** T-TEST.3.

**Depends on:** [S2-in-process-hub.md](./S2-in-process-hub.md) (T1.8), [S2-agent-lifecycle.md](./S2-agent-lifecycle.md) (T1.7).

---

## 1. Goal

Prove CreateSession / StopSession against a real Kubernetes apiserver without
kind: agent Pod objects are created and deleted. This is **IT1.1**.

## 2. Layout

| Path | Role |
|------|------|
| `pkg/hub/hub_envtest_test.go` | `//go:build integration` — IT1.1 |
| `make setup-envtest` | Installs `setup-envtest` into `./bin` (version-stamped) |
| `make integration-test` | Downloads kube-apiserver/etcd for `ENVTEST_K8S_VERSION`, sets `KUBEBUILDER_ASSETS`, runs `-tags=integration` |

`make verify` stays unit-only (no envtest binaries). The T-TEST.2 `integration`
job will run `make integration-test` once that workflow lands
([S2-ci-e2e.md](./S2-ci-e2e.md)).

## 3. Behaviour under envtest

envtest has no kubelet. IT1.1 uses a **fake kubelet** helper that:

- patches agent pod status to Ready so `WaitReady` succeeds
- finishes GC for Terminating pods (clear finalizers + force delete) only after
  Hub has stamped `DeletionTimestamp`

The test pauses GC around `StopSession` so it can assert Hub-issued deletion
(`DeletionTimestamp` on both agents) before allowing removal. It also asserts
each agent’s `sniffer.node` / `spec.nodeName` cover the session’s nodes.

Production `DeleteSessionAgents` keeps a short non-zero grace period (see
[S2-agent-lifecycle.md](./S2-agent-lifecycle.md) / capture stop-drain). envtest
must not rely on grace `0` for GC.

Workload pods are created with `UpdateStatus` → `Phase=Running` so discovery’s
Running-only filter matches.

## 4. Pinning / module deps

| Pin | Value |
|-----|-------|
| `sigs.k8s.io/controller-runtime` | v0.19.4 (k8s 0.31 client-go) — **direct** `require` for the integration-tagged `envtest` import |
| `ENVTEST_K8S_VERSION` | 1.31.0 |
| `SETUP_ENVTEST_VERSION` | release-0.19 |
| `GOTOOLCHAIN` | `local` in `integration-test` so module resolution does not pull a newer Go |

`controller-runtime` is a direct module dependency solely because Go cannot
isolate build-tagged test imports from `go.mod`. Acceptable for MVP; revisit a
tools/`go.mod` split if envtest surface grows.

## 5. Acceptance

`make integration-test` passes **IT1.1** without a kind cluster.
