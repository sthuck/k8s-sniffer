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
| `make setup-envtest` | Installs `setup-envtest` into `./bin` |
| `make integration-test` | Downloads kube-apiserver/etcd for `ENVTEST_K8S_VERSION`, sets `KUBEBUILDER_ASSETS`, runs `-tags=integration` |

`make verify` stays unit-only (no envtest binaries). The CI `integration` job
(T-TEST.2) runs `make integration-test`.

## 3. Behaviour under envtest

envtest has no kubelet:

- Workload pods are created with `UpdateStatus` → `Phase=Running` so discovery’s
  Running-only filter matches.
- A background marker patches agent pod status to Ready so `WaitReady` succeeds.
- The same marker clears finalizers / force-deletes Terminating agent pods so
  `DeleteSessionAgents` can observe removal.

Production `DeleteSessionAgents` uses **grace period 0** (ephemeral agents;
matches the T1.7 lifecycle spec). Grace 5 left pods Terminating forever under
envtest and slowed real cleanup.

## 4. Pinning

| Pin | Value |
|-----|-------|
| `sigs.k8s.io/controller-runtime` | v0.19.4 (k8s 0.31 client-go) |
| `ENVTEST_K8S_VERSION` | 1.31.0 |
| `SETUP_ENVTEST_VERSION` | release-0.19 |
| `GOTOOLCHAIN` | `local` in `integration-test` so module resolution does not pull a newer Go |

## 5. Acceptance

`make integration-test` passes **IT1.1** without a kind cluster.
