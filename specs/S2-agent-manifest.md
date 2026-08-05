# S2 — Agent pod manifest

**Task:** T1.6.

**Tests covered:** UT1.4.

**Depends on:** [S2-node-grouping.md](./S2-node-grouping.md) (T1.5).

---

## 1. Package

`pkg/hub/agent` — builds ephemeral sniffer agent Pod objects.

## 2. API

`PodManifest(sessionID, nodeName, cfg)` validates `AgentConfig` and returns a
Pod with:

| Field | Value |
|-------|-------|
| `metadata.generateName` | `k8s-sniffer-` |
| `metadata.labels` | `app=k8s-sniffer-agent`, `sniffer.session=<id>` |
| `spec.nodeName` | target node |
| `spec.hostPID` | `true` |
| `spec.restartPolicy` | `Never` |
| `spec.automountServiceAccountToken` | `false` (agent has no API client) |
| container `securityContext` | `privileged: true` by default, or scoped capabilities when `Unprivileged` |
| container `imagePullPolicy` | `IfNotPresent`; `PullAlways` when `AllowMutableImage` |
| CRI socket volume | `hostPath` at `AgentConfig.CRISocketHostPath`, type `Socket`, mounted read-only |

## 3. Security modes

**Privileged (default):** `securityContext.privileged: true`.

**Unprivileged:** adds `SYS_ADMIN`, `NET_ADMIN`, `NET_RAW`, `BPF`, and `PERFMON`
so the agent can enter target netns and capture packets without the full
privileged container (ARCHITECTURE §5.3).

## 4. Golden test

`pkg/hub/agent/testdata/agent-pod.golden.yaml` — privileged default config.

## 5. Notes for T1.7

T1.7 creates these Pod objects, waits for Ready, and deletes them on stop.
Use `LabelAppKey` + `LabelSessionKey` for scoped list/delete.
