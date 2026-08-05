# S2 — Node grouping

**Task:** T1.5.

**Tests covered:** UT1.3.

**Depends on:** [S2-pod-matcher.md](./S2-pod-matcher.md) (T1.4).

---

## 1. API

| Symbol | Role |
|--------|------|
| `GroupByNode(pods)` | Maps pods to `[]NodeGroup` by `spec.nodeName` |
| `GroupMatchingPods(pods, matcher)` | Filters with `PodMatcher`, then groups |
| `SkippedPod` | A matched pod that cannot be scheduled yet |
| `SkipReasonNoNode` | Stable reason when `spec.nodeName` is empty |

## 2. Grouping contract

```go
type NodeGroup struct {
    Node    string
    Targets []*snifferv1.PodRef
}
```

- One `NodeGroup` per distinct `spec.nodeName`.
- `Targets` holds `PodRef` values with `Node` set to the group node.
- Node order follows **first-seen** order while iterating the input slice.

## 3. Skipped pods

Running matched pods with an empty `spec.nodeName` are not placed in any group.
They are returned in `[]SkippedPod` with reason `pod has no nodeName assigned`
so T1.8 can emit a structured `SessionEvent` instead of silently dropping them.

## 4. Notes for T1.6 / T1.8

- T1.8 should call `ListMatchingPods` → `GroupByNode`, emit events for each
  `SkippedPod`, then schedule one agent per `NodeGroup`.
- T1.6 builds the per-node agent Pod; it does not perform grouping.
