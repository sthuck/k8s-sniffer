# S2 — Pod name regex matcher

**Task:** T1.4.

**Tests covered:** UT1.2.

---

## 1. Package

`pkg/hub/discovery` — pod listing and name filtering for capture sessions.

## 2. API

| Symbol | Role |
|--------|------|
| `NewPodMatcher(spec)` | Compiles `Spec.PodPatterns` via `Spec.CompilePatterns()` |
| `MatchName(name)` | Returns true when any unanchored RE2 pattern matches |
| `IsRunning(pod)` | True only for `PodRunning` phase |
| `ListMatchingPods(ctx, client, ns, matcher)` | Lists namespace pods; returns Running matches |
| `PodRefFromPod(pod)` | Maps API metadata to `sniffer.v1.PodRef` |

## 3. Behaviour

- Patterns are OR-ed; a pod matches when **any** pattern matches its name.
- Only `PodRunning` pods are selected. Pending, Succeeded, Failed, and Unknown
  are excluded (ARCHITECTURE §8.1).
- `PodRef.container_id` is left empty until netns resolution (T1.10).
- `ListMatchingPods` uses `kubernetes.Interface` so unit tests can use
  `fake.NewSimpleClientset`.

## 4. Notes for T1.5

`ListMatchingPods` returns a flat pod list. T1.5 groups matched pods by
`spec.nodeName` and records pods without a node as skipped events.
