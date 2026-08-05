# Output specs

One document per landed slice of work, written after the code exists. Each spec
records **what was built and how**, at design level — interfaces, decisions,
deviations from the plan — not line-by-line code.

Planning documents live in [`../docs`](../docs): [ARCHITECTURE.md](../docs/ARCHITECTURE.md),
[TASKS.md](../docs/TASKS.md), [TESTING.md](../docs/TESTING.md).

| Spec | Tasks | Summary |
|------|-------|---------|
| [S1-skeleton-and-api.md](./S1-skeleton-and-api.md) | T1.1, T1.3, T1.2 (+ T0.3 in code) | Go module & package layout, `capture.Spec` + validation, `sniffer.v1` protobuf/gRPC contract |
| [S2-pod-matcher.md](./S2-pod-matcher.md) | T1.4 | Pod name regex matcher, Running-only filter, `PodRef` mapping |
