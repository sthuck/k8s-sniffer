# Output specs

One document per landed slice of work, written after the code exists. Each spec
records **what was built and how**, at design level — interfaces, decisions,
deviations from the plan — not line-by-line code.

Planning documents live in [`../docs`](../docs): [ARCHITECTURE.md](../docs/ARCHITECTURE.md),
[TASKS.md](../docs/TASKS.md), [TESTING.md](../docs/TESTING.md), [LOGGING.md](../docs/LOGGING.md).

| Spec | Tasks | Summary |
|------|-------|---------|
| [S0-ci-verify.md](./S0-ci-verify.md) | pre–T-TEST.2 | PR/`main` `unit` job runs `make verify`; pinned `PROTOC_VERSION` |
| [S1-skeleton-and-api.md](./S1-skeleton-and-api.md) | T1.1, T1.3, T1.2 (+ T0.3 in code) | Go module & package layout, `capture.Spec` + validation, `sniffer.v1` protobuf/gRPC contract |
| [S2-pod-matcher.md](./S2-pod-matcher.md) | T1.4 | Pod name regex matcher, Running-only filter, `PodRef` mapping |
| [S2-node-grouping.md](./S2-node-grouping.md) | T1.5 | Map matched pods to `nodeName`; skip unscheduled pods with events |
| [S2-agent-manifest.md](./S2-agent-manifest.md) | T1.6 | Privileged agent Pod manifest, labels, CRI socket volume |
| [S2-agent-lifecycle.md](./S2-agent-lifecycle.md) | T1.7 | Create/wait/delete session-scoped agent pods |
| [S2-in-process-hub.md](./S2-in-process-hub.md) | T1.8 | In-process Hub: CreateSession/StopSession, event stream, agent assignments |
| [S2-agent-capture.md](./S2-agent-capture.md) | T1.9–T1.12 | Agent bootstrap, CRI netns resolve, tcpdump, frame ingest |
| [S2-cli-sink.md](./S2-cli-sink.md) | T1.13–T1.17, T-TEST.1 | PCAP sink, `capture` CLI, agent image, RBAC, kind e2e harness |
