# k8s-sniffer

Lightweight Kubernetes traffic sniffer: match pods by namespace + regex, run node-local capture agents, stream PCAP (with optional TLS decryption) back to the client.

## Status

Early Phase 1. The shared API and capture spec exist; discovery, agents and the
capture pipeline do not yet — the CLI is still a stub.

- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — design
- **[docs/TASKS.md](docs/TASKS.md)** — phased task breakdown + progress checklist
- **[docs/TESTING.md](docs/TESTING.md)** — unit / integration / kind+k3s e2e by phase
- **[specs/](specs/README.md)** — output specs for work that has landed

## Development

```bash
make build   # ./bin/k8s-sniffer, ./bin/k8s-sniffer-agent
make verify  # proto-check + vet + test (the pre-push gate)
make proto   # regenerate api/sniffer/v1 (needs protoc on PATH)
```

Release builds pin the privileged agent image by digest:

```bash
make build AGENT_IMAGE=ghcr.io/sthuck/k8s-sniffer-agent@sha256:...
```

Development builds have no default agent image, so the image must be passed
explicitly rather than resolving to a mutable tag.

## Intended CLI (sketch)

```bash
k8s-sniffer capture \
  --namespace prod \
  --pod 'payments-.*|checkout-.*' \
  --out ./session.pcapng \
  --tls auto
```

## High-level shape

- **CLI** — entry point (namespace + regexes)
- **Hub** — session orchestration, discovery, stream aggregation (in-process for MVP; extractable for a future UI)
- **Sniffer agents** — ephemeral per-node pods: tcpdump/libpcap in target netns + optional eBPF TLS worker (e.g. ecapture)

UI is deferred; the Hub API is designed so a dashboard can attach later without redesigning capture.
