# k8s-sniffer

Lightweight Kubernetes traffic sniffer: match pods by namespace + regex, run node-local capture agents, stream PCAP (with optional TLS decryption) back to the client.

## Status

Phase 1 MVP wire path: discovery, hub scheduling, agent capture, CLI `capture`
command, PCAP sink, agent image, RBAC manifests, and kind e2e harness.

```bash
k8s-sniffer capture -n NAMESPACE --pod 'REGEX' -o out.pcapng \
  --agent-image k8s-sniffer-agent:e2e --allow-mutable-agent-image \
  --hub-ingest-addr <host-reachable-from-pods>:30551
```

See [docs/TASKS.md](docs/TASKS.md) for remaining Phase 1 testing (T-TEST.2/3/7).

- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — design
- **[docs/TASKS.md](docs/TASKS.md)** — phased task breakdown + progress checklist
- **[docs/TESTING.md](docs/TESTING.md)** — unit / integration / kind+k3s e2e by phase
- **[docs/LOGGING.md](docs/LOGGING.md)** — slog conventions (info vs debug)
- **[specs/](specs/README.md)** — output specs for work that has landed

## Development

```bash
make build   # ./bin/k8s-sniffer, ./bin/k8s-sniffer-agent
make verify  # proto-check + vet + test (the pre-push / CI gate)
make proto   # regenerate api/sniffer/v1 (needs protoc on PATH; pin PROTOC_VERSION)
```

CI (`.github/workflows/verify.yml`) runs `make verify` on every PR and on pushes
to `main`. Use `protoc` at `PROTOC_VERSION` from the Makefile so `proto-check`
matches committed stubs.

Release builds pin the privileged agent image by digest:

```bash
make build AGENT_IMAGE=ghcr.io/sthuck/k8s-sniffer-agent@sha256:...
```

Development builds have no default agent image, so the image must be passed
explicitly rather than resolving to a mutable tag.

## Agent image & e2e

```bash
make image-agent AGENT_IMAGE=k8s-sniffer-agent:e2e
kubectl apply -f deploy/rbac.yaml
./test/e2e/run.sh kind    # create kind cluster, load image, apply fixtures
./test/e2e/run.sh test    # E2E1.1 smoke (needs kind + docker)
```

## CLI

```bash
k8s-sniffer capture \
  --namespace prod \
  --pod 'payments-.*' --pod 'checkout-.*' \
  --out ./session.pcapng \
  --agent-image ghcr.io/sthuck/k8s-sniffer-agent@sha256:... \
  --hub-ingest-addr 172.18.0.1:30551
```

TLS modes (`--tls auto`) land in Phase 3; Phase 1 is wire capture only.

## High-level shape

- **CLI** — entry point (namespace + regexes)
- **Hub** — session orchestration, discovery, stream aggregation (in-process for MVP; extractable for a future UI)
- **Sniffer agents** — ephemeral per-node pods: tcpdump/libpcap in target netns + optional eBPF TLS worker (e.g. ecapture)

UI is deferred; the Hub API is designed so a dashboard can attach later without redesigning capture.
