# k8s-sniffer

Lightweight Kubernetes traffic sniffer: match pods by namespace + regex, run node-local capture agents, stream PCAP (with optional TLS decryption) back to the client.

## Status

Phase 1+2 wire path plus Phase 3 TLS: `--tls auto` (default) attaches eCapture when
the workload uses OpenSSL; `--tls-out` writes plaintext JSONL. Keylog mode does
not mutate pods — see [docs/TLS.md](docs/TLS.md).

```bash
k8s-sniffer capture -n NAMESPACE --pod 'REGEX' -o out.pcapng \
  --tls auto --tls-out tls.jsonl \
  --agent-image k8s-sniffer-agent:e2e --allow-mutable-agent-image \
  --hub-ingest-addr <host-reachable-from-pods>:30551
```

Testing: unit, envtest (IT1.1 / IT2.1 / IT3.1), kind e2e (E2E1.1, E2E2.*,
E2E3.2–E2E3.4), and `e2e-kind-tls` for E2E3.1. `--bpf` e2e, `--split-per-pod`,
`--duration` e2e, and T3.8 synthetic TLS PCAP are deferred.

- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — design
- **[docs/TASKS.md](docs/TASKS.md)** — phased task breakdown + progress checklist
- **[docs/TESTING.md](docs/TESTING.md)** — unit / integration / kind+k3s e2e by phase
- **[docs/TLS.md](docs/TLS.md)** — `--tls` modes, eCapture, keylog / SSLKEYLOGFILE
- **[docs/LOGGING.md](docs/LOGGING.md)** — slog conventions (info vs debug)
- **[specs/](specs/README.md)** — output specs for work that has landed

## Development

```bash
make build     # ./bin/k8s-sniffer, ./bin/k8s-sniffer-agent
make verify    # proto-check + vet + test + release-version tests
make dist-all  # CLI archives (linux/amd64, windows/amd64, darwin/arm64) in ./dist
make proto     # regenerate api/sniffer/v1 (needs protoc on PATH; pin PROTOC_VERSION)
```

Windows `make dist` needs `zip` on PATH. CI (`.github/workflows/verify.yml`)
runs `make verify` on every PR and on pushes to `main`. Use `protoc` at
`PROTOC_VERSION` from the Makefile so `proto-check` matches committed stubs.

To cut a GitHub release, run the **release** workflow from `main` (Actions →
release → Run workflow). It reuses the verify suite (unit, envtest, kind e2e),
publishes the agent image to `ghcr.io/<owner>/k8s-sniffer-agent`, digest-pins
that image into CLI archives for linux/amd64, windows/amd64, and darwin/arm64,
tags the next minor version (or a version you type that is newer than the
latest tag), generates notes from commits since the previous tag, and uploads
the archives. The first tag is `v0.1.0`. Locally: `make dist-all`.

Release CLI builds bake the privileged agent image digest:

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
  --tls auto --tls-out ./session-tls.jsonl \
  --agent-image ghcr.io/sthuck/k8s-sniffer-agent@sha256:... \
  --hub-ingest-addr 172.18.0.1:30551
```

k3s and RKE2 expose CRI at `/run/k3s/containerd/containerd.sock`, not the
kind/Talos default `/run/containerd/containerd.sock`. The hub selects the k3s
path from the node's `containerRuntimeVersion` when `--cri-socket` is left at
the default. Override explicitly if auto-detect is wrong:

```bash
k8s-sniffer capture ... --cri-socket /run/k3s/containerd/containerd.sock
```

TLS: `--tls off|ebpf|keylog|auto` (default `auto`). Plaintext JSONL is `--tls-out`.
Keylog / SSLKEYLOGFILE: [docs/TLS.md](docs/TLS.md).

## High-level shape

- **CLI** — entry point (namespace + regexes)
- **Hub** — session orchestration, discovery, stream aggregation (in-process for MVP; extractable for a future UI)
- **Sniffer agents** — ephemeral per-node pods: tcpdump/libpcap in target netns + optional eBPF TLS worker (e.g. ecapture)

UI is deferred; the Hub API is designed so a dashboard can attach later without redesigning capture.
