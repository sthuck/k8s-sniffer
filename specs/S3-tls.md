# S3 — TLS plaintext (eBPF + keylog)

**Tasks:** T3.1–T3.7, T3.9, T-TEST.5.

**Deferred:** T3.8 (synthetic PCAP from TLS events). JSONL is the plaintext sink.

**Depends on:** [S2-agent-capture.md](./S2-agent-capture.md), [S2-cli-sink.md](./S2-cli-sink.md), [S2-phase2.md](./S2-phase2.md).

**Tests covered:** UT3.1, UT3.2, IT3.1, E2E3.1 (`e2e_tls`), E2E3.2, E2E3.3, E2E3.4.

Operator-facing notes: [docs/TLS.md](../docs/TLS.md).

---

## 1. Modes (T3.1)

`--tls` accepts `off`, `ebpf`, `keylog`, `auto` (default). Unspecified proto values become `auto` via `Spec.WithDefaults()`. Invalid names are rejected; known modes are not silently downgraded.

Wire PCAP is always collected. TLS attach failures never fail the session.

| Mode | eBPF worker | On attach failure |
|------|-------------|-------------------|
| `off` | no | n/a |
| `ebpf` | yes | status `denied` / `unsupported`; wire continues |
| `auto` | yes | status `fallback` / `unsupported`; wire continues |
| `keylog` | no | status `fallback`; operator supplies SSLKEYLOGFILE |

`--tls-out` is a JSONL path on the client. It cannot be `-` or equal to `--out`. `--keylog-file` is client-side only and is never injected into workloads.

Existing kind wire e2e forces `TLSModeOff` so those jobs do not wait on ecapture.

## 2. Agent image (T3.2)

The agent runtime image is `debian:bookworm-slim` (glibc) so the pinned [eCapture](https://github.com/gojue/ecapture) **v2.4.1** binary can run. Checksums are ARG-pinned in the Dockerfile. License: Apache-2.0, noted in `third_party/ecapture.NOTICE`.

## 3. TLS worker (T3.3 / T3.6)

`pkg/agent/tlsworker.Attacher` starts per target alongside tcpdump. Cancel of the per-UID capture context stops both.

eCapture is invoked as:

```text
ecapture tls -m text --libssl /proc/<pid>/root/.../libssl.so [--cgroup_path ...]
```

`--pid` is omitted on purpose: nginx and similar servers terminate TLS in workers, not the container init PID. Uprobes on the container's libssl inode cover every process that maps it. `findLibSSLInNetns` scans `/proc` for PIDs sharing the container netns so a worker that maps libssl is found even if the init PID does not.

Missing binary / no libssl → `unsupported` (`fallback` in `auto` when the binary is absent). Permission/BTF failures → `denied` (`fallback` in `auto`). After ~2s or the first parsed event → `active`.

Status is `ReportStatus` `TlsStateChanged`; the CLI prints `event: tls <pod>: TLS_STATUS_…`.

## 4. Multiplex + JSONL sink (T3.4 / T3.5)

Agents send `CaptureRecord.tls_event` on the same `StreamCapture` as wire frames. Hub `SubscribePackets` with an empty kind list delivers both; the CLI subscribes to wire-only unless `--tls-out` is set.

`pkg/sink.JSONLWriter` writes one object per line. UTF-8 payloads use `payload`; otherwise `payload_b64`.

## 5. Keylog (T3.7)

`--tls keylog` does not launch eBPF and does not mutate pods. The operator (or e2e harness) writes an NSS key log via `SSLKEYLOGFILE` / `tls.Config.KeyLogWriter` and decrypts the wire PCAP in Wireshark/tshark.

## 6. E2e (T3.9 / T-TEST.5)

HTTPS fixture: `nginx:1.27-bookworm` + generated TLS Secret, marker `e2e-secret-token`.

| Test | Tag | Assert |
|------|-----|--------|
| E2E3.1 | `e2e,e2e_tls` | `--tls-out` JSONL contains the marker |
| E2E3.2 | `e2e` | `auto` on http-echo → unsupported/fallback; wire pcap non-empty |
| E2E3.3 | `e2e` | host client keylog + wire pcap; tshark decrypts when installed |
| E2E3.4 | `e2e` | `--tls=off` JSONL has no marker |

CI: `e2e-kind` runs E2E3.2–3.4; `e2e-kind-tls` runs `E2E_GO_TAGS=e2e,e2e_tls E2E_GO_RUN=TestE2E3_`.
