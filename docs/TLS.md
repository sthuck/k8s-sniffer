# TLS capture

Phase 3 adds optional TLS plaintext (eBPF) and a keylog fallback. Wire PCAP is
always collected.

## Modes (`--tls`)

| Mode | Default | Wire PCAP | TLS plaintext JSONL | Notes |
|------|---------|-----------|---------------------|-------|
| `auto` | yes | yes | if `--tls-out` and eBPF attaches | On attach failure, session continues; status is `unsupported` / `fallback` / `denied` |
| `ebpf` | | yes | if `--tls-out` and attach works | Same non-fatal attach failure as `auto`, status `denied`/`unsupported` |
| `keylog` | | yes | no | Does not inject env into pods. Use `--keylog-file` / `SSLKEYLOGFILE` with Wireshark |
| `off` | | yes | no | No TLS worker |

Invalid names are rejected. Unspecified API values default to `auto`.

## eBPF (`auto` / `ebpf`)

The agent shells out to a pinned [eCapture](https://github.com/gojue/ecapture)
binary (`v2.4.1`, Apache-2.0) in the agent image:

```text
ecapture tls -m text --pid <container-pid> --libssl /proc/<pid>/root/.../libssl.so [--cgroup_path ...]
```

Requirements:

- Privileged (or `CAP_BPF` / `CAP_PERFMON` / `CAP_SYS_ADMIN`) agent with `hostPID`
- Kernel BTF (`/sys/kernel/btf/vmlinux`) typical of kind / Ubuntu hosts
- Dynamically linked OpenSSL/BoringSSL in the **target** container

Go `crypto/tls` and uncommon stacks report `unsupported`; wire capture continues.

Plaintext is a `TlsPlaintextEvent` on `SubscribePackets`, written by the CLI to
`--tls-out` (JSONL). Synthetic PCAP (T3.8) is not implemented.

## Keylog (`--tls keylog` and `--keylog-file`)

k8s-sniffer does **not** mutate workloads (no `SSLKEYLOGFILE` injection, no
binary copy into the target). Enable a key log in the client or server:

```bash
export SSLKEYLOGFILE=./keys.log
curl -k https://app.example/
```

Then decrypt the wire PCAP:

```bash
tshark -r session.pcapng -o tls.keylog_file:./keys.log -Y http
# or Wireshark: (Pre)-Master-Secret log filename = keys.log
```

`--keylog-file` records the path the operator will use; it is not uploaded to
the hub.

## Status events

WatchEvents includes `TlsStateChanged`: `active`, `unsupported`, `denied`,
`fallback`. The CLI prints `event: tls <pod>: TLS_STATUS_…`.
