# TLS capture

Phase 3 adds optional TLS plaintext (eBPF) and a keylog fallback. Wire PCAP is
always collected.

## Modes (`--tls`)

| Mode | Default | Wire PCAP | TLS plaintext JSONL | Notes |
|------|---------|-----------|---------------------|-------|
| `auto` | yes | yes | if `--tls-out` and eBPF attaches | Always tries eBPF attach for WatchEvents status, even without `--tls-out`. On attach failure, session continues; status is `unsupported` / `fallback` / `denied` |
| `ebpf` | | yes | if `--tls-out` and attach works | Same non-fatal attach failure as `auto`, status `denied`/`unsupported` |
| `keylog` | | yes | no | Does not inject env into pods. Use `--keylog-file` / `SSLKEYLOGFILE` with Wireshark |
| `off` | | yes | no | No TLS worker |

Invalid names are rejected. Unspecified API values default to `auto`.

## eBPF (`auto` / `ebpf`)

The agent shells out to a pinned [eCapture](https://github.com/gojue/ecapture)
binary (`v2.4.1`, Apache-2.0) in the agent image:

```text
ecapture tls -m text --libssl /proc/<pid>/root/.../libssl.so [--cgroup_path ...]
```

`--pid` is omitted so nginx workers (not the container init PID) are covered.
`--libssl` is taken from the CRI container PID, then from other processes in
that container's **mount namespace** (workers). Sidecars share the pod netns
but not the app mount ns, so their libraries are not used.

Requirements:

- Privileged (or `CAP_BPF` / `CAP_PERFMON` / `CAP_SYS_ADMIN`) agent with `hostPID`
- Kernel BTF (`/sys/kernel/btf/vmlinux`) typical of kind / Ubuntu hosts
- Dynamically linked OpenSSL/BoringSSL in the **target** container

Go `crypto/tls` is **not** hooked in Phase 3 (`ecapture tls` / OpenSSL only).
Those workloads report `unsupported`; `ecapture gotls` is follow-up work.

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

`--keylog-file` records the path the operator will pass to Wireshark/tshark; it
is not uploaded to the hub and need not exist when capture starts (clients
often create it during the session).

## Status events

WatchEvents includes `TlsStateChanged`: `active` (first parsed plaintext event),
`unsupported`, `denied`, `fallback`. Starting eCapture is logged; it is not
reported as `active` until plaintext is seen. The CLI prints
`event: tls <pod>: TLS_STATUS_…`.
