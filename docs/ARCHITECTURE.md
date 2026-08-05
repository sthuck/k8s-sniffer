# k8s-sniffer — Architecture Plan

Lightweight Kubernetes traffic capture tool: select pods by namespace + regex, schedule node-local sniffers, stream PCAP (and decrypted TLS where possible) back to the client.

**Status:** planning only — no implementation yet.

---

## 1. Goals

| Goal | Notes |
|------|--------|
| Easy entry point | CLI takes namespace + pod-name regex(es); optional label/container filters later |
| Multi-pod capture | One session can cover many pods across many nodes |
| TLS decryption | First-class; prefer approaches that need minimal app changes |
| PCAP export/stream | Live stream + write to `.pcap` / `.pcapng` |
| Lightweight & simple | Ephemeral agents, tear down on exit; reuse existing capture tools |
| UI-ready later | Clean session/API boundaries so a dashboard can sit on the same hub |

## 2. Non-goals (initial versions)

- Full L7 protocol UI / API catalog (Kubeshark territory)
- Always-on cluster-wide monitoring / long retention
- Service-mesh control-plane integration beyond “capture what we can see”
- Replacing Wireshark — we produce PCAPs; analysis stays external for v1

---

## 3. Recommended approach (summary)

**Orchestration inspired by ksniff; TLS inspired by eBPF uprobe tools (e.g. ecapture); product shape inspired by Kubeshark’s hub/worker split — but much thinner.**

1. **Wire capture:** privileged helper pod on each relevant node, enter target pod netns, run `tcpdump` (or libpcap) → raw PCAP frames.
2. **TLS plaintext:** prefer **eBPF uprobes** on common crypto stacks (OpenSSL / BoringSSL / Go `crypto/tls`) via an existing tool (primary candidate: [ecapture](https://github.com/gojue/ecapture)), not MITM and not requiring private keys.
3. **Fallback TLS:** `SSLKEYLOGFILE` / NSS key log when eBPF is unavailable or the stack is unsupported — still decryptable in Wireshark.
4. **Control plane:** local CLI embeds a small **Hub** in MVP; Hub is designed to detach into an in-cluster Deployment later for a UI.

Do **not** build a custom packet engine or custom TLS parser from scratch. Shell out to / embed battle-tested binaries and stream their output.

---

## 4. High-level architecture

```
┌──────────────────────┐
│  Clients             │
│  - CLI (v1)          │
│  - Web UI (later)    │
└──────────┬───────────┘
           │ gRPC / HTTP (session API)
           ▼
┌──────────────────────┐
│  Hub                 │
│  - session lifecycle │
│  - pod discovery     │
│  - agent scheduling  │
│  - stream mux/demux  │
│  - sink: pcap/file   │
└──────────┬───────────┘
           │ gRPC (agent control + packet/event stream)
           ▼
┌──────────────────────┐
│  Sniffer Agent Pods  │  (one per selected node, ephemeral)
│  - netns attach      │
│  - tcpdump / libpcap │
│  - TLS worker (eBPF) │
│  - framed stream out │
└──────────────────────┘
           │
           ▼
     Target pod netns(es) on that node
```

### Why this shape

| Concern | Choice |
|---------|--------|
| Multi-pod | Hub groups matched pods by `nodeName`, one agent per node |
| Stream to client | Agents push framed chunks to Hub; Hub fans in to session sinks |
| Future UI | UI becomes another Hub client; capture path unchanged |
| Lightweight | Agents created for a session, deleted on stop; no permanent DaemonSet required for MVP |

---

## 5. Components

### 5.1 CLI (`k8s-sniffer`)

Entry point for humans and scripts.

```bash
k8s-sniffer capture \
  --namespace prod \
  --pod 'payments-.*|checkout-.*' \
  --out ./session.pcapng \
  --tls auto \
  [--duration 5m] \
  [--bpf 'tcp port 8080']
```

Responsibilities:

- Parse flags, build a **CaptureSession** request
- Talk to Hub (in-process in MVP; remote later)
- Print status: matched pods, nodes, agent readiness, drop counters
- On Ctrl-C / duration end: stop session, tear down agents

### 5.2 Hub

Session orchestrator. Interfaces (stable even when process-local):

```text
CreateSession(spec) -> session_id
WatchSession(session_id) -> events (pods matched, agents up, errors)
SubscribePackets(session_id) -> PacketFrame stream
StopSession(session_id)
```

Internal jobs:

1. **Discover** pods in namespace matching regex(es) (name; later: labels).
2. **Watch** for pod create/delete during the session; attach/detach dynamically.
3. **Schedule** one Sniffer Agent pod per node that hosts ≥1 matched pod.
4. **Configure** each agent with target list: `{podUID, netns inode or containerID, interfaces, bpf filter, tls mode}`.
5. **Aggregate** streams; tag frames with pod/node metadata for multi-pod PCAPng.
6. **Cleanup** agent pods and RBAC-scoped objects on stop (and on panic via ownerRefs / finalizers).

MVP: Hub runs inside the CLI process using the user’s kubeconfig.  
Later: Hub Deployment + Service; CLI/UI authenticate to it.

### 5.3 Sniffer Agent

Privileged (or carefully capability-scoped) pod scheduled onto a specific node (`nodeName` / node affinity + tolerations).

Capabilities needed (typical):

- `CAP_NET_ADMIN`, `CAP_NET_RAW` — packet capture
- `CAP_SYS_ADMIN` / `CAP_BPF` / `CAP_PERFMON` — eBPF TLS (kernel-dependent)
- Host PID and/or CRI socket access — resolve container → netns
- Privileged may be simplest for v1; tighten later

Per target pod on that node:

1. Resolve container runtime ID → network namespace (`/proc/<pid>/ns/net` or equivalent via CRI).
2. Start **wire capture** in that netns (`tcpdump -i any -w -` or libpcap equivalent).
3. Optionally start **TLS worker** attached to target PIDs/libs.
4. Multiplex outputs into a single gRPC stream back to Hub.

Agent image should be small: static `tcpdump`/`libpcap` + TLS helper binary + thin Go agent wrapper.

---

## 6. Capture & TLS strategy

### 6.1 Wire PCAP (always on)

- Tooling: **tcpdump** or **libpcap** via Go (`gopacket/pcap`) — tcpdump subprocess is simpler and battle-tested.
- Scope: target pod netns only (not whole node) to reduce noise and privilege blast radius of filters.
- Output: standard pcap/pcapng packets with custom metadata (PCAPng options or parallel sidecar events): `k8s.pod`, `k8s.namespace`, `k8s.node`.

### 6.2 TLS decryption — primary path: eBPF uprobes

**Recommendation:** reuse **ecapture** (or a thin wrapper around the same approach) rather than reimplementing OpenSSL/Go hooks.

How it works conceptually:

- Attach uprobes to `SSL_read` / `SSL_write` (OpenSSL) or Go TLS internals.
- Capture **plaintext** before encrypt / after decrypt.
- Works without private keys, without MITM, without app config — when the binary/stack is supported.

Constraints to document for users:

- Needs relatively recent kernel + BPF permissions
- Static Go binaries / uncommon TLS stacks may miss
- Some locked-down nodes (GKE COS policies, Bottlerocket lockdown) may block eBPF

Hub should report per-pod TLS status: `active | unsupported | denied | fallback`.

### 6.3 TLS decryption — fallback: SSL key log

When eBPF fails or `--tls keylog`:

1. Inject `SSLKEYLOGFILE` if we control the workload (dev/debug only), **or**
2. Accept a user-provided keylog file / secret, **or**
3. Document how to enable keylog in the app and point the session at it.

Client/Hub can:

- Stream encrypted PCAP + keylog side channel, **or**
- Run `editcap`/`tshark` locally with keylog to produce a decrypted view

This path is weaker operationally but excellent for “easy” local/dev TLS.

### 6.4 Explicitly not recommended as default

| Approach | Why not default |
|----------|-----------------|
| MITM + custom CA | Requires trust injection; breaks pinning/mTLS; invasive |
| Steal server private keys from Secrets | Fragile, incomplete for PFS, high security risk |
| Full Kubeshark-style product clone | Too heavy for “lightweight & simple” |

MITM can remain an optional later mode for stubborn stacks.

### 6.5 eBPF vs no eBPF

| Mode | Wire PCAP | TLS plaintext | Complexity |
|------|-----------|---------------|------------|
| `tls=off` | yes | no | lowest |
| `tls=keylog` | yes | via Wireshark + keys | low |
| `tls=ebpf` (default when available) | yes | yes (supported stacks) | medium |
| `tls=auto` | yes | eBPF → else keylog hint | medium |

**Decision:** support both; default `auto`. Ship without eBPF first if needed for a working MVP, but keep the agent interface ready for a TLS worker process.

---

## 7. Streaming & PCAP export

### 7.1 On-wire framing (agent → hub)

```text
PacketFrame {
  session_id
  node
  pod_uid / pod_name
  source: WIRE | TLS_PLAINTEXT
  timestamp
  link_type          // for pcap
  payload            // raw packet bytes OR synthetic plaintext record
}
```

TLS plaintext can be emitted as:

- **Synthetic packets** (e.g. fake TCP/HTTP frames) into a second pcap stream, or
- **Parallel event stream** (JSON/protobuf HTTP records) + optional conversion to pcap for Wireshark

**Recommendation for v1:** two sinks per session:

1. `session-wire.pcapng` — true on-the-wire capture  
2. `session-tls.jsonl` or `session-tls.pcapng` — decrypted payloads  

Keep formats boring and tool-friendly.

### 7.2 Client sinks

- File (`--out`)
-Stdout (`--out -`) for piping to Wireshark: `... --out - | wireshark -k -i -`
- Multiple files when multi-pod metadata needs separation (optional `--split-per-pod`)

### 7.3 Multi-pod PCAP

Prefer **single PCAPng** with Interface Description Blocks or packet comments carrying pod identity, so one Wireshark session can filter `k8s.pod == foo`.

---

## 8. Kubernetes integration details

### 8.1 Discovery

```text
List/Watch Pods in namespace
Filter: name matches any of the provided regexes
Optional later: --selector, --container, --exclude
```

Map each Running pod → `spec.nodeName`. Ignore Pending/Succeeded/Failed unless they become Running during the watch.

### 8.2 Agent scheduling

For each node in the matched set:

```yaml
# conceptual
kind: Pod
metadata:
  generateName: k8s-sniffer-
  labels:
    app: k8s-sniffer-agent
    sniffer.session: <id>
spec:
  nodeName: <node>
  hostPID: true          # for netns via /proc
  restartPolicy: Never
  containers:
  - name: agent
    image: ghcr.io/.../k8s-sniffer-agent:<ver>
    securityContext:
      privileged: true   # tighten later
    volumeMounts:
    - name: cri-sock     # if needed
    ...
```

Prefer creating agents in the **target namespace** or a dedicated `k8s-sniffer` namespace (config flag). Use ownerReferences / session labels for garbage collection.

### 8.3 RBAC (minimum sketch)

- `pods`: get/list/watch/create/delete (create/delete scoped to agent pods)
- `pods/log`: optional
- nodes: get/list (optional)
- If using CRI socket: node-local only, no extra API

CLI mode uses the user’s credentials. In-cluster Hub uses a ServiceAccount.

### 8.4 Netns attachment techniques (reuse existing patterns)

Same family as ksniff privileged mode:

1. Resolve container PID via CRI (`crictl`) or `/proc` walk from node
2. `nsenter --net=/proc/<pid>/ns/net tcpdump ...`  
   or open that ns from Go and capture with libpcap

Do not copy binaries into target pods (ksniff default mode) — prefer external helper to avoid mutating workloads.

---

## 9. Future UI proofing

Without building UI now, lock these contracts:

1. **Session is the unit of work** — not “a CLI run”. CLI creates a session and attaches sinks.
2. **Hub API is network-accessible** — gRPC (+ optional HTTP/JSON gateway) even when colocated.
3. **All capture metadata is structured events** — pod matched, agent ready, TLS mode, errors, stats — not only stdout text.
4. **Packet subscription is multiplex-friendly** — multiple subscribers (CLI file writer + future live viewer) per session.
5. **Authn/z hook** — stub interface (`kubeconfig` / bearer) so UI SSO can plug in later.

Suggested later UI surfaces (do not implement yet):

- Live session list, matched pods, per-node agent health  
- Live packet/HTTP feed (consuming TLS event stream)  
- Download PCAP button (same sink the CLI uses)

---

## 10. Suggested tech stack

| Layer | Choice | Rationale |
|-------|--------|-----------|
| Language | Go | client-go, single static binaries |
| CLI | `cobra` / `urfave/cli` | standard |
| API | gRPC + protobuf | streaming, UI-ready |
| Wire capture | tcpdump (subprocess) | simple, PCAP-native |
| TLS | ecapture (subprocess) or equiv. | existing eBPF TLS tool |
| K8s | client-go informers | watch pods efficiently |
| Local PCAP write | gopacket/pcapgo | PCAPng writer |

Avoid writing custom eBPF C if an existing binary covers OpenSSL/Go.

---

## 11. Security & ops notes

- Capturing plaintext TLS is sensitive — treat sessions as privileged debug actions; audit log session start/stop.
- Default to **short-lived** agents; hard timeout (`--duration`) recommended.
- Document cluster requirements: privileged pods, kernel BPF, possibly AppArmor/SELinux exceptions.
- Never persist captures in-cluster by default; stream to the client.
- Warn clearly when falling back to encrypted-only PCAP.

---

## 12. Phased delivery

High-level phases below. **Concrete task IDs, dependencies, and acceptance criteria:** [TASKS.md](./TASKS.md).

### Phase 0 — Plan (this document)
Architecture, TLS options, component boundaries.

### Phase 1 — MVP wire sniffer
- CLI: namespace + regex → match pods → agents on nodes  
- tcpdump in target netns  
- Stream to local `.pcap` / stdout  
- Cleanup on exit  
- **No TLS yet**

### Phase 2 — Multi-pod polish
- Live pod watch (pods appearing mid-session)  
- PCAPng metadata annotations  
- BPF capture filter flag  
- Basic stats / drop reporting  

### Phase 3 — TLS
- Integrate eBPF TLS worker (`tls=ebpf` / `auto`)  
- Keylog fallback path  
- Dual sinks: wire + plaintext  

### Phase 4 — Hub extraction
- In-cluster Hub Deployment  
- Remote CLI attach  
- Multi-subscriber sessions  

### Phase 5 — UI (deferred)
- Web client on Hub API  
- Live view + PCAP download  

Each phase should leave the previous CLI UX working.

---

## 13. Open decisions (resolve before / during Phase 1)

1. **Agent namespace:** same as targets vs dedicated system namespace?  
   - Recommendation: dedicated `k8s-sniffer` (or flag), to avoid polluting app namespaces.
2. **Privileged vs fine-grained caps:** start privileged; document hardening path.
3. **CRI socket path diversity:** containerd vs CRI-O vs Docker — detect or configure.
4. **TLS plaintext format:** synthetic PCAP vs JSONL events first?  
   - Recommendation: JSONL events in Phase 3, optional PCAP export after.
5. **License/compliance** of vendored binaries (tcpdump, ecapture) in the agent image.

---

## 14. Comparison to existing tools (why build this)

| Tool | Fit | Gap vs our goals |
|------|-----|------------------|
| **ksniff** | Great single-pod PCAP UX | Weak multi-pod orchestration; no TLS decrypt |
| **Kubeshark** | Full TLS + multi-pod + UI | Heavy product; not “lightweight & simple” |
| **ecapture** | Excellent TLS eBPF | Not K8s-orchestrated / multi-pod session aware |
| **tcpdump in debug pod** | Universal | Manual, no session abstraction |

**This project** = thin K8s orchestrator (ksniff-like) + multi-pod sessions + PCAP streaming + optional ecapture-class TLS, with a Hub API that a UI can consume later.

---

## 15. Success criteria for MVP

- One command captures traffic from all pods in a namespace matching a regex.
- Agents appear only on nodes that need them and disappear when the session ends.
- Output is a valid PCAP/PCAPng openable in Wireshark.
- Architecture docs and package boundaries already separate CLI / Hub / Agent so TLS and UI can land without rewrite.
