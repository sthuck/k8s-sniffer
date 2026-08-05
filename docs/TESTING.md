# Testing strategy

Maps test layers to delivery phases from [TASKS.md](./TASKS.md) / [ARCHITECTURE.md](./ARCHITECTURE.md).

**Logging:** unit tests do not assert on slog output unless a test specifically covers logging behavior. See [LOGGING.md](./LOGGING.md).

**Principle:** every feature task ships with the cheapest test that proves it; cluster e2e is reserved for paths that need a real node, netns, or CRI.

---

## 1. Test pyramid

```text
                    ┌─────────────┐
                    │  Cluster e2e │  kind (primary) / k3s (compat)
                    │  slow, few   │
                ┌───┴─────────────┴───┐
                │  Integration        │  envtest, fake CRI, gRPC in-proc
                │  medium             │
            ┌───┴─────────────────────┴───┐
            │  Unit                       │  pure Go, table-driven
            │  fast, many                 │
            └─────────────────────────────┘
```

| Layer | Runs where | Speed | What it proves |
|-------|------------|-------|----------------|
| **Unit** | `go test ./...` | seconds | Matchers, specs, manifests, PCAP writers, framing |
| **Integration** | `go test` + envtest / fakes | tens of seconds | Hub scheduling against API server; gRPC session flows without real packets |
| **Cluster e2e** | kind (CI) + optional k3s | minutes | Real agent pods, netns attach, tcpdump, TLS eBPF, multi-node |

---

## 2. Cluster runtime choice

| Runtime | Role | Why |
|---------|------|-----|
| **kind** (primary) | Local + CI e2e | containerd (matches our CRI-first decision), multi-node easy, image load (`kind load`), widely used in K8s projects |
| **k3s** (secondary) | Compat / optional job | Different defaults (Traefik, single binary); catches “works only on kind” bugs; not required for every PR |

**Recommendation**

- Develop and gate PRs on **kind**.
- Add a **scheduled or manual k3s** job once Phase 1 e2e is stable (see T-TEST.k3s).
- Prefer a **2-node kind** cluster for multi-node agent tests (Phase 2+); Phase 1 smoke can use 1 node.

Avoid requiring a full kubevirt / cloud cluster for CI.

---

## 3. Shared e2e harness (build once, reuse)

Introduce early (with T1.17) so later phases only add scenarios:

```text
test/e2e/
  harness/          # cluster up/down helpers, kubeconfig, wait utils
  fixtures/         # Deployments: echo/http, https-openssl, traffic generator
  kind.yaml         # 1- or 2-node config
  run.sh            # entry: build images → load → apply fixtures → go test
```

Conventions:

- Tests are Go (`testing` or Ginkgo — prefer std `testing` + helpers for simplicity).
- Build CLI + agent image in the script; `kind load docker-image`.
- Each test creates an isolated namespace `e2e-<name>-<suffix>` and deletes it.
- Assert with `tshark`/`tcpdump -r` or a small Go pcap reader — not Wireshark GUI.
- Mark privileged / BPF tests with build tags: `//go:build e2e` and `//go:build e2e_tls`.

CI shape (evolve over phases):

| Job | When | Command | Status |
|-----|------|---------|--------|
| `unit` | every PR + push to `main` | `make verify` (proto-check, vet, `go test ./...`) | Live in [`.github/workflows/verify.yml`](../.github/workflows/verify.yml) (pre–T-TEST.2 slice) |
| `integration` | every PR | `go test ./pkg/... -tags=integration` (envtest) | Planned (T-TEST.2 / T-TEST.3) |
| `e2e-kind` | every PR after T1.17 | `./test/e2e/run.sh kind` | Planned (T-TEST.2) |
| `e2e-kind-tls` | every PR after T3.9 (or nightly if flaky) | `./test/e2e/run.sh kind -tags e2e_tls` | Planned |
| `e2e-k3s` | nightly / manual | `./test/e2e/run.sh k3s` | Planned |

The interim workflow uses a single `unit` job so `integration` / `e2e-kind` can land as sibling jobs under T-TEST.2 without redesigning the gate. CI installs `protoc` at `PROTOC_VERSION` from the Makefile (same pin as local regen).

---

## 4. What to test in each phase

### Phase 0 — Docs only

No automated product tests. Optional: markdown link check later.

---

### Phase 1 — MVP wire sniffer

**Goal of testing:** prove multi-pod PCAP capture on a real cluster; keep unit coverage on pure logic so e2e stays thin.

| ID | Layer | Covers tasks | What to assert |
|----|-------|--------------|----------------|
| **UT1.1** | Unit | T1.3 | `CaptureSpec` validation (empty ns, bad regex, good regex) |
| **UT1.2** | Unit | T1.4 | Pod name regex match / miss / non-Running excluded |
| **UT1.3** | Unit | T1.5 | Node grouping; pods without `nodeName` skipped |
| **UT1.4** | Unit | T1.6 | Agent Pod manifest golden (privileged, labels, `nodeName`, image) |
| **UT1.5** | Unit | T1.13 | PCAP writer round-trip: write frames → read back N packets |
| **UT1.6** | Unit | T1.2 / framing | `PacketFrame` encode/decode; metadata fields preserved |
| **IT1.1** | Integration (envtest) | T1.7, T1.8 | CreateSession creates agent Pod objects; StopSession deletes them |
| **IT1.2** | Integration (in-proc gRPC) | T1.8, T1.9 | Hub ↔ fake agent: target list delivered; stop propagates |
| **E2E1.1** | kind smoke | T1.14–T1.17 | Deploy 2 HTTP pods matching regex; generate curl traffic; capture → pcap has TCP packets; agents gone after exit |
| **E2E1.2** | kind | T1.4, T1.14 | Regex excludes non-matching pod (no frames tagged with that name) |
| **E2E1.3** | kind | T1.7 | Kill CLI with SIGINT → agent pods deleted within timeout |

**Phase 1 CI minimum:** `unit` + `E2E1.1`.  
**E2E1.2 / E2E1.3** can land in the same harness PR or immediately after.

**Out of scope for Phase 1 e2e:** TLS, live watch, multi-node, remote Hub.

---

### Phase 2 — Multi-pod polish

| ID | Layer | Covers tasks | What to assert |
|----|-------|--------------|----------------|
| **UT2.1** | Unit | T2.4 | BPF filter string passed into tcpdump arg builder |
| **UT2.2** | Unit | T2.5 | PCAPng options/comments contain pod/node/ns |
| **UT2.3** | Unit | T2.6 | Split-per-pod sink creates one writer per pod UID |
| **IT2.1** | envtest | T2.1–T2.3 | Watch: add Pod → agent target update / new agent; delete last pod on node → agent removed |
| **E2E2.1** | kind | T2.1 | Mid-session: create new matching pod → later packets include it |
| **E2E2.2** | kind | T2.1 | Mid-session: delete pod → no crash; capture continues for others |
| **E2E2.3** | kind **2-node** | T2.3 | Pods on node A and B → two agents; drain B’s pods → B agent removed |
| **E2E2.4** | kind | T2.4 | `--bpf "tcp port 8080"` → no (or negligible) traffic on other ports in pcap |
| **E2E2.5** | kind | T2.8 | `--duration 10s` exits 0; finite pcap; agents cleaned up |
| **E2E2.6** | kind | T2.7 | Stats/events show packet counters > 0 after traffic |

**Phase 2 CI:** keep Phase 1 jobs; add `E2E2.1` + `E2E2.3` as required; rest can be `e2e-kind-extended` if runtime is high.

---

### Phase 3 — TLS

TLS e2e is flakier (kernel, privileges, library match). Isolate with `e2e_tls` tag.

| ID | Layer | Covers tasks | What to assert |
|----|-------|--------------|----------------|
| **UT3.1** | Unit | T3.1 | TLS mode parsing / default `auto` |
| **UT3.2** | Unit | T3.4 | Multiplex: wire frames + TLS events ordered per stream contract |
| **IT3.1** | Integration | T3.3, T3.6 | Fake TLS worker reports `unsupported` → Hub emits status; session stays up |
| **E2E3.1** | kind + `e2e_tls` | T3.3–T3.5, T3.9 | OpenSSL/nginx fixture; HTTPS traffic; `--tls-out` JSONL contains known plaintext marker |
| **E2E3.2** | kind + `e2e_tls` | T3.6 | Unsupported binary (e.g. static uncommon stack) → status `unsupported`/`fallback`; wire pcap still non-empty |
| **E2E3.3** | kind | T3.7 | Keylog mode: provide keylog + wire pcap; `tshark` decrypts Host/path or known string |
| **E2E3.4** | kind | T3.1 | `--tls=off` produces no TLS plaintext file even if worker present |

**Fixtures to add in Phase 3**

- `fixtures/https-openssl` — dynamically linked OpenSSL server + client with predictable body (`e2e-secret-token`)
- Optional: Go `crypto/tls` app for a second stack later

**Phase 3 CI:** `E2E3.1` required if runners allow privileged BPF; otherwise nightly + document skip. Never skip wire e2e because TLS failed.

---

### Phase 4 — Hub extraction

| ID | Layer | Covers tasks | What to assert |
|----|-------|--------------|----------------|
| **UT4.1** | Unit | T4.5 | Auth middleware rejects missing token |
| **IT4.1** | Integration | T4.1, T4.4 | Two in-proc subscribers receive the same fake frames; one cancel leaves the other alive |
| **E2E4.1** | kind | T4.2, T4.3 | Install Hub manifests; CLI `--hub` captures successfully |
| **E2E4.2** | kind | T4.4 | Two CLI subscribers (or test clients) on one session both get packets |
| **E2E4.3** | kind | T4.6 | `ListSessions` shows active session during capture |

---

### Phase 5 — UI (deferred)

| ID | Layer | Notes |
|----|-------|-------|
| **UT5.*** | Component / unit | UI state, form validation |
| **E2E5.1** | Playwright/Cypress against Hub | Create session via UI → same Hub session as CLI path |
| Prefer contract tests against Hub HTTP/gRPC over brittle full UI e2e early |

---

## 5. Cross-cutting test tasks (add to backlog)

| ID | Task | Phase | Size | Notes |
|----|------|-------|------|-------|
| **T-TEST.1** | E2e harness scaffold (`test/e2e`, kind config, fixtures/http) | 1 (with T1.17) | M | Blocks meaningful E2E1.* |
| **T-TEST.2** | CI workflows: unit + integration + e2e-kind | 1 | M | GitHub Actions; kind on ubuntu |
| **T-TEST.3** | envtest setup for Hub pod lifecycle | 1 (with T1.7) | M | No cluster needed for IT1.1 |
| **T-TEST.4** | 2-node kind config + scheduling helpers | 2 | S | For E2E2.3 |
| **T-TEST.5** | HTTPS/OpenSSL fixture + `e2e_tls` tag | 3 | M | For E2E3.1 |
| **T-TEST.6** | Optional k3s e2e job | 1–2 (after kind stable) | M | Nightly; document containerd socket path differences |
| **T-TEST.7** | Flake policy: retries, artifact upload (pcap, agent logs) | 1 | S | On failure, upload `*.pcap` and `kubectl logs` |

---

## 6. kind vs k3s scenario matrix

| Scenario | kind | k3s |
|----------|------|-----|
| Single-node wire capture (E2E1.1) | Required CI | Nightly |
| Multi-node agents (E2E2.3) | Required CI (2-node) | Optional if multi-node k3s painful |
| Privileged agent + hostPID | Required | Required (validate k3s security defaults) |
| containerd netns resolve | Primary path | Validate path/config still works |
| TLS eBPF (E2E3.1) | Primary | Best-effort (kernel/config may differ) |
| Hub in-cluster (E2E4.1) | Required | Nightly |

If k3s diverges only on CRI socket path, fix via config flag — do not fork capture logic.

---

## 7. Assertions cookbook (keep e2e honest)

Prefer deterministic signals over “pcap size > 0” alone:

| Check | How |
|-------|-----|
| Traffic happened | Fixture writes unique HTTP path `/e2e/<uuid>` or body token |
| Wire capture works | `tshark -r out.pcap -Y http.request.uri` contains uuid **or** TCP stream to fixture Service IP |
| Pod tagging | Frame/event metadata includes expected pod name |
| Cleanup | `kubectl get pods -l sniffer.session=...` → empty after test |
| TLS plaintext | JSONL line contains the known body token |
| Duration/stop | Process exit code 0; no leaked namespaces/pods (list by label) |

Generate traffic **during** capture (background curl loop), not only before start.

---

## 8. What not to do

- Do not run full cluster e2e for pure regex/manifest changes — unit/golden is enough.
- Do not depend on a developer’s Docker Desktop Kubernetes as the only e2e path.
- Do not make TLS e2e block Phase 1 merges.
- Do not assert on absolute packet counts (CNI noise); assert on presence of fixture markers / 5-tuples.
- Do not leave agent images as `:latest` without digests in CI — pin tag to git SHA.

---

## 9. Mapping to Phase exit criteria

| Phase exit | Must-pass tests |
|------------|-----------------|
| Phase 1 | UT1.* (core), IT1.1, **E2E1.1**, E2E1.3 |
| Phase 2 | + **E2E2.1**, **E2E2.3**, E2E2.5 |
| Phase 3 | + **E2E3.1** (or documented CI skip + nightly), E2E3.3, E2E3.4 |
| Phase 4 | + **E2E4.1**, E2E4.2 |
| Phase 5 | + UI contract / E2E5.1 |

---

## 10. Suggested order to add testing work

```text
Phase 1:
  T-TEST.3 (envtest)  → with T1.7
  T-TEST.1 (harness)  → with T1.17
  T-TEST.2 (CI)       → right after first green local E2E1.1
  T-TEST.7 (artifacts)→ with T-TEST.2

Phase 2:
  T-TEST.4 (2-node)   → before E2E2.3

Phase 3:
  T-TEST.5 (TLS fixture) → before E2E3.1

Anytime after Phase 1 stable:
  T-TEST.6 (k3s nightly)
```
