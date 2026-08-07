#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLUSTER_NAME="${KIND_CLUSTER_NAME:-k8s-sniffer-e2e}"
AGENT_IMAGE="${AGENT_IMAGE:-k8s-sniffer-agent:e2e}"
HUB_INGEST_PORT="${K8S_SNIFFER_HUB_INGEST_PORT:-30551}"
ARTIFACT_DIR="${K8S_SNIFFER_E2E_ARTIFACT_DIR:-$ROOT/test/e2e/artifacts}"

# Resolve after kind is up: the kind docker network does not exist until
# cluster_up, and pods reach the host via that network's IPv4 gateway
# (typically 172.18.0.1), not the runner's default route.
detect_hub_ingest_host() {
  if [[ -n "${K8S_SNIFFER_HUB_INGEST_HOST:-}" ]]; then
    echo "$K8S_SNIFFER_HUB_INGEST_HOST"
    return
  fi
  if command -v docker >/dev/null && docker network inspect kind >/dev/null 2>&1; then
    local gw
    gw="$(
      docker network inspect kind \
        -f '{{range .IPAM.Config}}{{if .Gateway}}{{.Gateway}} {{end}}{{end}}' 2>/dev/null \
        | awk '{for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { print $i; exit }}'
    )"
    if [[ -n "$gw" ]]; then
      echo "$gw"
      return
    fi
  fi
  ip -4 route show default 2>/dev/null | awk '{print $3; exit}'
}

usage() {
  cat <<EOF
Usage: $0 [kind|test|all]

  kind   Create/load kind cluster, build images, apply fixtures
  test   Run e2e tests (expects cluster + images ready)
  all    cluster-up + test (default; CI entrypoint)

Environment:
  KIND_CLUSTER_NAME            kind cluster name (default: k8s-sniffer-e2e)
  AGENT_IMAGE                  agent image tag to build/load (default: k8s-sniffer-agent:e2e)
  K8S_SNIFFER_HUB_INGEST_HOST  host IP agents use to reach CLI hub (default: kind docker IPv4 gateway)
  K8S_SNIFFER_HUB_INGEST_PORT  host port the CLI hub listens on (default: 30551)
  K8S_SNIFFER_E2E_ARTIFACT_DIR directory for failure artifacts (default: test/e2e/artifacts)
EOF
}

ensure_kind() {
  if ! command -v kind >/dev/null; then
    echo "kind is required for e2e; install https://kind.sigs.k8s.io/" >&2
    exit 1
  fi
}

clear_artifact_dir() {
  mkdir -p "$ARTIFACT_DIR"
  # Remove prior-run files so a failed retry does not upload a stale pcap.
  find "$ARTIFACT_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
}

cluster_up() {
  ensure_kind
  if ! kind get clusters | grep -qx "$CLUSTER_NAME"; then
    kind create cluster --name "$CLUSTER_NAME" --config "$ROOT/test/e2e/kind.yaml"
  fi
  docker build -t "$AGENT_IMAGE" --target agent "$ROOT"
  kind load docker-image "$AGENT_IMAGE" --name "$CLUSTER_NAME"
  kubectl --context "kind-${CLUSTER_NAME}" apply -f "$ROOT/deploy/rbac.yaml"
  kubectl --context "kind-${CLUSTER_NAME}" apply -f "$ROOT/test/e2e/fixtures/http-echo.yaml"
}

dump_failure_artifacts() {
  local ctx="kind-${CLUSTER_NAME}"
  mkdir -p "$ARTIFACT_DIR"
  {
    echo "=== hub ingest ==="
    echo "K8S_SNIFFER_HUB_INGEST_HOST=${K8S_SNIFFER_HUB_INGEST_HOST:-}"
    echo "K8S_SNIFFER_E2E_HUB_INGEST_ADDR=${K8S_SNIFFER_E2E_HUB_INGEST_ADDR:-}"
    echo
    echo "=== kubectl get pods -A ==="
    kubectl --context "$ctx" get pods -A -o wide 2>&1 || true
    echo
    echo "=== agent pods (k8s-sniffer) ==="
    kubectl --context "$ctx" -n k8s-sniffer get pods -o yaml 2>&1 || true
    echo
    echo "=== agent logs ==="
    local pods
    pods="$(kubectl --context "$ctx" -n k8s-sniffer get pods -l app=k8s-sniffer-agent -o name 2>/dev/null || true)"
    if [[ -n "$pods" ]]; then
      while IFS= read -r pod; do
        echo "--- logs $pod ---"
        kubectl --context "$ctx" -n k8s-sniffer logs "$pod" --all-containers 2>&1 || true
        echo "--- previous logs $pod ---"
        kubectl --context "$ctx" -n k8s-sniffer logs "$pod" --all-containers --previous 2>&1 || true
      done <<<"$pods"
    else
      echo "(no agent pods found)"
    fi
    echo
    echo "=== fixture pods ==="
    kubectl --context "$ctx" -n e2e-fixtures get pods -o wide 2>&1 || true
    kubectl --context "$ctx" -n e2e-fixtures describe pods 2>&1 || true
  } >"$ARTIFACT_DIR/cluster-dump.txt" 2>&1 || true
}

run_tests() {
  local hub_host hub_addr
  hub_host="$(detect_hub_ingest_host)"
  hub_addr="${hub_host}:${HUB_INGEST_PORT}"
  echo "hub ingest addr for agents: ${hub_addr}" >&2

  export K8S_SNIFFER_HUB_INGEST_HOST="$hub_host"
  export K8S_SNIFFER_E2E_AGENT_IMAGE="$AGENT_IMAGE"
  export K8S_SNIFFER_E2E_KUBECONTEXT="kind-${CLUSTER_NAME}"
  export K8S_SNIFFER_E2E_HUB_INGEST_ADDR="$hub_addr"
  export K8S_SNIFFER_E2E_ARTIFACT_DIR="$ARTIFACT_DIR"
  clear_artifact_dir
  if ! (cd "$ROOT" && go test -tags=e2e -count=1 -timeout=15m ./test/e2e/...); then
    dump_failure_artifacts
    return 1
  fi
}

run_all() {
  clear_artifact_dir
  if ! cluster_up; then
    dump_failure_artifacts
    return 1
  fi
  run_tests
}

case "${1:-}" in
  kind)
    cluster_up
    ;;
  test)
    run_tests
    ;;
  ""|all)
    run_all
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
