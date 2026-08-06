#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLUSTER_NAME="${KIND_CLUSTER_NAME:-k8s-sniffer-e2e}"
AGENT_IMAGE="${AGENT_IMAGE:-k8s-sniffer-agent:e2e}"
HUB_INGEST_PORT="${K8S_SNIFFER_HUB_INGEST_PORT:-30551}"

detect_hub_ingest_host() {
  if [[ -n "${K8S_SNIFFER_HUB_INGEST_HOST:-}" ]]; then
    echo "$K8S_SNIFFER_HUB_INGEST_HOST"
    return
  fi
  if command -v docker >/dev/null; then
    local gw
    gw="$(docker network inspect kind -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null || true)"
    if [[ -n "$gw" ]]; then
      echo "$gw"
      return
    fi
  fi
  ip -4 route show default 2>/dev/null | awk '{print $3; exit}'
}

HUB_INGEST_HOST="$(detect_hub_ingest_host)"
HUB_INGEST_ADDR="${HUB_INGEST_HOST}:${HUB_INGEST_PORT}"

usage() {
  cat <<EOF
Usage: $0 <kind|test>

  kind   Create/load kind cluster, build images, apply fixtures
  test   Run e2e tests (expects cluster + images ready)

Environment:
  KIND_CLUSTER_NAME          kind cluster name (default: k8s-sniffer-e2e)
  AGENT_IMAGE                agent image tag to build/load (default: k8s-sniffer-agent:e2e)
  K8S_SNIFFER_HUB_INGEST_HOST  host IP agents use to reach CLI hub (default: 127.0.0.1)
  K8S_SNIFFER_HUB_INGEST_PORT  host port mapped into kind (default: 30551)
EOF
}

ensure_kind() {
  if ! command -v kind >/dev/null; then
    echo "kind is required for e2e; install https://kind.sigs.k8s.io/" >&2
    exit 1
  fi
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

run_tests() {
  export K8S_SNIFFER_HUB_INGEST_HOST="$HUB_INGEST_HOST"
  export K8S_SNIFFER_E2E_AGENT_IMAGE="$AGENT_IMAGE"
  export K8S_SNIFFER_E2E_KUBECONTEXT="kind-${CLUSTER_NAME}"
  export K8S_SNIFFER_E2E_HUB_INGEST_ADDR="$HUB_INGEST_ADDR"
  (cd "$ROOT" && go test -tags=e2e -count=1 -timeout=15m ./test/e2e/...)
}

case "${1:-}" in
  kind)
    cluster_up
    ;;
  test)
    run_tests
    ;;
  ""|-h|--help)
    usage
    ;;
  *)
    cluster_up
    run_tests
    ;;
esac
