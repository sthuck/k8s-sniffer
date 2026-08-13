# Build stage: static Go binaries for CLI and agent.
FROM golang:1.22-alpine AS build
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG AGENT_IMAGE=
RUN set -eux; \
    LDFLAGS="-s -w -X main.version=${VERSION}"; \
    if [ -n "${AGENT_IMAGE}" ]; then \
      LDFLAGS="${LDFLAGS} -X github.com/sthuck/k8s-sniffer/pkg/capture.agentImageRef=${AGENT_IMAGE}"; \
    fi; \
    CGO_ENABLED=0 go build -ldflags "${LDFLAGS}" -o /out/k8s-sniffer ./cmd/k8s-sniffer; \
    CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=${VERSION}" -o /out/k8s-sniffer-agent ./cmd/k8s-sniffer-agent

# Agent runtime: debian for glibc (ecapture) plus tcpdump/nsenter.
# ecapture is Apache-2.0; see third_party/ecapture.NOTICE.
FROM debian:bookworm-slim AS agent
ARG TARGETARCH=amd64
ARG ECAPTURE_VERSION=v2.4.1
ARG ECAPTURE_AMD64_SHA256=f7ea5f8627acca0ce3e2e597de8b0658b5d160be1802b07904293295a7ab20e6
ARG ECAPTURE_ARM64_SHA256=513ab836f1723af6087885cbcebf08064e925f167f4d5de09b20bfd5be24b275
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates tcpdump util-linux wget \
    && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    arch="${TARGETARCH}"; \
    case "$arch" in \
      amd64) sha="$ECAPTURE_AMD64_SHA256" ;; \
      arm64) sha="$ECAPTURE_ARM64_SHA256" ;; \
      *) echo "unsupported TARGETARCH=$arch" >&2; exit 1 ;; \
    esac; \
    wget -q -O /tmp/ecapture.tar.gz \
      "https://github.com/gojue/ecapture/releases/download/${ECAPTURE_VERSION}/ecapture-${ECAPTURE_VERSION}-linux-${arch}.tar.gz"; \
    echo "${sha}  /tmp/ecapture.tar.gz" | sha256sum -c -; \
    mkdir -p /tmp/ecapture; \
    tar -xzf /tmp/ecapture.tar.gz -C /tmp/ecapture; \
    found="$(find /tmp/ecapture -type f -name ecapture | head -n 1)"; \
    test -n "$found"; \
    install -m 0755 "$found" /usr/local/bin/ecapture; \
    rm -rf /tmp/ecapture /tmp/ecapture.tar.gz
COPY --from=build /out/k8s-sniffer-agent /usr/local/bin/k8s-sniffer-agent
COPY third_party/ecapture.NOTICE /usr/share/doc/ecapture/NOTICE
USER 0
ENTRYPOINT ["/usr/local/bin/k8s-sniffer-agent"]

# CLI runtime (optional convenience image).
FROM gcr.io/distroless/static-debian12:nonroot AS cli
COPY --from=build /out/k8s-sniffer /k8s-sniffer
ENTRYPOINT ["/k8s-sniffer"]
