# Build stage: static Go binaries for CLI and agent.
FROM golang:1.22-alpine AS build
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG AGENT_IMAGE=
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=${VERSION}" -o /out/k8s-sniffer ./cmd/k8s-sniffer && \
    CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=${VERSION}" -o /out/k8s-sniffer-agent ./cmd/k8s-sniffer-agent

# Agent runtime: privileged pod needs tcpdump + nsenter on the node netns path.
FROM alpine:3.20 AS agent
RUN apk add --no-cache ca-certificates tcpdump util-linux
COPY --from=build /out/k8s-sniffer-agent /usr/local/bin/k8s-sniffer-agent
USER 0
ENTRYPOINT ["/usr/local/bin/k8s-sniffer-agent"]

# CLI runtime (optional convenience image).
FROM gcr.io/distroless/static-debian12:nonroot AS cli
COPY --from=build /out/k8s-sniffer /k8s-sniffer
ENTRYPOINT ["/k8s-sniffer"]
