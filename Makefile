SHELL := /bin/bash

MODULE := github.com/sthuck/k8s-sniffer
LOCALBIN := $(CURDIR)/bin
PROTO_ROOT := api
PROTO_FILES := $(shell find $(PROTO_ROOT) -name '*.proto')
PROTO_TARGETS := $(patsubst $(PROTO_ROOT)/%,%,$(PROTO_FILES))

# Pin the protoc binary used by proto / proto-check (and CI). Distro packages
# float; regenerate with this version so stubs stay reproducible.
PROTOC_VERSION ?= 27.1
PROTOC_GEN_GO_VERSION ?= v1.34.2
PROTOC_GEN_GO_GRPC_VERSION ?= v1.5.1

GO ?= go
GOFLAGS ?=

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Digest-pinned agent image for this release, e.g.
#   make build AGENT_IMAGE=ghcr.io/sthuck/k8s-sniffer-agent@sha256:...
# Left empty in development builds, which makes --agent-image mandatory instead
# of defaulting a privileged node agent to a mutable tag.
AGENT_IMAGE ?=

LDFLAGS := -X main.version=$(VERSION)
ifneq ($(AGENT_IMAGE),)
LDFLAGS += -X $(MODULE)/pkg/capture.agentImageRef=$(AGENT_IMAGE)
endif

.PHONY: all
all: build verify

# The gate to run before pushing: proto-check catches generated code that no
# longer matches the schema, which plain `go test` cannot see.
.PHONY: verify
verify: proto-check vet test

$(LOCALBIN):
	mkdir -p $(LOCALBIN)

.PHONY: build
build: $(LOCALBIN)
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(LOCALBIN)/k8s-sniffer ./cmd/k8s-sniffer
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(LOCALBIN)/k8s-sniffer-agent ./cmd/k8s-sniffer-agent

.PHONY: test
test:
	$(GO) test ./...

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: fmt
fmt:
	$(GO) fmt ./...

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: require-protoc
require-protoc:
	@command -v protoc >/dev/null || { \
		echo "protoc not found; install v$(PROTOC_VERSION) (CI downloads the official release; brew: protobuf)"; \
		exit 1; \
	}

# Installs the protoc plugins into ./bin at pinned versions. protoc itself is a
# system dependency.
.PHONY: proto-tools
proto-tools: $(LOCALBIN)
	GOBIN=$(LOCALBIN) $(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	GOBIN=$(LOCALBIN) $(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)

.PHONY: proto
proto: require-protoc proto-tools
	PATH="$(LOCALBIN):$$PATH" protoc \
		-I $(PROTO_ROOT) \
		--go_out=$(PROTO_ROOT) --go_opt=paths=source_relative \
		--go-grpc_out=$(PROTO_ROOT) --go-grpc_opt=paths=source_relative \
		$(PROTO_TARGETS)

# Generated code is committed, so a schema change with stale output would
# compile and test green while shipping an API nobody reviewed. Regenerate into
# a scratch tree and fail on any difference.
.PHONY: proto-check
proto-check: require-protoc proto-tools
	@tmp=$$(mktemp -d) && trap "rm -rf $$tmp" EXIT && \
	PATH="$(LOCALBIN):$$PATH" protoc \
		-I $(PROTO_ROOT) \
		--go_out=$$tmp --go_opt=paths=source_relative \
		--go-grpc_out=$$tmp --go-grpc_opt=paths=source_relative \
		$(PROTO_TARGETS) && \
	if ! diff -r -x '*.proto' -x '*_test.go' $(PROTO_ROOT) $$tmp >/dev/null; then \
		echo "generated protobuf code is stale; run 'make proto' and commit the result:"; \
		diff -r -u -x '*.proto' -x '*_test.go' $(PROTO_ROOT) $$tmp | head -40; \
		exit 1; \
	fi

.PHONY: image-agent image-cli docker-build
image-agent:
	docker build --target agent -t $(or $(AGENT_IMAGE),k8s-sniffer-agent:dev) .

image-cli:
	docker build --target cli -t $(or $(CLI_IMAGE),k8s-sniffer:dev) .

docker-build: image-agent image-cli

.PHONY: clean
clean:
	rm -rf $(LOCALBIN)
