SHELL := /bin/bash

MODULE := github.com/sthuck/k8s-sniffer
LOCALBIN := $(CURDIR)/bin
PROTO_ROOT := api
PROTO_FILES := $(shell find $(PROTO_ROOT) -name '*.proto')

PROTOC_GEN_GO_VERSION ?= v1.34.2
PROTOC_GEN_GO_GRPC_VERSION ?= v1.5.1

GO ?= go
GOFLAGS ?=

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: all
all: build test

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

# Installs the protoc plugins into ./bin at pinned versions. protoc itself is a
# system dependency (apt: protobuf-compiler, brew: protobuf).
.PHONY: proto-tools
proto-tools: $(LOCALBIN)
	GOBIN=$(LOCALBIN) $(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	GOBIN=$(LOCALBIN) $(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)

.PHONY: proto
proto: proto-tools
	PATH="$(LOCALBIN):$$PATH" protoc \
		-I $(PROTO_ROOT) \
		--go_out=$(PROTO_ROOT) --go_opt=paths=source_relative \
		--go-grpc_out=$(PROTO_ROOT) --go-grpc_opt=paths=source_relative \
		$(patsubst $(PROTO_ROOT)/%,%,$(PROTO_FILES))

.PHONY: clean
clean:
	rm -rf $(LOCALBIN)
