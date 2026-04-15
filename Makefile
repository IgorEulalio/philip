.PHONY: all build build-agent build-server build-cli proto clean test lint run-agent run-server

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOVET=$(GOCMD) vet
GOMOD=$(GOCMD) mod

# Binary names
AGENT_BINARY=bin/philip-agent
SERVER_BINARY=bin/philip-server
CLI_BINARY=bin/philip

# Proto
PROTO_DIR=proto
PROTO_OUT=pkg/proto

# Build flags
LDFLAGS=-ldflags "-s -w"
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS=-ldflags "-s -w -X github.com/IgorEulalio/philip/internal/version.Version=$(VERSION) -X github.com/IgorEulalio/philip/internal/version.BuildTime=$(BUILD_TIME)"

all: build

build: build-agent build-server build-cli

build-agent:
	$(GOBUILD) $(LDFLAGS) -o $(AGENT_BINARY) ./agent/cmd/philip-agent

build-server:
	$(GOBUILD) $(LDFLAGS) -o $(SERVER_BINARY) ./backend/cmd/philip-server

build-cli:
	$(GOBUILD) $(LDFLAGS) -o $(CLI_BINARY) ./backend/cmd/philip-cli

proto:
	@mkdir -p $(PROTO_OUT)
	protoc \
		--proto_path=$(PROTO_DIR) \
		--go_out=$(PROTO_OUT) --go_opt=paths=source_relative \
		--go-grpc_out=$(PROTO_OUT) --go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/philip/v1/*.proto

test:
	$(GOTEST) -v -race -count=1 ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/
	rm -rf $(PROTO_OUT)

run-agent:
	$(GOBUILD) $(LDFLAGS) -o $(AGENT_BINARY) ./agent/cmd/philip-agent
	./$(AGENT_BINARY)

run-server:
	$(GOBUILD) $(LDFLAGS) -o $(SERVER_BINARY) ./backend/cmd/philip-server
	./$(SERVER_BINARY)

deps:
	$(GOMOD) download
	$(GOMOD) tidy

docker-backend:
	docker build -f deploy/docker/Dockerfile.backend -t philip-server .

docker-compose-up:
	docker-compose -f deploy/docker-compose.yml up -d

docker-compose-down:
	docker-compose -f deploy/docker-compose.yml down
