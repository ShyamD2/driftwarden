BINARY_NAME=driftwarden
BIN_DIR=bin
VERSION=1.0.0
BUILD_DATE=$(shell date -u +'%Y-%m-%d')
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")

.PHONY: all build test lint localstack-up chaos-test docker-build verify clean

all: build test

build:
	@mkdir -p $(BIN_DIR)
	go build -ldflags="-s -w -X main.version=$(VERSION) -X main.gitCommit=$(COMMIT) -X main.buildDate=$(BUILD_DATE)" -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/driftwarden

build-windows:
	@mkdir -p $(BIN_DIR)
	go build -ldflags="-s -w -X main.version=$(VERSION)" -o $(BIN_DIR)/$(BINARY_NAME).exe ./cmd/driftwarden

build-linux:
	@mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X main.version=$(VERSION)" -o $(BIN_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/driftwarden

test:
	go test -v -count=1 ./pkg/... ./cmd/driftwarden/... ./tests/...

test-race:
	go test -v -race -count=1 ./pkg/...

bench:
	go test -bench=. -benchmem ./pkg/terraform/... ./pkg/diff/...

lint:
	go vet ./...
	@if command -v staticcheck > /dev/null; then staticcheck ./...; else echo "staticcheck not installed (skipping)"; fi

localstack-up:
	docker compose up -d
	@echo "Waiting for LocalStack to be healthy..."
	@sleep 5
	./scripts/seed_localstack.sh

localstack-down:
	docker compose down

chaos-test:
	go test -v ./tests/chaos/...

docker-build:
	docker build -t driftwarden:$(VERSION) -t driftwarden:latest .

verify: lint test bench chaos-test build
	@echo "All verification gates passed successfully!"

clean:
	rm -rf $(BIN_DIR) testdata/evidence_bundle
