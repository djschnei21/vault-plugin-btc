.PHONY: all build clean test fmt lint dev

PLUGIN_NAME := vault-plugin-btc
PLUGIN_DIR := vault/plugins
GOARCH := $(shell go env GOARCH)
GOOS := $(shell go env GOOS)

all: build

build:
	@echo "Building $(PLUGIN_NAME)..."
	@mkdir -p $(PLUGIN_DIR)
	CGO_ENABLED=0 go build -o $(PLUGIN_DIR)/$(PLUGIN_NAME) ./cmd/$(PLUGIN_NAME)
	@echo "Plugin built at $(PLUGIN_DIR)/$(PLUGIN_NAME)"

clean:
	@echo "Cleaning..."
	rm -rf $(PLUGIN_DIR)
	go clean

test:
	@echo "Running tests..."
	go test -v ./...

fmt:
	@echo "Formatting code..."
	go fmt ./...

lint:
	@echo "Running linter..."
	golangci-lint run

# Development mode: start Vault with the plugin
dev: build
	@echo "Starting Vault in dev mode..."
	@echo ""
	@echo "In another terminal, run:"
	@echo "  export VAULT_ADDR='http://127.0.0.1:8200'"
	@echo "  export VAULT_TOKEN='root'"
	@echo "  vault secrets enable -path=btc vault-plugin-btc"
	@echo ""
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=$(PLUGIN_DIR) -log-level=debug

# Show help
help:
	@echo "Available targets:"
	@echo "  build  - Build the plugin binary"
	@echo "  clean  - Remove build artifacts"
	@echo "  test   - Run tests"
	@echo "  fmt    - Format Go code"
	@echo "  lint   - Run golangci-lint"
	@echo "  dev    - Start Vault in dev mode with plugin"
	@echo "  help   - Show this help"
