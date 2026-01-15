.PHONY: all build clean test fmt lint dev

PLUGIN_NAME := vault-plugin-secrets-btc
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
	@echo "Starting Vault in dev mode with debug logging..."
	@echo "Plugin SHA256: $$(sha256sum $(PLUGIN_DIR)/$(PLUGIN_NAME) | cut -d' ' -f1)"
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=$(PLUGIN_DIR) -log-level=debug

# Register and enable the plugin (run in another terminal after 'make dev')
enable:
	@echo "Registering plugin..."
	vault plugin register -sha256=$$(sha256sum $(PLUGIN_DIR)/$(PLUGIN_NAME) | cut -d' ' -f1) secret $(PLUGIN_NAME)
	@echo "Enabling plugin at btc/..."
	vault secrets enable -path=btc $(PLUGIN_NAME)
	@echo "Plugin enabled!"

# Quick test workflow
quicktest: enable
	@echo "Creating test wallet..."
	vault write btc/config network=testnet
	vault write btc/roles/test-wallet
	vault write btc/addresses/test-wallet
	vault read btc/balance/test-wallet
	vault read btc/addresses/test-wallet

# Show help
help:
	@echo "Available targets:"
	@echo "  build      - Build the plugin binary"
	@echo "  clean      - Remove build artifacts"
	@echo "  test       - Run tests"
	@echo "  fmt        - Format Go code"
	@echo "  lint       - Run golangci-lint"
	@echo "  dev        - Start Vault in dev mode with plugin"
	@echo "  enable     - Register and enable the plugin (run after 'make dev')"
	@echo "  quicktest  - Run quick test workflow"
	@echo "  help       - Show this help"
