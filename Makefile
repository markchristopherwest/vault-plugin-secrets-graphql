GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
PLUGIN_NAME := vault-plugin-secrets-graphql
PLUGIN_DIR := vault/plugins

.PHONY: all build test fmt vet gen clean enable

all: fmt vet test build

build:
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(PLUGIN_DIR)/$(PLUGIN_NAME) cmd/$(PLUGIN_NAME)/main.go

test:
	go test ./... -count=1

fmt:
	gofmt -s -w .

vet:
	go vet ./...

# Regenerate the capability matrix in README.md from the live backend.
gen:
	go generate ./...

clean:
	rm -f $(PLUGIN_DIR)/$(PLUGIN_NAME)

# Convenience target for local dev-mode Vault (assumes VAULT_ADDR is set).
enable: build
	@SHA256=$$(openssl dgst -sha256 $(PLUGIN_DIR)/$(PLUGIN_NAME) | cut -d ' ' -f2); \
	vault plugin register -sha256="$$SHA256" -command="$(PLUGIN_NAME)" secret $(PLUGIN_NAME); \
	vault secrets enable -path=graphql $(PLUGIN_NAME)
