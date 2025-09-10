MODULE_BINARY := bin/module
GO_FILES := $(shell find . -name '*.go' -not -path './vendor/*')

.PHONY: all build clean test lint setup module update

all: clean build module

$(MODULE_BINARY): $(GO_FILES) go.mod
	@echo "Building module binary..."
	@mkdir -p bin
	go build -o $(MODULE_BINARY) cmd/module/main.go

build: $(MODULE_BINARY)

module.tar.gz: meta.json $(MODULE_BINARY)
	@echo "Creating module archive..."
	@if [ -f $(MODULE_BINARY) ]; then \
		strip $(MODULE_BINARY) 2>/dev/null || true; \
	fi
	tar czf $@ meta.json $(MODULE_BINARY)
	@echo "Module archive created: $@"

module: module.tar.gz

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf bin/
	@rm -f module.tar.gz

test:
	@echo "Running tests..."
	go test ./...

lint:
	@echo "Running linter..."
	gofmt -s -w .

setup:
	@echo "Setting up module dependencies..."
	go mod download
	go mod tidy

update:
	@echo "Updating dependencies..."
	go get -u go.viam.com/rdk@latest
	go get -u github.com/vishvananda/netlink@latest
	go mod tidy

# Cross-compilation targets
build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -o bin/module-linux-arm64 cmd/module/main.go

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -o bin/module-linux-amd64 cmd/module/main.go

build-all: build-linux-arm64 build-linux-amd64