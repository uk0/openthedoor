.PHONY: build clean install test

BINARY=fwctl
BUILD_DIR=bin

build:
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/fwctl

clean:
	rm -rf $(BUILD_DIR)

install: build
	sudo cp $(BUILD_DIR)/$(BINARY) /usr/local/bin/

test:
	go test -v ./...

# Cross compile for Linux
build-linux:
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY)-linux-amd64 ./cmd/fwctl
	GOOS=linux GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY)-linux-arm64 ./cmd/fwctl

# Build with version info
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
build-release:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY) ./cmd/fwctl
