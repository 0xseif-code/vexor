BINARY := bin/vexor
VERSION ?= 1.0.0
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.Version=$(VERSION) -X main.BuildDate=$(BUILD_DATE)

.PHONY: default build install clean test

default: build

build:
	mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/vexor

install:
	go install -ldflags "$(LDFLAGS)" ./cmd/vexor

clean:
	rm -rf bin

test:
	go test ./...