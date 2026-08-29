BINARY := bin/vexor

.PHONY: default build install clean test

default: build

build:
	mkdir -p bin
	go build -ldflags "-s -w" -o $(BINARY) ./cmd/vexor

install:
	go install ./cmd/vexor

clean:
	rm -rf bin

test:
	go test ./...