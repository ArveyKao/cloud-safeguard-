# Cloud Safeguard — build/test/demo entry points.
#
# make build   build the web console and the single Go binary (bin/csg)
# make test    run the full Go test suite
# make demo    run the end-to-end demo against the built-in mock cloud
# make web     rebuild only the web console into web/dist
# make fmt     gofmt the Go tree
# make clean   remove build artifacts

SHELL := /bin/bash
BINARY := bin/csg
GO ?= go
NPM ?= npm
DATA_DIR ?= .demo/data
DEMO_PORT ?= 18787
WEB_DIR := web

.PHONY: all build test demo web fmt vet clean help

all: build

help:
	@echo "make build   build web console + bin/csg"
	@echo "make test    go test ./..."
	@echo "make demo    end-to-end demo (mock cloud, port $(DEMO_PORT))"
	@echo "make web     build web console only"
	@echo "make fmt     gofmt -w ."
	@echo "make clean   remove bin/ .demo/"

build: web
	mkdir -p bin
	$(GO) build -trimpath -ldflags "-s -w" -o $(BINARY) ./cmd/csg

web:
	cd $(WEB_DIR) && $(NPM) install --no-audit --no-fund
	cd $(WEB_DIR) && $(NPM) run build

test:
	$(GO) test ./...

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

demo: build
	./scripts/demo.sh --port $(DEMO_PORT) --data-dir $(DATA_DIR)

clean:
	rm -rf bin .demo
