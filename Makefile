.PHONY: fmt vet test build build-agent build-server frontend-build install uninstall central-setup central-up central-down

fmt:
	@test -z "$$(gofmt -l cmd internal)" || (gofmt -l cmd internal; exit 1)

vet:
	go vet ./cmd/... ./internal/...

test:
	go test ./cmd/... ./internal/...

build:
	$(MAKE) build-agent build-server

build-agent:
	mkdir -p bin
	go build -trimpath -ldflags "-s -w -X main.version=$$(git describe --tags --always --dirty 2>/dev/null || echo dev)" -o bin/hostsentry-agent ./cmd/hostsentry-agent

build-server:
	mkdir -p bin
	go build -trimpath -ldflags "-s -w" -o bin/hostsentry-server ./cmd/hostsentry-server

frontend-build:
	npm --prefix frontend run build

install:
	./scripts/install-agent.sh

uninstall:
	./scripts/uninstall-agent.sh

central-setup:
	./scripts/setup-central.sh

central-up:
	docker compose up --build -d

central-down:
	docker compose down
