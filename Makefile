.PHONY: fmt vet test build

fmt:
	@test -z "$$(gofmt -l cmd internal)" || (gofmt -l cmd internal; exit 1)

vet:
	go vet ./...

test:
	go test ./...

build:
	go build -trimpath -ldflags "-s -w -X main.version=$$(git describe --tags --always --dirty 2>/dev/null || echo dev)" -o bin/hostsentry-agent ./cmd/hostsentry-agent
