VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
.PHONY: all web build test test-unit test-race bench blackbox e2e spec-check docker docker-test test-split lint clean
all: web build
web:            ## build the dashboard into web/dist (embedded by the binary)
	cd web && npm ci && npm run build
build:          ## build bin/gw
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/gw ./cmd/gw
test: spec-check test-race blackbox e2e  ## everything
test-unit:      ## unit + integration tests
	go test ./internal/...
test-race:      ## unit + integration tests with the race detector
	go test -race -count=1 ./internal/...
bench:          ## hot-path benchmarks
	go test -run '^$$' -bench . -benchmem ./internal/policy ./internal/keybox ./internal/services/gateway ./internal/services/auth
blackbox: build ## black-box tests against the compiled binary
	cd test/blackbox && go test -count=1 .
e2e: web build  ## Playwright UI automation tests
	cd test/e2e && npm ci && npx playwright install chromium && npx playwright test
spec-check:     ## every acceptance criterion has a test
	./scripts/spec-check.sh
docker:         ## build the image
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) -t mcp-gateway:local .
docker-test:    ## image hardening + container smoke tests
	cd test/blackbox && GW_DOCKER_TESTS=1 go test -count=1 -run Docker -v .
test-split: docker  ## run the black-box suite against the microservices compose stack
	./scripts/test-split.sh
lint:
	go vet ./...
	cd web && npm run typecheck
clean:
	rm -rf bin web/dist/assets
