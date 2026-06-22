# ──────────────────────────────────────────────────────────────────────
#  Makefile — common dev tasks for the autorzp project.
#  Usage: `make <target>`. Run `make help` to see all targets.
# ──────────────────────────────────────────────────────────────────────

# Allow overriding Go binary path (useful in CI with a specific Go version).
GO         ?= go
BINARY     := autorzp
PORT       ?= 7070

# Files that contain example / test data. Override via env if needed.
PROXY_FILE ?= px.txt
SITES_FILE ?= sites.txt
LIVE_FILE  ?= live.txt

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help message
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make \033[36m<target>\033[0m\n\nTargets:\n"} \
	      /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build the autorzp binary into ./bin/
	@mkdir -p bin
	$(GO) build -trimpath -ldflags="-s -w" -o bin/$(BINARY) ./...
	@echo "✓ Built bin/$(BINARY)"

.PHONY: run
run: ## Run locally on port $(PORT)
	PORT=$(PORT) $(GO) run autorzp.go

.PHONY: run-docker
run-docker: docker-build ## Run inside Docker on port $(PORT)
	docker run --rm -p $(PORT):$(PORT) \
	  -e PORT=$(PORT) \
	  -e PROXY_FILE=$(PROXY_FILE) \
	  -e SITES_FILE=$(SITES_FILE) \
	  -e LIVE_FILE=$(LIVE_FILE) \
	  -v "$$(pwd)/live.txt:/app/live.txt" \
	  autorzp:latest

.PHONY: test
test: ## Run all unit tests with race detector
	$(GO) test -race -v ./...

.PHONY: test-short
test-short: ## Run only short tests (skip integration)
	$(GO) test -short -v ./...

.PHONY: vet
vet: ## Run go vet
	$(GO) vet ./...

.PHONY: fmt
fmt: ## Format all .go files
	$(GO) fmt ./...
	@command -v goimports >/dev/null 2>&1 && goimports -w . || true

.PHONY: fmt-check
fmt-check: ## Fail if any file is not gofmt-clean
	@out=$$($(GO) fmt ./...); \
	if [ -n "$$out" ]; then \
	  echo "The following files were reformatted (run 'make fmt' and commit):"; \
	  echo "$$out"; \
	  exit 1; \
	else \
	  echo "✓ All files are gofmt-clean"; \
	fi

.PHONY: lint
lint: vet fmt-check ## Run all static checks (vet + fmt)

.PHONY: check
check: lint test ## Run everything CI would run (lint + tests)

.PHONY: coverage
coverage: ## Generate test coverage report (coverage.html)
	$(GO) test -coverprofile=coverage.txt -covermode=atomic ./...
	$(GO) tool cover -html=coverage.txt -o coverage.html
	@echo "✓ Coverage report: coverage.html"

.PHONY: docker-build
docker-build: ## Build the Docker image (autorzp:latest)
	docker build -t autorzp:latest .

.PHONY: docker-run
docker-run: docker-build ## Run the Docker image on port $(PORT)
	docker run --rm -p $(PORT):$(PORT) autorzp:latest

.PHONY: tidy
tidy: ## Run go mod tidy
	$(GO) mod tidy

.PHONY: clean
clean: ## Remove build artifacts and coverage files
	rm -rf bin coverage.txt coverage.html *.test *.out
	@echo "✓ Cleaned"

.PHONY: health
health: ## Hit the local /health endpoint
	curl -sS http://127.0.0.1:$(PORT)/health | jq . 2>/dev/null || curl -sS http://127.0.0.1:$(PORT)/health

.PHONY: deps
deps: ## Download and verify all dependencies
	$(GO) mod download
	$(GO) mod verify
