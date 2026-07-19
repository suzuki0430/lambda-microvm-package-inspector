SHELL := /usr/bin/env bash

.DEFAULT_GOAL := help

GO_WORKSPACE := $(abspath .cache/go)
GO_TOOLCHAIN := go1.25.12
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.6.0
PNPM := pnpm
RUNNER_DIR := runner
CONTROLLER_DIR := controller
INFRA_DIR := infra

.PHONY: help fixtures fixtures-check microvm-artifact runner-format runner-lint runner-test runner-integration runner-scan-good runner-scan-canary \
	controller-format controller-generate controller-test controller-audit infra-format infra-test infra-audit security-audit synth test preflight verify-cleanup

help: ## Show available targets.
	@awk 'BEGIN {FS = ":.*## "; printf "Usage: make <target>\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-24s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

fixtures: ## Build the deterministic good and canary npm tarballs.
	./scripts/build-fixtures

fixtures-check: ## Parse-check fixture and catalog JavaScript without executing hooks.
	node --check scripts/generate-catalog.mjs
	node --check packages/good/index.js
	node --check packages/canary/index.js
	node --check packages/canary/postinstall.js

microvm-artifact: fixtures ## Assemble the MicroVM image build context.
	./scripts/prepare-microvm-artifact

runner-format: ## Format the Python runner.
	cd $(RUNNER_DIR) && uv run --frozen ruff format .

runner-lint: ## Lint and type-check the Python runner.
	cd $(RUNNER_DIR) && uv run --frozen ruff check .
	cd $(RUNNER_DIR) && uv run --frozen pyright

runner-test: fixtures ## Run Python runner tests.
	cd $(RUNNER_DIR) && uv run --frozen pytest --cov=package_inspector --cov-report=term-missing

runner-integration: ## Verify non-root npm execution and strace in a Linux/arm64 container.
	./scripts/test-runner-container

runner-scan-good: fixtures ## Run a local inspection of the benign fixture.
	cd $(RUNNER_DIR) && uv run --frozen package-inspector scan --catalog ../fixtures/catalog.json --package @demo/good --version 1.0.0 --output ../reports/good

runner-scan-canary: fixtures ## Run a local inspection of the canary fixture.
	cd $(RUNNER_DIR) && uv run --frozen package-inspector scan --catalog ../fixtures/catalog.json --package @demo/canary --version 1.0.0 --output ../reports/canary

controller-format: ## Format Go controller code.
	cd $(CONTROLLER_DIR) && env GOPATH="$(GO_WORKSPACE)" GOTOOLCHAIN="$(GO_TOOLCHAIN)" gofmt -w $$(find . -name '*.go' -type f)

controller-generate: ## Regenerate PackageInspection CRD and RBAC from Go markers.
	cd $(CONTROLLER_DIR) && env GOPATH="$(GO_WORKSPACE)" GOTOOLCHAIN="$(GO_TOOLCHAIN)" go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.18.0 crd:crdVersions=v1 paths=./api/... output:crd:artifacts:config=../deploy/crd
	cd $(CONTROLLER_DIR) && env GOPATH="$(GO_WORKSPACE)" GOTOOLCHAIN="$(GO_TOOLCHAIN)" go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.18.0 rbac:roleName=package-inspection-controller paths=./internal/controller/... output:rbac:artifacts:config=../deploy/rbac

controller-test: ## Run Go controller tests.
	cd $(CONTROLLER_DIR) && env GOPATH="$(GO_WORKSPACE)" GOTOOLCHAIN="$(GO_TOOLCHAIN)" go vet ./...
	cd $(CONTROLLER_DIR) && env GOPATH="$(GO_WORKSPACE)" GOTOOLCHAIN="$(GO_TOOLCHAIN)" go test -race -cover ./...

controller-audit: ## Scan reachable Go dependency vulnerabilities.
	cd $(CONTROLLER_DIR) && env GOPATH="$(GO_WORKSPACE)" GOTOOLCHAIN="$(GO_TOOLCHAIN)" go run $(GOVULNCHECK) ./...

infra-format: ## Format CDK TypeScript code.
	cd $(INFRA_DIR) && $(PNPM) format

infra-test: ## Type-check and test CDK stacks.
	cd $(INFRA_DIR) && $(PNPM) format:check
	cd $(INFRA_DIR) && $(PNPM) build
	cd $(INFRA_DIR) && $(PNPM) lint
	cd $(INFRA_DIR) && $(PNPM) test

infra-audit: ## Fail on high or critical Node dependency advisories.
	cd $(INFRA_DIR) && $(PNPM) audit --audit-level high

security-audit: controller-audit infra-audit ## Run dependency vulnerability checks.

synth: microvm-artifact ## Synthesize the AWS CDK stack without deploying it.
	cd $(INFRA_DIR) && $(PNPM) synth

test: fixtures-check runner-lint runner-test controller-test infra-test ## Run all local quality gates.

preflight: ## Verify local tools and AWS Lambda MicroVM access without creating resources.
	./scripts/preflight

verify-cleanup: ## Verify there are no billable MicroVMs left in the configured Region.
	./scripts/verify-cleanup
