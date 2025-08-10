# Common Access Token (CAT) Implementation Makefile

# Set default build type if not provided
CARGO_BUILD_TYPE ?= release

.PHONY: all build test clean install help 

# Default target
all: build

help:
	@echo "Available targets:"
	@echo "  build         - Build the project"
	@echo "  test          - Run tests"
	@echo "  test-verbose  - Run tests with verbose output"
	@echo "  clean         - Clean build artifacts"
	@echo "  install       - Install the binary"
	@echo "  format        - Format code with rustfmt"
	@echo "  lint          - Run clippy linter"
	@echo "  check         - Check code without building"
	@echo "  docs          - Generate and open documentation"
	@echo "  examples      - Run all example commands"
	@echo "  demo          - Run demo"
	@echo "  security-audit - Run security audit"
	@echo "  compliance-check - Run compliance checks"
	@echo "  perf-test     - Run performance tests"
	@echo "  clean-all     - Clean everything including caches"
	@echo "  version       - Show version information"

build:
	cargo build --$(CARGO_BUILD_TYPE)

test:
	cargo test --$(CARGO_BUILD_TYPE)

test-verbose:
	cargo test --$(CARGO_BUILD_TYPE) -- --nocapture

clean: 
	cargo clean

install:
	cargo install --path .

run-hmac: build
	@echo "Running Rust CLI with HMAC256..."
	cargo run --$(CARGO_BUILD_TYPE) --bin cat-cli generate-hmac

run-es256: build
	@echo "Running Rust CLI with ES256..."
	cargo run --$(CARGO_BUILD_TYPE) --bin cat-cli generate-es256

run-ps256: build
	@echo "Running Rust CLI with PS256..."
	cargo run --$(CARGO_BUILD_TYPE) --bin cat-cli generate-ps256

run-bench: build
	cargo bench

format:
	cargo fmt

lint:
	cargo clippy -- -D warnings

check:
	cargo check --all-targets --all-features

docs:
	cargo doc --no-deps --open


perf-test: build
	@echo "⚡ Running performance tests..."
	cargo bench --bench token_bench 2>/dev/null || echo "No benchmarks found, skipping..."

package:
	@echo "📦 Creating Rust package..."
	cargo package --allow-dirty

# Example and demo targets
examples: run-hmac run-es256 run-ps256
	@echo "🎯 All examples completed"

demo: examples
	@echo "🎭 Demo complete"

# Security and compliance targets
security-audit:
	@echo " Running security audit..."
	cargo audit 2>/dev/null || echo "cargo-audit not installed, install with: cargo install cargo-audit"

compliance-check:
	@echo "Running compliance checks..."
	@echo "Checking for CTA-5007-B compliance..."
	cargo test --$(CARGO_BUILD_TYPE) test_all_cat_claims
	@echo "Compliance check complete"

# Docker targets (if Dockerfile exists)
docker-build:
	@if [ -f Dockerfile ]; then \
		echo "🐳 Building Docker image..."; \
		docker build -t cat-impl .; \
	else \
		echo "No Dockerfile found, skipping Docker build"; \
	fi

docker-test: docker-build
	@echo "🐳 Running tests in Docker..."
	docker run --rm cat-impl make test

# Clean everything including caches
clean-all: clean
	rm -rf target/

# Version information
version:
	@echo "📊 Version Information:"
	@echo "Rust version: $$(rustc --version 2>/dev/null || echo 'Not installed')"
	@echo "Cargo version: $$(cargo --version 2>/dev/null || echo 'Not installed')"
