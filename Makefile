# pqready - Quantum Security Scanner Makefile

# Project information
PROJECT_NAME := pqready
BINARY_NAME := pqready
VERSION := 0.1.0

# Default target
.PHONY: all
all: build

# Build targets
.PHONY: build
build:
	@echo "🔨 Building $(PROJECT_NAME) (debug)..."
	cargo build

.PHONY: release
release:
	@echo "🚀 Building $(PROJECT_NAME) (release)..."
	cargo build --release

.PHONY: install
install: release
	@echo "📦 Installing $(PROJECT_NAME)..."
	cargo install --path .

# Test targets
.PHONY: test
test:
	@echo "🧪 Running tests..."
	cargo test

.PHONY: test-verbose
test-verbose:
	@echo "🧪 Running tests (verbose)..."
	cargo test -- --nocapture

# Development targets
.PHONY: check
check:
	@echo "🔍 Checking code..."
	cargo check

.PHONY: clippy
clippy:
	@echo "📎 Running clippy..."
	cargo clippy -- -D warnings

.PHONY: fmt
fmt:
	@echo "🎨 Formatting code..."
	cargo fmt

.PHONY: fmt-check
fmt-check:
	@echo "🎨 Checking code formatting..."
	cargo fmt -- --check

# Run targets
.PHONY: run
run:
	@echo "🏃 Running $(PROJECT_NAME) with example..."
	cargo run -- https://example.com

.PHONY: run-verbose
run-verbose:
	@echo "🏃 Running $(PROJECT_NAME) with verbose output..."
	cargo run -- -v https://github.com

.PHONY: run-json
run-json:
	@echo "🏃 Running $(PROJECT_NAME) with JSON output..."
	cargo run -- -j https://google.com

.PHONY: run-deep
run-deep:
	@echo "🔬 Running $(PROJECT_NAME) with deep analysis (default)..."
	cargo run -- -v https://github.com

.PHONY: run-regular
run-regular:
	@echo "🔧 Running $(PROJECT_NAME) with regular analysis (high-level)..."
	cargo run -- --regular -v https://github.com

.PHONY: run-deep-json
run-deep-json:
	@echo "🔬 Running $(PROJECT_NAME) with deep analysis (JSON)..."
	cargo run -- -j https://github.com

# Utility targets
.PHONY: clean
clean:
	@echo "🧹 Cleaning build artifacts..."
	cargo clean

.PHONY: update
update:
	@echo "⬆️  Updating dependencies..."
	cargo update

.PHONY: audit
audit:
	@echo "🔒 Auditing dependencies for security vulnerabilities..."
	cargo audit

# Documentation targets
.PHONY: doc
doc:
	@echo "📚 Building documentation..."
	cargo doc --no-deps

.PHONY: doc-open
doc-open:
	@echo "📚 Building and opening documentation..."
	cargo doc --no-deps --open

# Binary targets
.PHONY: strip
strip: release
	@echo "🪚 Stripping release binary..."
	strip target/release/$(BINARY_NAME)

.PHONY: size
size: release
	@echo "📏 Binary size information:"
	@ls -lh target/release/$(BINARY_NAME)
	@file target/release/$(BINARY_NAME)

# Development workflow
.PHONY: dev
dev: fmt clippy test build

.PHONY: ci
ci: fmt-check clippy test build

# Demo targets
.PHONY: demo
demo: build
	@echo "🎬 Running demo sequence..."
	@echo "\n=== Testing Google ==="
	cargo run -- https://google.com
	@echo "\n=== Testing GitHub (verbose) ==="
	cargo run -- -v https://github.com
	@echo "\n=== Testing Cloudflare (JSON) ==="
	cargo run -- -j https://cloudflare.com

.PHONY: demo-deep
demo-deep: build
	@echo "🔬 Running analysis demo sequence (deep is default)..."
	@echo "\n=== Deep Analysis: GitHub (default behavior) ==="
	cargo run -- -v https://github.com
	@echo "\n=== Deep Analysis: Google ==="
	cargo run -- -v https://google.com
	@echo "\n=== Regular vs Deep Analysis Comparison ==="
	@echo "--- Regular Analysis (high-level) ---"
	cargo run -- --regular -v https://github.com
	@echo "--- Deep Analysis (default) ---"
	cargo run -- -v https://github.com

# Help target
.PHONY: help
help:
	@echo "$(PROJECT_NAME) v$(VERSION) - Quantum Security Scanner"
	@echo ""
	@echo "Available targets:"
	@echo "  build         Build debug version"
	@echo "  release       Build optimized release version"
	@echo "  install       Install binary to system"
	@echo "  test          Run tests"
	@echo "  test-verbose  Run tests with verbose output"
	@echo "  check         Check code without building"
	@echo "  clippy        Run clippy linter"
	@echo "  fmt           Format code"
	@echo "  fmt-check     Check code formatting"
	@echo "  run           Run with example URL"
	@echo "  run-verbose   Run with verbose output"
	@echo "  run-json      Run with JSON output"
	@echo "  run-deep      Run with deep analysis (default behavior)"
	@echo "  run-regular   Run with regular high-level analysis"
	@echo "  run-deep-json Run with deep analysis (JSON output)"
	@echo "  clean         Clean build artifacts"
	@echo "  update        Update dependencies"
	@echo "  audit         Audit dependencies for vulnerabilities"
	@echo "  doc           Build documentation"
	@echo "  doc-open      Build and open documentation"
	@echo "  strip         Strip release binary (reduce size)"
	@echo "  size          Show binary size information"
	@echo "  dev           Development workflow (fmt + clippy + test + build)"
	@echo "  ci            CI workflow (fmt-check + clippy + test + build)"
	@echo "  demo          Run demo with multiple URLs"
	@echo "  demo-deep     Run deep analysis demo (showcases TLS handshake inspection)"
	@echo "  help          Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make build                    # Build debug version"
	@echo "  make release                  # Build release version"
	@echo "  make demo                     # Run demo"
	@echo "  make demo-deep                # Run deep analysis demo"
	@echo "  make dev                      # Full development check"
	@echo ""
	@echo "Direct binary usage:"
	@echo "  ./target/release/pqready https://example.com"
	@echo "  ./target/release/pqready -v https://github.com"
	@echo "  ./target/release/pqready -j https://google.com"
	@echo "  ./target/release/pqready --regular -v https://github.com  # Use high-level analysis"
	@echo ""
	@echo "Note: Deep analysis is the default behavior (best quantum detection)."
	@echo "Use --regular for high-level analysis (limited quantum detection)." 