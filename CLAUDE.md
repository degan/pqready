# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is **pqready**, a cross-platform CLI tool written in Rust that tests TLS/HTTPS servers for quantum-secure encryption support, specifically the `X25519MLKEM768` key exchange algorithm. The tool performs deep TLS handshake analysis to detect post-quantum cryptographic algorithms.

## Development Commands

### Core Commands (via Make)
- `make build` - Build debug version
- `make release` - Build optimized release version  
- `make test` - Run all tests
- `make dev` - Full development workflow: `fmt + clippy-all + test + audit + build`
- `make ci` - CI workflow: `fmt-check + clippy-all + test + audit + build`
- `make clean` - Clean build artifacts

### Code Quality
- `make fmt` - Format code with rustfmt
- `make fmt-check` - Check code formatting (CI)
- `make clippy-all` - Run clippy with all targets and features
- `make audit` - Security audit dependencies with cargo-audit

### Running the Tool
- `make run` - Run with example.com
- `make run-verbose` - Run with verbose output on github.com
- `make run-json` - Run with JSON output on google.com
- `make demo` - Demo with multiple URLs
- `make demo-deep` - Demo showcasing deep vs regular analysis

### Publishing (for maintainers)
- `make publish-check` - Dry run publish to crates.io
- `make publish` - Full publish workflow with CI checks

## Architecture

### Core Components

**Binary Structure:**
- `src/main.rs` - Main CLI application with argument parsing, URL validation, and result formatting
- `src/tls_inspector.rs` - Low-level TLS handshake analysis module for quantum detection

**Two Analysis Modes:**
1. **Deep Analysis (Default)** - Custom TLS handshake implementation that sends ClientHello with quantum-secure groups and parses ServerHello responses to detect actual negotiated key exchange algorithms
2. **Regular Analysis** - High-level analysis using rustls library (limited quantum detection capabilities)

### Key Technical Details

**Quantum-Secure Algorithms Detected:**
- `X25519MLKEM768` (0x11ec) - X25519+ML-KEM-768 (Cloudflare recommended)
- `X25519_KYBER768_DRAFT` (0x6399) - X25519+Kyber768-Draft00 (current implementation)
- Classical fallback: `X25519` (0x001d)

**TLS Implementation:**
- Custom ClientHello generation with quantum-secure supported_groups and key_share extensions
- Raw TLS record and handshake message parsing
- ServerHello analysis to extract negotiated key exchange algorithm
- Support for TLS alerts and error handling

**Output Modes:**
- Human-readable colored output with emojis (default)
- JSON output for machine parsing (`-j` flag)
- Verbose mode with detailed handshake analysis (`-v` flag)
- No-color mode for CI environments (`-n` flag)

## Dependencies

**Core Dependencies:**
- `clap` - CLI argument parsing
- `tokio` + `tokio-rustls` - Async runtime and TLS (for regular mode)
- `rustls` + `webpki-roots` - TLS implementation and root certificates
- `colored` - Terminal color output
- `anyhow` - Error handling
- `serde` + `serde_json` - JSON serialization
- `url` - URL parsing

## Testing

Run tests with `make test` or `cargo test`. The codebase has comprehensive unit tests covering:
- URL parsing and validation
- TLS handshake analysis
- Quantum algorithm detection
- JSON output formatting  
- Color configuration
- Error handling scenarios

## Color and Output Configuration

The tool automatically detects terminal capabilities and respects:
- `--no-color` flag
- `NO_COLOR` environment variable  
- `TERM=dumb` environment variable
- Pipe/redirection detection

## Release Process

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md` 
3. Run `make dev` to verify everything works
4. Commit changes: `git commit -m "Bump version to X.X.X"`
5. Create and push tag: `git tag vX.X.X && git push origin vX.X.X`
6. GitHub Actions automatically creates release with cross-platform binaries
7. Optionally publish to crates.io with `make publish`

## Important Implementation Notes

- Deep analysis is the default because it provides accurate quantum detection by inspecting actual TLS handshake messages
- The tool respects server limitations and includes conservative ClientHello options
- Key shares for large post-quantum algorithms are commented out to avoid server compatibility issues
- Comprehensive error handling for various TLS failure scenarios including unsupported extensions and decode errors