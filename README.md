# pqready - Post-Quantum TLS Validator

A cross-platform CLI tool to test TLS/HTTPS servers for quantum-secure encryption support, specifically the `X25519MLKEM768` key exchange algorithm introduced in Apple's latest operating systems.

## Overview

Based on Apple's quantum-secure encryption specifications from [iOS 26, iPadOS 26, macOS Tahoe 26 and visionOS 26](https://support.apple.com/en-my/122756), this tool tests whether HTTPS servers support hybrid, quantum-secure key exchange algorithms that are designed to protect against future quantum computer attacks.

## Features

- ✅ **Cross-platform**: Works on Windows, macOS, and Linux
- 🔍 **TLS Analysis**: Detailed analysis of TLS connections and cipher suites
- 🛡️ **Quantum Security Detection**: Tests for X25519MLKEM768 key exchange support
- 🎨 **Colorized Output**: Easy-to-read results with color coding
- 📊 **JSON Output**: Machine-readable output format
- ⚡ **Async Operations**: Fast, non-blocking network operations
- 🕒 **Configurable Timeouts**: Customizable connection timeouts

## Installation

### Install Pre-built Binary (Recommended)

Download the latest release for your platform from [GitHub Releases](https://github.com/degan/pqready/releases):

#### macOS
1. Download `pqready` from the [releases page](https://github.com/degan/pqready/releases)
2. Open Terminal and navigate to your Downloads folder
3. Remove quarantine and run/install:
```bash
# Remove macOS quarantine (required for unsigned binaries)
chmod +x pqready
xattr -d com.apple.quarantine pqready
./pqready example.com
# optional
sudo mv pqready /usr/local/bin/pqready
```

#### Linux
1. Download `pqready` from the [releases page](https://github.com/degan/pqready/releases)  
2. Open a terminal and navigate to your downloads folder
3. Make executable and run/install:
```bash
# install
chmod +x pqready
./pqready example.com
# optional
sudo mv pqready /usr/local/bin/
```

#### Windows
Download `pqready.exe` from the [releases page](https://github.com/degan/pqready/releases) and (OPTIONAL) add it to your PATH.

### Install from Cargo

```bash
cargo install pqready
```

### Building from Source

#### Prerequisites

- Rust 1.70 or later
- Cargo package manager

#### Build Steps

```bash
git clone https://github.com/degan/pqready.git
cd pqready

# Using Make (recommended)
make release

# Or using Cargo directly
cargo build --release
```

The binary will be available at `target/release/pqready` (or `target/release/pqready.exe` on Windows).

## Usage

### Basic Usage

```bash
# Test a single URL
pqready https://example.com

# Test with verbose output
pqready -v https://example.com

# Test with JSON output
pqready -j https://example.com

# Test with custom timeout
pqready -t 30 https://example.com
```

### Command Line Options

```
pqready [OPTIONS] <URL>

Arguments:
  <URL>  The HTTPS URL to test

Options:
  -v, --verbose          Enable verbose output
  -j, --json            Output results in JSON format
  -t, --timeout <SECONDS> Connection timeout in seconds [default: 10]
  -r, --regular         Use regular high-level TLS analysis (limited quantum detection)
  -c, --conservative    Use conservative ClientHello (for servers that reject unknown groups)
  -n, --no-color        Disable color and emoji output
  -h, --help            Print help
  -V, --version         Print version
```

### Examples

#### Basic Test
```bash
$ pqready https://google.com

🔍 Quantum Security Test Results
URL: https://google.com/
Quantum-secure encryption: ❌ NOT SUPPORTED
```

#### Verbose Output
```bash
$ pqready -v https://example.com

🔍 Quantum Security Scanner
Testing: https://example.com/
Timeout: 10s

🔌 Connecting to example.com:443
📡 Resolved to: 93.184.216.34:443
🤝 TCP connection established
🔐 TLS handshake completed
🔑 Cipher suite: TLS13_AES_256_GCM_SHA384
📋 TLS version: TLSv1_3
🛡️  Quantum-secure: NO

🔍 Quantum Security Test Results
URL: https://example.com/
Quantum-secure encryption: ❌ NOT SUPPORTED
TLS Version: TLSv1_3
Cipher Suite: TLS13_AES_256_GCM_SHA384
Key Exchange: Unknown
```

#### JSON Output
```bash
$ pqready -j https://example.com
{
  "url": "https://example.com/",
  "supports_quantum": false,
  "tls_version": "TLSv1_3",
  "cipher_suite": "TLS13_AES_256_GCM_SHA384",
  "key_exchange": "Unknown",
  "error": null
}
```

## Technical Details

### Quantum-Secure Encryption

This tool tests for the `X25519MLKEM768` key exchange algorithm, which is a hybrid approach combining:

- **X25519**: Classical elliptic curve Diffie-Hellman
- **ML-KEM-768**: Post-quantum key encapsulation mechanism

This hybrid approach provides:
- **Current security**: Protection against classical computers
- **Future security**: Protection against quantum computers
- **Compatibility**: Fallback to classical algorithms when quantum-secure ones aren't supported

### Supported Platforms

- **Windows**: Windows 10 and later
- **macOS**: macOS 10.15 and later  
- **Linux**: Most modern distributions

### Limitations

- Currently, most servers do not support `X25519MLKEM768`
- The quantum-secure algorithms are still being deployed across the internet
- This tool provides a foundation that will become more useful as server adoption increases

## Development

### Quick Start with Make

```bash
# Show all available commands
make help

# Build debug version
make build

# Build release version
make release

# Run with example
make run

# Run demo with multiple URLs
make demo

# Development workflow (format + lint + test + build)
make dev

# Clean build artifacts
make clean
```

### Available Make Targets

- **build** - Build debug version
- **release** - Build optimized release version
- **install** - Install binary to system
- **test** - Run tests
- **run** - Run with example URL
- **run-verbose** - Run with verbose output
- **run-json** - Run with JSON output
- **demo** - Run demo with multiple URLs
- **dev** - Development workflow (fmt + clippy + test + build)
- **clean** - Clean build artifacts
- **help** - Show all available commands

### Manual Cargo Commands

```bash
# Building
cargo build              # Debug build
cargo build --release    # Release build

# Testing
cargo test

# Running
cargo run -- https://example.com -v

# Code quality
cargo clippy             # Linting
cargo fmt               # Formatting
```

## Releases and Publishing

### Creating a New Release

Follow this workflow to create a new release:

#### 1. Prepare the Release
```bash
# Update version in Cargo.toml
# Example: version = "0.1.1" or "0.2.0"

# Update CHANGELOG.md with new version and proper date
## [0.1.1] - 2025-01-15
### Added
- New feature descriptions
### Fixed  
- Bug fix descriptions
### Changed
- Breaking change descriptions (for major versions)
```

#### 2. Test Everything Locally
```bash
make dev 
```

#### 3. Commit and Push Changes
```bash
git add -A
git commit -m "Bump version to 0.1.1"
git push
```

#### 4. Create and Push Tag
```bash
git tag v0.1.1
git push origin v0.1.1
```

#### 5. Automatic Release Creation
When you push the tag, GitHub Actions will automatically:
- ✅ Build binaries for Windows, macOS, and Linux
- ✅ Create GitHub release with binaries attached
- ✅ Use CHANGELOG content as release notes
- ✅ Run all CI checks

#### 6. Publish to Crates.io (Optional)
```bash
# Test publish without actually doing it
make publish-check

# Actually publish to crates.io
make publish
```

### Versioning Guidelines

Follow [Semantic Versioning](https://semver.org/):
- **Patch** (0.1.1): Bug fixes, no breaking changes
- **Minor** (0.2.0): New features, no breaking changes  
- **Major** (1.0.0): Breaking changes

### Publishing Targets

Your Makefile includes these publishing commands:
- `make publish-check` - Dry run publish check (requires clean git)
- `make publish` - Full publish workflow with CI checks and user confirmation
- `make publish-check-dirty` - Development version allowing uncommitted changes
- `make publish-dirty` - Development publish allowing uncommitted changes

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## References

- [Apple Support: Prepare your network for quantum-secure encryption in TLS](https://support.apple.com/en-my/122756)
- [NIST Post-Quantum Cryptography Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://tools.ietf.org/html/rfc8446)
- [Cloudflare Research: Post-Quantum Key Agreement](https://pq.cloudflareresearch.com)

## Acknowledgments

- Apple Inc. for the quantum-secure encryption specifications, even though as of first release apple.com does not appear to support.
- The post-quantum cryptography research community


## TODO

1. Batch URLs from file