# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2024-12-20

### Added
- Initial release of pqready
- Deep TLS handshake analysis for quantum-secure encryption detection
- Support for X25519MLKEM768 and X25519Kyber768Draft key exchange detection
- Command-line interface with verbose and JSON output options
- Cross-platform support (Windows, macOS, Linux)
- Regular and deep analysis modes
- Comprehensive error handling and user-friendly messages
- Unit tests for core functionality

### Features
- **Deep Analysis Mode**: Low-level TLS handshake inspection (default)
- **Regular Analysis Mode**: High-level library-based analysis
- **JSON Output**: Machine-readable results for integration
- **Verbose Mode**: Detailed analysis output
- **Configurable Timeouts**: Customizable connection timeouts
- **Color-coded Output**: Easy-to-read results with visual indicators

### Technical Details
- Built with Rust for performance and safety
- Async/await support for non-blocking operations
- Custom TLS handshake parser for deep analysis
- Support for quantum-secure key exchange algorithms:
  - X25519+ML-KEM-768 (0x11ec)
  - X25519+Kyber768-Draft00 (0x6399)
- Fallback to classical algorithms when quantum-secure ones unavailable

[0.1.0]: https://github.com/degan/pqready/releases/tag/v0.1.0 