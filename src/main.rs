use anyhow::{anyhow, Result};
use clap::{Arg, Command};
use colored::*;
use std::net::{TcpStream as StdTcpStream, ToSocketAddrs};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{rustls, TlsConnector};
use url::Url;

mod tls_inspector;

/// Represents the result of a quantum security scan
#[derive(Debug, serde::Serialize)]
struct ScanResult {
    /// The URL that was tested
    url: String,
    /// Whether the server supports quantum-secure encryption
    supports_quantum: bool,
    /// The TLS version negotiated
    tls_version: Option<String>,
    /// The cipher suite used
    cipher_suite: Option<String>,
    /// The key exchange algorithm used
    key_exchange: Option<String>,
    /// Any error that occurred during scanning
    error: Option<String>,
}

impl ScanResult {
    fn new(url: String) -> Self {
        Self {
            url,
            supports_quantum: false,
            tls_version: None,
            cipher_suite: None,
            key_exchange: None,
            error: None,
        }
    }

    fn with_error(url: String, error: String) -> Self {
        Self {
            url,
            supports_quantum: false,
            tls_version: None,
            cipher_suite: None,
            key_exchange: None,
            error: Some(error),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = Command::new("pqready")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Your Name <your.email@example.com>")
        .about("A cross-platform CLI tool to test for quantum-secure encryption support")
        .long_about("Tests HTTPS servers for quantum-secure encryption support (X25519MLKEM768 key exchange).\n\nBased on Apple's quantum-secure encryption specifications from iOS 26, iPadOS 26, macOS Tahoe 26 and visionOS 26.\n\nDeep TLS handshake analysis is enabled by default for accurate quantum detection. Use --regular for high-level library analysis (limited detection capabilities).")
        .after_help("EXAMPLES:\n    pqready https://example.com\n    pqready -v https://github.com\n    pqready -j https://google.com\n    pqready --regular -v https://cloudflare.com")
        .arg(
            Arg::new("url")
                .help("The HTTPS URL to test")
                .required(true)
                .value_name("URL")
                .index(1),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose output")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("json")
                .short('j')
                .long("json")
                .help("Output results in JSON format")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .help("Connection timeout in seconds")
                .value_name("SECONDS")
                .default_value("10"),
        )
        .arg(
            Arg::new("regular")
                .short('r')
                .long("regular")
                .help("Use regular high-level TLS analysis (limited quantum detection)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("conservative")
                .short('c')
                .long("conservative")
                .help("Use conservative ClientHello (for servers that reject unknown groups)")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let url_str = matches.get_one::<String>("url").unwrap();
    let verbose = matches.get_flag("verbose");
    let json_output = matches.get_flag("json");
    let regular = matches.get_flag("regular");
    let conservative = matches.get_flag("conservative");
    let timeout: u64 = matches
        .get_one::<String>("timeout")
        .unwrap()
        .parse()
        .map_err(|_| anyhow!("Invalid timeout value"))?;

    // Validate and parse URL
    let url = match Url::parse(url_str) {
        Ok(u) => {
            if u.scheme() != "https" {
                return Err(anyhow!("Only HTTPS URLs are supported. Please use 'https://' prefix."));
            }
            u
        }
        Err(_) => {
            // Try adding https:// prefix
            let with_https = format!("https://{}", url_str);
            match Url::parse(&with_https) {
                Ok(u) => u,
                Err(e) => return Err(anyhow!("Invalid URL format '{}': {}", url_str, e)),
            }
        }
    };

    if verbose && !json_output {
        println!("{}", "🔍 Quantum Security Scanner".bold().blue());
        println!("Testing: {}", url.as_str().yellow());
        println!("Timeout: {}s", timeout);
        println!();
    }

    let result = if regular {
        scan_quantum_support(&url, timeout, verbose && !json_output).await
    } else {
        scan_quantum_support_deep(&url, timeout, verbose && !json_output, conservative).await
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print_result(&result, verbose);
    }

    Ok(())
}

async fn scan_quantum_support_deep(
    url: &Url,
    timeout_secs: u64,
    verbose: bool,
    _conservative: bool,
) -> ScanResult {
    let host = match url.host_str() {
        Some(h) => h,
        None => return ScanResult::with_error(url.to_string(), "Invalid hostname".to_string()),
    };

    let port = url.port().unwrap_or(443);

    if verbose {
        println!("🔬 Starting DEEP quantum security analysis");
        println!("🔌 Connecting to {}:{}", host, port);
    }

    // Resolve hostname
    let addr = match format!("{}:{}", host, port).to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr,
            None => {
                return ScanResult::with_error(
                    url.to_string(),
                    "Could not resolve hostname".to_string(),
                )
            }
        },
        Err(e) => {
            return ScanResult::with_error(url.to_string(), format!("DNS resolution failed: {}", e))
        }
    };

    if verbose {
        println!("📡 Resolved to: {}", addr);
    }

    // Create synchronous TCP connection for low-level analysis
    let tcp_stream =
        match StdTcpStream::connect_timeout(&addr, std::time::Duration::from_secs(timeout_secs)) {
            Ok(stream) => stream,
            Err(e) => {
                return ScanResult::with_error(url.to_string(), format!("Connection failed: {}", e))
            }
        };

    if verbose {
        println!("🤝 TCP connection established");
    }

    // Perform deep TLS handshake analysis
    let mut inspector = match tls_inspector::TlsInspector::new(tcp_stream) {
        Ok(inspector) => inspector,
        Err(e) => {
            return ScanResult::with_error(
                url.to_string(),
                format!("Failed to create TLS inspector: {}", e),
            )
        }
    };

    let handshake_info = match inspector.perform_quantum_handshake_analysis(host, verbose) {
        Ok(info) => info,
        Err(e) => {
            return ScanResult::with_error(
                url.to_string(),
                format!("TLS handshake analysis failed: {}", e),
            )
        }
    };

    // Convert handshake info to ScanResult
    let mut result = ScanResult::new(url.to_string());
    result.supports_quantum = handshake_info.supports_quantum;

    if let Some(version) = handshake_info.negotiated_version {
        result.tls_version = Some(format!("0x{:04x}", version));
    }

    if let Some(cipher) = handshake_info.cipher_suite {
        result.cipher_suite = Some(format!("0x{:04x}", cipher));
    }

    if let Some(group) = handshake_info.server_selected_group {
        result.key_exchange = Some(tls_inspector::format_group_name(group));
    } else {
        result.key_exchange = Some("No key exchange detected".to_string());
    }

    if verbose {
        println!("🔬 Deep analysis complete!");
        if handshake_info.supports_quantum {
            println!("🎯 QUANTUM-SECURE ENCRYPTION CONFIRMED!");
        } else {
            println!("❌ No quantum-secure encryption found");
        }
    }

    result
}

async fn scan_quantum_support(url: &Url, timeout_secs: u64, verbose: bool) -> ScanResult {
    let host = match url.host_str() {
        Some(h) => h,
        None => return ScanResult::with_error(url.to_string(), "Invalid hostname".to_string()),
    };

    let port = url.port().unwrap_or(443);

    if verbose {
        println!("🔧 Starting REGULAR quantum security analysis (high-level)");
        println!("🔌 Connecting to {}:{}", host, port);
    }

    // Create a custom TLS config that supports quantum-secure algorithms
    let config = create_quantum_tls_config();
    let connector = TlsConnector::from(Arc::new(config));

    // Resolve hostname
    let addr = match format!("{}:{}", host, port).to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr,
            None => {
                return ScanResult::with_error(
                    url.to_string(),
                    "Could not resolve hostname".to_string(),
                )
            }
        },
        Err(e) => {
            return ScanResult::with_error(url.to_string(), format!("DNS resolution failed: {}", e))
        }
    };

    if verbose {
        println!("📡 Resolved to: {}", addr);
    }

    // Connect with timeout
    let tcp_stream = match tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        TcpStream::connect(addr),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            return ScanResult::with_error(url.to_string(), format!("Connection failed: {}", e))
        }
        Err(_) => return ScanResult::with_error(url.to_string(), "Connection timeout".to_string()),
    };

    if verbose {
        println!("🤝 TCP connection established");
    }

    // Perform TLS handshake
    let server_name = match rustls::ServerName::try_from(host) {
        Ok(name) => name,
        Err(e) => {
            return ScanResult::with_error(url.to_string(), format!("Invalid server name: {}", e))
        }
    };

    let tls_stream = match tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        connector.connect(server_name, tcp_stream),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            return ScanResult::with_error(url.to_string(), format!("TLS handshake failed: {}", e))
        }
        Err(_) => {
            return ScanResult::with_error(url.to_string(), "TLS handshake timeout".to_string())
        }
    };

    if verbose {
        println!("🔐 TLS handshake completed");
    }

    // Analyze the TLS connection
    let (_, connection) = tls_stream.into_inner();
    analyze_tls_connection(url.to_string(), &connection, verbose)
}

fn create_quantum_tls_config() -> rustls::ClientConfig {
    use rustls::RootCertStore;

    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let mut config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Note: Actual quantum-secure algorithms like X25519MLKEM768 are not yet
    // widely supported in rustls. This is a simplified implementation that
    // demonstrates the concept and structure.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    config
}

fn analyze_tls_connection(
    url: String,
    connection: &rustls::ClientConnection,
    verbose: bool,
) -> ScanResult {
    let mut result = ScanResult::new(url);

    // Get negotiated cipher suite
    if let Some(suite) = connection.negotiated_cipher_suite() {
        let cipher_name = format!("{:?}", suite.suite());
        result.cipher_suite = Some(cipher_name.clone());
        if verbose {
            println!("🔑 Cipher suite: {}", cipher_name);
        }
    }

    // Get protocol version
    if let Some(version) = connection.protocol_version() {
        let version_str = format!("{:?}", version);
        result.tls_version = Some(version_str.clone());
        if verbose {
            println!("📋 TLS version: {}", version_str);
        }
    }

    // Extract key exchange information and check for quantum-secure algorithms
    let (key_exchange, is_quantum_secure) = analyze_key_exchange(connection, verbose);
    result.key_exchange = Some(key_exchange);
    result.supports_quantum = is_quantum_secure;

    if verbose {
        println!(
            "🛡️  Quantum-secure: {}",
            if result.supports_quantum {
                "YES".green()
            } else {
                "NO".red()
            }
        );
    }

    result
}

fn analyze_key_exchange(connection: &rustls::ClientConnection, verbose: bool) -> (String, bool) {
    // Try to extract key exchange information from the cipher suite
    let cipher_suite = connection.negotiated_cipher_suite();
    let protocol_version = connection.protocol_version();

    let mut key_exchange_info = String::new();
    let mut is_quantum_secure = false;

    // Analyze the cipher suite for key exchange information
    if let Some(suite) = cipher_suite {
        let suite_name = format!("{:?}", suite.suite());

        // Extract key exchange method from cipher suite name
        // Note: This is limited by what rustls exposes. In a full implementation,
        // you would need deeper TLS handshake inspection or use a library that
        // provides access to the negotiated groups/key shares.

        if suite_name.contains("ECDHE") {
            key_exchange_info.push_str("ECDHE");
        } else if suite_name.contains("DHE") {
            key_exchange_info.push_str("DHE");
        } else if suite_name.contains("RSA") {
            key_exchange_info.push_str("RSA");
        } else {
            key_exchange_info.push_str("Unknown from cipher");
        }

        // Check for TLS 1.3 (required for quantum-secure algorithms)
        if let Some(version) = protocol_version {
            if format!("{:?}", version) == "TLSv1_3" {
                key_exchange_info.push_str(" (TLS 1.3)");

                // In TLS 1.3, we would need to inspect the actual key_share extension
                // to determine if X25519MLKEM768 was used. This requires lower-level
                // access than rustls currently provides.

                // For now, we can only make educated guesses based on what's available
                is_quantum_secure = check_for_quantum_indicators(&suite_name, verbose);
            }
        }
    }

    if key_exchange_info.is_empty() {
        key_exchange_info = "Unknown".to_string();
    }

    if verbose && !key_exchange_info.contains("Unknown") {
        println!("🔄 Key exchange: {}", key_exchange_info);
    }

    (key_exchange_info, is_quantum_secure)
}

fn check_for_quantum_indicators(cipher_suite_name: &str, verbose: bool) -> bool {
    // Note: This is a heuristic approach since rustls doesn't expose
    // the actual negotiated groups (like X25519MLKEM768).
    //
    // In a real implementation, you would need:
    // 1. Access to the ClientHello and ServerHello messages
    // 2. Inspection of the supported_groups extension
    // 3. Analysis of the key_share extension
    // 4. Verification that X25519MLKEM768 was actually negotiated

    if verbose {
        println!(
            "🔬 Analyzing cipher suite for quantum indicators: {}",
            cipher_suite_name
        );
        println!("⚠️  Note: Deep TLS inspection limited by rustls API");
    }

    // Look for any hints in the cipher suite name
    // (This is very limited and mostly for demonstration)
    let quantum_indicators = ["MLKEM", "KYBER", "X25519MLKEM768", "HYBRID", "PQ"];

    for indicator in &quantum_indicators {
        if cipher_suite_name.to_uppercase().contains(indicator) {
            if verbose {
                println!("🎯 Found potential quantum indicator: {}", indicator);
            }
            return true;
        }
    }

    // Additional checks could include:
    // - Inspecting connection peer certificates for PQ signatures
    // - Looking for specific TLS extensions
    // - Checking for hybrid key exchange patterns

    false
}

fn print_result(result: &ScanResult, verbose: bool) {
    println!();
    println!("{}", "🔍 Quantum Security Test Results".bold().blue());
    println!("URL: {}", result.url.yellow());

    if let Some(error) = &result.error {
        println!("❌ Error: {}", error.red());
        return;
    }

    let status = if result.supports_quantum {
        "✅ SUPPORTED".green().bold()
    } else {
        "❌ NOT SUPPORTED".red().bold()
    };

    println!("Quantum-secure encryption: {}", status);

    if verbose {
        if let Some(tls_version) = &result.tls_version {
            println!("TLS Version: {}", tls_version);
        }
        if let Some(cipher_suite) = &result.cipher_suite {
            println!("Cipher Suite: {}", cipher_suite);
        }
        if let Some(key_exchange) = &result.key_exchange {
            println!("Key Exchange: {}", key_exchange);
        }
    }

    println!();

    // Add appropriate warnings based on analysis mode
    if result
        .key_exchange
        .as_ref()
        .is_some_and(|ke| ke.contains("Unknown from cipher"))
    {
        println!("{}", "⚠️  Detection Limitations:".yellow().bold());
        println!(
            "{}",
            "   • Current TLS libraries have limited access to key exchange details".dimmed()
        );
        println!(
            "{}",
            "   • True X25519MLKEM768 detection requires deeper handshake inspection".dimmed()
        );
        println!(
            "{}",
            "   • Deep analysis is the default - use --regular to force high-level analysis"
                .dimmed()
        );
        println!();
    } else if result.key_exchange.as_ref().is_some_and(|ke| {
        ke.contains("(Quantum-Secure)") || ke.contains("(Classical)")
    }) {
        println!("{}", "✅ Deep Analysis Mode:".green().bold());
        println!(
            "{}",
            "   • Low-level TLS handshake inspection performed".dimmed()
        );
        println!(
            "{}",
            "   • Actual key exchange algorithms detected from handshake messages".dimmed()
        );
        println!(
            "{}",
            "   • Results show true negotiated algorithms, not library interpretations".dimmed()
        );
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_result_creation() {
        let result = ScanResult::new("https://example.com".to_string());
        assert_eq!(result.url, "https://example.com");
        assert!(!result.supports_quantum);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_scan_result_with_error() {
        let result = ScanResult::with_error(
            "https://example.com".to_string(),
            "Connection failed".to_string(),
        );
        assert_eq!(result.url, "https://example.com");
        assert!(!result.supports_quantum);
        assert_eq!(result.error, Some("Connection failed".to_string()));
    }

    #[test]
    fn test_url_parsing() {
        // Test HTTPS URL
        let url = Url::parse("https://example.com").unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.port(), None);

        // Test HTTPS URL with port
        let url = Url::parse("https://example.com:8443").unwrap();
        assert_eq!(url.port(), Some(8443));
    }

    #[test]
    fn test_format_group_name() {
        use crate::tls_inspector::format_group_name;
        
        assert_eq!(format_group_name(0x001d), "X25519 (Classical)");
        assert_eq!(format_group_name(0x11ec), "X25519+ML-KEM-768 (Quantum-Secure)");
        assert_eq!(format_group_name(0x6399), "X25519+Kyber768-Draft (Quantum-Secure)");
        assert_eq!(format_group_name(0x9999), "Unknown Group (0x9999)");
    }
}
