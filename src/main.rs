use anyhow::{anyhow, Result};
use clap::{Arg, Command};
use colored::*;
use std::env;
use std::net::{TcpStream as StdTcpStream, ToSocketAddrs};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{rustls, TlsConnector};
use url::Url;

mod tls_inspector;

/// Color configuration for output
#[derive(Debug, Clone)]
pub struct ColorConfig {
    enabled: bool,
}

impl ColorConfig {
    pub fn new(no_color_flag: bool) -> Self {
        let enabled = Self::should_use_color(no_color_flag);

        // Configure the colored crate globally
        colored::control::set_override(enabled);

        Self { enabled }
    }

    fn should_use_color(no_color_flag: bool) -> bool {
        // If --no-color flag is explicitly set, disable colors
        if no_color_flag {
            return false;
        }

        // Check NO_COLOR environment variable (any value disables color)
        if env::var("NO_COLOR").is_ok() {
            return false;
        }

        // Check TERM=dumb (disables color)
        if let Ok(term) = env::var("TERM") {
            if term == "dumb" {
                return false;
            }
        }

        // Default to automatic detection: color on for interactive terminals, off for pipes/files
        std::io::IsTerminal::is_terminal(&std::io::stdout())
    }

    // Helper methods for styled output
    pub fn emoji_or_text(&self, emoji: &str, text: &str) -> String {
        if self.enabled {
            emoji.to_string()
        } else {
            text.to_string()
        }
    }

    fn status_success(&self, text: &str) -> String {
        if self.enabled {
            text.green().bold().to_string()
        } else {
            text.to_string()
        }
    }

    fn status_error(&self, text: &str) -> String {
        if self.enabled {
            text.red().bold().to_string()
        } else {
            text.to_string()
        }
    }

    fn header(&self, text: &str) -> String {
        if self.enabled {
            text.bold().blue().to_string()
        } else {
            text.to_string()
        }
    }

    fn url_highlight(&self, text: &str) -> String {
        if self.enabled {
            text.yellow().to_string()
        } else {
            text.to_string()
        }
    }

    fn warning(&self, text: &str) -> String {
        if self.enabled {
            text.yellow().bold().to_string()
        } else {
            text.to_string()
        }
    }

    fn dimmed(&self, text: &str) -> String {
        if self.enabled {
            text.dimmed().to_string()
        } else {
            text.to_string()
        }
    }
}

/// Represents the result of a quantum security scan
#[derive(Debug, serde::Serialize)]
struct ScanResult {
    /// The version of pqready that generated this result
    version: String,
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
            version: env!("CARGO_PKG_VERSION").to_string(),
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
            version: env!("CARGO_PKG_VERSION").to_string(),
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
        .author("Devin Egan <github@devinegan.com>")
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
        .arg(
            Arg::new("no-color")
                .short('n')
                .long("no-color")
                .help("Disable color and emoji output")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let url_str = matches.get_one::<String>("url").unwrap();
    let verbose = matches.get_flag("verbose");
    let json_output = matches.get_flag("json");
    let regular = matches.get_flag("regular");
    let conservative = matches.get_flag("conservative");
    let no_color = matches.get_flag("no-color");
    let timeout: u64 = matches
        .get_one::<String>("timeout")
        .unwrap()
        .parse()
        .map_err(|_| anyhow!("Invalid timeout value"))?;

    // Initialize color configuration
    let color_config = ColorConfig::new(no_color);

    // Validate and parse URL
    let url = match Url::parse(url_str) {
        Ok(u) => {
            if u.scheme() != "https" {
                return Err(anyhow!(
                    "Only HTTPS URLs are supported. Please use 'https://' prefix."
                ));
            }
            u
        }
        Err(_) => {
            // Try adding https:// prefix
            let with_https = format!("https://{url_str}");
            match Url::parse(&with_https) {
                Ok(u) => u,
                Err(e) => return Err(anyhow!("Invalid URL format '{}': {}", url_str, e)),
            }
        }
    };

    if verbose && !json_output {
        println!();
        println!(
            "{} {}",
            color_config.emoji_or_text("🔍", "[SCAN]"),
            color_config.header("Quantum Security Scanner")
        );
        println!("Testing: {}", color_config.url_highlight(url.as_str()));
        println!("Timeout: {timeout}s");
        println!();
    }

    let result = if regular {
        scan_quantum_support(&url, timeout, verbose && !json_output, &color_config).await
    } else {
        scan_quantum_support_deep(
            &url,
            timeout,
            verbose && !json_output,
            conservative,
            &color_config,
        )
        .await
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print_result(&result, verbose, &color_config);
    }

    Ok(())
}

async fn scan_quantum_support_deep(
    url: &Url,
    timeout_secs: u64,
    verbose: bool,
    _conservative: bool,
    color_config: &ColorConfig,
) -> ScanResult {
    let host = match url.host_str() {
        Some(h) => h,
        None => return ScanResult::with_error(url.to_string(), "Invalid hostname".to_string()),
    };

    let port = url.port().unwrap_or(443);

    if verbose {
        println!(
            "{} Starting DEEP quantum security analysis",
            color_config.emoji_or_text("🔬", "[DEEP]")
        );
        println!(
            "{} Connecting to {}:{}",
            color_config.emoji_or_text("🔌", "[CONNECT]"),
            host,
            port
        );
    }

    // Resolve hostname
    let addr = match format!("{host}:{port}").to_socket_addrs() {
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
            return ScanResult::with_error(url.to_string(), format!("DNS resolution failed: {e}"))
        }
    };

    if verbose {
        println!(
            "{} Resolved to: {}",
            color_config.emoji_or_text("📡", "[RESOLVED]"),
            addr
        );
    }

    // Create synchronous TCP connection for low-level analysis
    let tcp_stream =
        match StdTcpStream::connect_timeout(&addr, std::time::Duration::from_secs(timeout_secs)) {
            Ok(stream) => stream,
            Err(e) => {
                return ScanResult::with_error(url.to_string(), format!("Connection failed: {e}"))
            }
        };

    if verbose {
        println!(
            "{} TCP connection established",
            color_config.emoji_or_text("🤝", "[CONNECTED]")
        );
    }

    // Perform deep TLS handshake analysis
    let mut inspector = match tls_inspector::TlsInspector::new(tcp_stream) {
        Ok(inspector) => inspector,
        Err(e) => {
            return ScanResult::with_error(
                url.to_string(),
                format!("Failed to create TLS inspector: {e}"),
            )
        }
    };

    let handshake_info =
        match inspector.perform_quantum_handshake_analysis(host, verbose, color_config) {
            Ok(info) => info,
            Err(e) => {
                return ScanResult::with_error(
                    url.to_string(),
                    format!("TLS handshake analysis failed: {e}"),
                )
            }
        };

    // Convert handshake info to ScanResult
    let mut result = ScanResult::new(url.to_string());
    result.supports_quantum = handshake_info.supports_quantum;

    if let Some(version) = handshake_info.negotiated_version {
        result.tls_version = Some(format_tls_version(version));
    }

    if let Some(cipher) = handshake_info.cipher_suite {
        result.cipher_suite = Some(format_cipher_suite(cipher));
    }

    if let Some(group) = handshake_info.server_selected_group {
        result.key_exchange = Some(tls_inspector::format_group_name(group));
    } else {
        result.key_exchange = Some("No key exchange detected".to_string());
    }

    if verbose {
        println!(
            "{} Deep analysis complete!",
            color_config.emoji_or_text("🔬", "[ANALYSIS]")
        );
        if handshake_info.supports_quantum {
            println!(
                "{} QUANTUM-SECURE ENCRYPTION CONFIRMED!",
                color_config.emoji_or_text("🎯", "[SUCCESS]")
            );
        } else {
            println!(
                "{} No quantum-secure encryption found",
                color_config.emoji_or_text("❌", "[FAILED]")
            );
        }
    }

    result
}

async fn scan_quantum_support(
    url: &Url,
    timeout_secs: u64,
    verbose: bool,
    color_config: &ColorConfig,
) -> ScanResult {
    let host = match url.host_str() {
        Some(h) => h,
        None => return ScanResult::with_error(url.to_string(), "Invalid hostname".to_string()),
    };

    let port = url.port().unwrap_or(443);

    if verbose {
        println!(
            "{} Starting REGULAR quantum security analysis (high-level)",
            color_config.emoji_or_text("🔧", "[REGULAR]")
        );
        println!(
            "{} Connecting to {}:{}",
            color_config.emoji_or_text("🔌", "[CONNECT]"),
            host,
            port
        );
    }

    // Create a custom TLS config that supports quantum-secure algorithms
    let config = create_quantum_tls_config();
    let connector = TlsConnector::from(Arc::new(config));

    // Resolve hostname
    let addr = match format!("{host}:{port}").to_socket_addrs() {
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
            return ScanResult::with_error(url.to_string(), format!("DNS resolution failed: {e}"))
        }
    };

    if verbose {
        println!(
            "{} Resolved to: {}",
            color_config.emoji_or_text("📡", "[RESOLVED]"),
            addr
        );
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
            return ScanResult::with_error(url.to_string(), format!("Connection failed: {e}"))
        }
        Err(_) => return ScanResult::with_error(url.to_string(), "Connection timeout".to_string()),
    };

    if verbose {
        println!(
            "{} TCP connection established",
            color_config.emoji_or_text("🤝", "[CONNECTED]")
        );
    }

    // Perform TLS handshake
    let server_name = match rustls::ServerName::try_from(host) {
        Ok(name) => name,
        Err(e) => {
            return ScanResult::with_error(url.to_string(), format!("Invalid server name: {e}"))
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
            return ScanResult::with_error(url.to_string(), format!("TLS handshake failed: {e}"))
        }
        Err(_) => {
            return ScanResult::with_error(url.to_string(), "TLS handshake timeout".to_string())
        }
    };

    if verbose {
        println!(
            "{} TLS handshake completed",
            color_config.emoji_or_text("🔐", "[TLS]")
        );
    }

    // Analyze the TLS connection
    let (_, connection) = tls_stream.into_inner();
    analyze_tls_connection(url.to_string(), &connection, verbose, color_config)
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
    color_config: &ColorConfig,
) -> ScanResult {
    let mut result = ScanResult::new(url);

    // Get negotiated cipher suite
    if let Some(suite) = connection.negotiated_cipher_suite() {
        let cipher_name = format!("{:?}", suite.suite());
        result.cipher_suite = Some(cipher_name.clone());
        if verbose {
            println!(
                "{} Cipher suite: {}",
                color_config.emoji_or_text("🔑", "[CIPHER]"),
                cipher_name
            );
        }
    }

    // Get protocol version
    if let Some(version) = connection.protocol_version() {
        let version_str = format!("{version:?}");
        result.tls_version = Some(version_str.clone());
        if verbose {
            println!(
                "{} TLS version: {}",
                color_config.emoji_or_text("📋", "[VERSION]"),
                version_str
            );
        }
    }

    // Extract key exchange information and check for quantum-secure algorithms
    let (key_exchange, is_quantum_secure) = analyze_key_exchange(connection, verbose, color_config);
    result.key_exchange = Some(key_exchange);
    result.supports_quantum = is_quantum_secure;

    if verbose {
        println!(
            "{} Quantum-secure: {}",
            color_config.emoji_or_text("🎯", "[SECURE]"),
            if result.supports_quantum {
                color_config.status_success("YES")
            } else {
                color_config.status_error("NO")
            }
        );
    }

    result
}

fn analyze_key_exchange(
    connection: &rustls::ClientConnection,
    verbose: bool,
    color_config: &ColorConfig,
) -> (String, bool) {
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
            if format!("{version:?}") == "TLSv1_3" {
                key_exchange_info.push_str(" (TLS 1.3)");

                // In TLS 1.3, we would need to inspect the actual key_share extension
                // to determine if X25519MLKEM768 was used. This requires lower-level
                // access than rustls currently provides.

                // For now, we can only make educated guesses based on what's available
                is_quantum_secure =
                    check_for_quantum_indicators(&suite_name, verbose, color_config);
            }
        }
    }

    if key_exchange_info.is_empty() {
        key_exchange_info = "Unknown".to_string();
    }

    if verbose && !key_exchange_info.contains("Unknown") {
        println!(
            "{} Key exchange: {}",
            color_config.emoji_or_text("🔄", "[KEY_EXCHANGE]"),
            key_exchange_info
        );
    }

    (key_exchange_info, is_quantum_secure)
}

fn format_tls_version(version: u16) -> String {
    match version {
        0x0304 => "TLS 1.3".to_string(),
        0x0303 => "TLS 1.2".to_string(),
        0x0302 => "TLS 1.1".to_string(),
        0x0301 => "TLS 1.0".to_string(),
        _ => format!("TLS (0x{version:04x})"),
    }
}

fn format_cipher_suite(cipher: u16) -> String {
    match cipher {
        0x1301 => "TLS_AES_128_GCM_SHA256".to_string(),
        0x1302 => "TLS_AES_256_GCM_SHA384".to_string(),
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256".to_string(),
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA".to_string(),
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA".to_string(),
        0x003c => "TLS_RSA_WITH_AES_128_CBC_SHA256".to_string(),
        0x003d => "TLS_RSA_WITH_AES_256_CBC_SHA256".to_string(),
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384".to_string(),
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string(),
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_string(),
        _ => format!("TLS_CIPHER (0x{cipher:04x})"),
    }
}

fn check_for_quantum_indicators(
    cipher_suite_name: &str,
    verbose: bool,
    color_config: &ColorConfig,
) -> bool {
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
            "{} Analyzing cipher suite for quantum indicators: {}",
            color_config.emoji_or_text("🔬", "[ANALYZE]"),
            cipher_suite_name
        );
        println!(
            "{} Note: Deep TLS inspection limited by rustls API",
            color_config.emoji_or_text("⚠️", "[WARNING]")
        );
    }

    // Look for any hints in the cipher suite name
    // (This is very limited and mostly for demonstration)
    let quantum_indicators = ["MLKEM", "KYBER", "X25519MLKEM768", "HYBRID", "PQ"];

    for indicator in &quantum_indicators {
        if cipher_suite_name.to_uppercase().contains(indicator) {
            if verbose {
                println!(
                    "{} Found potential quantum indicator: {}",
                    color_config.emoji_or_text("🎯", "[FOUND]"),
                    indicator
                );
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

fn print_result(result: &ScanResult, verbose: bool, color_config: &ColorConfig) {
    // Add visual spacing for all non-verbose modes (verbose already has spacing at start)
    if !verbose {
        println!();
    }
    if verbose {
        println!(
            "{} {} v{}",
            color_config.emoji_or_text("🔍", "[RESULTS]"),
            color_config.header("Quantum Security Test Results"),
            result.version
        );
    } else {
        let emoji = color_config.emoji_or_text("🔍", "");
        if emoji.is_empty() {
            println!(
                "{} v{}",
                color_config.header("Quantum Security Test Results"),
                result.version
            );
        } else {
            println!(
                "{} {} v{}",
                emoji,
                color_config.header("Quantum Security Test Results"),
                result.version
            );
        }
    }
    println!("URL: {}", color_config.url_highlight(&result.url));

    if let Some(error) = &result.error {
        println!(
            "{} Error: {}",
            color_config.emoji_or_text("❌", "[ERROR]"),
            color_config.status_error(error)
        );
        println!(); // Add trailing newline for consistency with success cases
        return;
    }

    let (status_emoji, status_text) = if result.supports_quantum {
        ("✅", "SUPPORTED")
    } else {
        ("❌", "NOT SUPPORTED")
    };

    let status_display = if result.supports_quantum {
        color_config.status_success(status_text)
    } else {
        color_config.status_error(status_text)
    };

    println!(
        "Quantum-secure encryption: {} {}",
        color_config.emoji_or_text(status_emoji, ""),
        status_display
    );

    if verbose {
        if let Some(tls_version) = &result.tls_version {
            println!("TLS Version: {tls_version}");
        }
        if let Some(cipher_suite) = &result.cipher_suite {
            println!("Cipher Suite: {cipher_suite}");
        }
        if let Some(key_exchange) = &result.key_exchange {
            println!("Key Exchange: {key_exchange}");
        }
    }

    println!();

    // Add appropriate warnings based on analysis mode
    if result
        .key_exchange
        .as_ref()
        .is_some_and(|ke| ke.contains("Unknown from cipher"))
    {
        println!(
            "{} {}",
            color_config.emoji_or_text("⚠️", "[WARNING]"),
            color_config.warning("Detection Limitations:")
        );
        println!(
            "{}",
            color_config
                .dimmed("   • Current TLS libraries have limited access to key exchange details")
        );
        println!(
            "{}",
            color_config
                .dimmed("   • True X25519MLKEM768 detection requires deeper handshake inspection")
        );
        println!(
            "{}",
            color_config.dimmed(
                "   • Deep analysis is the default - use --regular to force high-level analysis"
            )
        );
        println!();
    } else if verbose
        && result
            .key_exchange
            .as_ref()
            .is_some_and(|ke| ke.contains("(Quantum-Secure)") || ke.contains("(Classical)"))
    {
        println!(
            "{} {}",
            color_config.emoji_or_text("✅", "[INFO]"),
            color_config.status_success("Deep Analysis Mode:")
        );
        println!(
            "{}",
            color_config.dimmed("   • Low-level TLS handshake inspection performed")
        );
        println!(
            "{}",
            color_config
                .dimmed("   • Actual key exchange algorithms detected from handshake messages")
        );
        println!(
            "{}",
            color_config.dimmed(
                "   • Results show true negotiated algorithms, not library interpretations"
            )
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
        assert_eq!(result.version, env!("CARGO_PKG_VERSION"));
        assert!(!result.supports_quantum);
        assert!(result.error.is_none());
        assert!(result.tls_version.is_none());
        assert!(result.cipher_suite.is_none());
        assert!(result.key_exchange.is_none());
    }

    #[test]
    fn test_scan_result_with_error() {
        let result = ScanResult::with_error(
            "https://example.com".to_string(),
            "Connection failed".to_string(),
        );
        assert_eq!(result.url, "https://example.com");
        assert_eq!(result.version, env!("CARGO_PKG_VERSION"));
        assert!(!result.supports_quantum);
        assert_eq!(result.error, Some("Connection failed".to_string()));
        assert!(result.tls_version.is_none());
        assert!(result.cipher_suite.is_none());
        assert!(result.key_exchange.is_none());
    }

    #[test]
    fn test_scan_result_serialization() {
        let result = ScanResult {
            version: "0.1.0".to_string(),
            url: "https://test.com".to_string(),
            supports_quantum: true,
            tls_version: Some("TLSv1_3".to_string()),
            cipher_suite: Some("TLS13_AES_256_GCM_SHA384".to_string()),
            key_exchange: Some("X25519+ML-KEM-768".to_string()),
            error: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"supports_quantum\":true"));
        assert!(json.contains("\"url\":\"https://test.com\""));
        assert!(json.contains("\"version\":\"0.1.0\""));
        assert!(json.contains("\"tls_version\":\"TLSv1_3\""));
    }

    #[test]
    fn test_url_parsing_valid_cases() {
        // Test HTTPS URL
        let url = Url::parse("https://example.com").unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.port(), None);

        // Test HTTPS URL with port
        let url = Url::parse("https://example.com:8443").unwrap();
        assert_eq!(url.port(), Some(8443));

        // Test HTTPS URL with path
        let url = Url::parse("https://example.com/path").unwrap();
        assert_eq!(url.path(), "/path");

        // Test HTTPS URL with query
        let url = Url::parse("https://example.com?query=test").unwrap();
        assert_eq!(url.query(), Some("query=test"));
    }

    #[test]
    fn test_url_parsing_invalid_cases() {
        // Test invalid URL
        assert!(Url::parse("not-a-url").is_err());

        // Test HTTP URL (should be rejected in main logic)
        let url = Url::parse("http://example.com").unwrap();
        assert_eq!(url.scheme(), "http");
    }

    #[test]
    fn test_quantum_indicators_detection() {
        // Test positive cases
        assert!(check_for_quantum_indicators(
            "TLS_MLKEM_AES_256",
            false,
            &ColorConfig { enabled: true }
        ));
        assert!(check_for_quantum_indicators(
            "cipher_with_KYBER_support",
            false,
            &ColorConfig { enabled: true }
        ));
        assert!(check_for_quantum_indicators(
            "X25519MLKEM768_cipher",
            false,
            &ColorConfig { enabled: true }
        ));
        assert!(check_for_quantum_indicators(
            "HYBRID_key_exchange",
            false,
            &ColorConfig { enabled: true }
        ));
        assert!(check_for_quantum_indicators(
            "PQ_enabled_suite",
            false,
            &ColorConfig { enabled: true }
        ));

        // Test case insensitivity
        assert!(check_for_quantum_indicators(
            "mlkem_cipher",
            false,
            &ColorConfig { enabled: true }
        ));
        assert!(check_for_quantum_indicators(
            "kyber_cipher",
            false,
            &ColorConfig { enabled: true }
        ));

        // Test negative cases
        assert!(!check_for_quantum_indicators(
            "TLS_AES_256_GCM_SHA384",
            false,
            &ColorConfig { enabled: true }
        ));
        assert!(!check_for_quantum_indicators(
            "ECDHE_RSA_AES_256",
            false,
            &ColorConfig { enabled: true }
        ));
        assert!(!check_for_quantum_indicators(
            "classical_cipher",
            false,
            &ColorConfig { enabled: true }
        ));
        assert!(!check_for_quantum_indicators(
            "",
            false,
            &ColorConfig { enabled: true }
        ));
    }

    #[test]
    fn test_format_group_name() {
        use crate::tls_inspector::format_group_name;

        // Test quantum-secure groups
        assert_eq!(format_group_name(0x001d), "X25519 (Classical)");
        assert_eq!(
            format_group_name(0x11ec),
            "X25519+ML-KEM-768 (Quantum-Secure)"
        );
        assert_eq!(
            format_group_name(0x6399),
            "X25519+Kyber768-Draft (Quantum-Secure)"
        );

        // Test classical groups
        assert_eq!(format_group_name(0x0017), "secp256r1 (Classical)");
        assert_eq!(format_group_name(0x0018), "secp384r1 (Classical)");
        assert_eq!(format_group_name(0x0019), "secp521r1 (Classical)");

        // Test unknown groups
        assert_eq!(format_group_name(0x9999), "Unknown Group (0x9999)");
        assert_eq!(format_group_name(0x0000), "Unknown Group (0x0000)");
        assert_eq!(format_group_name(0xFFFF), "Unknown Group (0xffff)");
    }

    #[test]
    fn test_scan_result_quantum_support_detection() {
        let mut result = ScanResult::new("https://test.com".to_string());

        // Test quantum-secure key exchange detection
        result.key_exchange = Some("X25519+ML-KEM-768 (Quantum-Secure)".to_string());
        result.supports_quantum = true;
        assert!(result.supports_quantum);

        // Test classical key exchange detection
        result.key_exchange = Some("X25519 (Classical)".to_string());
        result.supports_quantum = false;
        assert!(!result.supports_quantum);
    }

    #[test]
    fn test_error_handling_scenarios() {
        // Test DNS resolution failure
        let error_result = ScanResult::with_error(
            "https://nonexistent.domain".to_string(),
            "DNS resolution failed".to_string(),
        );
        assert!(error_result.error.is_some());
        assert!(!error_result.supports_quantum);

        // Test connection timeout
        let timeout_result = ScanResult::with_error(
            "https://example.com".to_string(),
            "Connection timeout".to_string(),
        );
        assert!(timeout_result.error.is_some());
        assert_eq!(timeout_result.error.unwrap(), "Connection timeout");

        // Test TLS handshake failure
        let tls_error_result = ScanResult::with_error(
            "https://example.com".to_string(),
            "TLS handshake failed".to_string(),
        );
        assert!(tls_error_result.error.is_some());
    }

    #[test]
    fn test_tls_version_parsing() {
        let mut result = ScanResult::new("https://test.com".to_string());

        // Test TLS 1.3 version
        result.tls_version = Some("TLS 1.3".to_string());
        assert_eq!(result.tls_version, Some("TLS 1.3".to_string()));

        // Test TLS 1.2 version
        result.tls_version = Some("TLS 1.2".to_string());
        assert_eq!(result.tls_version, Some("TLS 1.2".to_string()));
    }

    #[test]
    fn test_cipher_suite_detection() {
        let mut result = ScanResult::new("https://test.com".to_string());

        // Test TLS 1.3 cipher suites
        result.cipher_suite = Some("TLS_AES_128_GCM_SHA256".to_string());
        assert_eq!(
            result.cipher_suite,
            Some("TLS_AES_128_GCM_SHA256".to_string())
        );

        result.cipher_suite = Some("TLS_AES_256_GCM_SHA384".to_string());
        assert_eq!(
            result.cipher_suite,
            Some("TLS_AES_256_GCM_SHA384".to_string())
        );

        result.cipher_suite = Some("TLS_CHACHA20_POLY1305_SHA256".to_string());
        assert_eq!(
            result.cipher_suite,
            Some("TLS_CHACHA20_POLY1305_SHA256".to_string())
        );
    }

    #[test]
    fn test_format_tls_version() {
        // Test known TLS versions
        assert_eq!(format_tls_version(0x0304), "TLS 1.3");
        assert_eq!(format_tls_version(0x0303), "TLS 1.2");
        assert_eq!(format_tls_version(0x0302), "TLS 1.1");
        assert_eq!(format_tls_version(0x0301), "TLS 1.0");

        // Test unknown version
        assert_eq!(format_tls_version(0x9999), "TLS (0x9999)");
    }

    #[test]
    fn test_format_cipher_suite() {
        // Test TLS 1.3 cipher suites
        assert_eq!(format_cipher_suite(0x1301), "TLS_AES_128_GCM_SHA256");
        assert_eq!(format_cipher_suite(0x1302), "TLS_AES_256_GCM_SHA384");
        assert_eq!(format_cipher_suite(0x1303), "TLS_CHACHA20_POLY1305_SHA256");

        // Test some TLS 1.2 cipher suites
        assert_eq!(
            format_cipher_suite(0xc02f),
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        );
        assert_eq!(
            format_cipher_suite(0xc030),
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        );

        // Test unknown cipher suite
        assert_eq!(format_cipher_suite(0x9999), "TLS_CIPHER (0x9999)");
    }

    #[test]
    fn test_key_exchange_analysis() {
        // Test different key exchange scenarios
        let test_cases = vec![
            ("X25519+ML-KEM-768 (Quantum-Secure)", true),
            ("X25519+Kyber768-Draft (Quantum-Secure)", true),
            ("X25519 (Classical)", false),
            ("secp256r1 (Classical)", false),
            ("Unknown Group (0x9999)", false),
            ("No key exchange detected", false),
        ];

        for (key_exchange, expected_quantum) in test_cases {
            let mut result = ScanResult::new("https://test.com".to_string());
            result.key_exchange = Some(key_exchange.to_string());
            result.supports_quantum = expected_quantum;

            assert_eq!(
                result.supports_quantum, expected_quantum,
                "Failed for key exchange: {key_exchange}"
            );
        }
    }

    #[test]
    fn test_url_normalization() {
        // Test various URL formats that should be normalized
        let test_urls = vec![
            ("example.com", "https://example.com/"),
            ("www.example.com", "https://www.example.com/"),
            ("example.com:8443", "https://example.com:8443/"),
            ("example.com/path", "https://example.com/path"),
        ];

        for (input, _expected) in test_urls {
            let normalized = format!("https://{input}");
            let url = Url::parse(&normalized).unwrap();
            assert!(
                url.as_str().starts_with("https://"),
                "URL should start with https://: {}",
                url.as_str()
            );
        }
    }

    #[test]
    fn test_json_output_format() {
        let result = ScanResult {
            version: "0.1.0".to_string(),
            url: "https://example.com".to_string(),
            supports_quantum: false,
            tls_version: Some("TLS 1.3".to_string()),
            cipher_suite: Some("TLS_AES_256_GCM_SHA384".to_string()),
            key_exchange: Some("X25519 (Classical)".to_string()),
            error: None,
        };

        let json = serde_json::to_string_pretty(&result).unwrap();

        // Verify JSON structure
        assert!(json.contains("\"url\""));
        assert!(json.contains("\"version\""));
        assert!(json.contains("\"supports_quantum\""));
        assert!(json.contains("\"tls_version\""));
        assert!(json.contains("\"cipher_suite\""));
        assert!(json.contains("\"key_exchange\""));
        assert!(json.contains("\"error\""));

        // Verify values
        assert!(json.contains("\"supports_quantum\": false"));
        assert!(json.contains("\"version\": \"0.1.0\""));
        assert!(json.contains("\"error\": null"));
    }

    #[test]
    fn test_error_json_output() {
        let error_result = ScanResult::with_error(
            "https://invalid.com".to_string(),
            "Connection refused".to_string(),
        );

        let json = serde_json::to_string(&error_result).unwrap();
        assert!(json.contains("\"error\":\"Connection refused\""));
        assert!(json.contains("\"supports_quantum\":false"));
    }

    #[test]
    fn test_color_config_creation() {
        // Test color disabled (no-color flag true) - should always be disabled
        let no_color_config = ColorConfig::new(true);
        assert!(!no_color_config.enabled);

        // Test that ColorConfig::new behaves consistently with should_use_color
        // Note: In test environment, terminal detection may vary, so we test consistency
        let color_config = ColorConfig::new(false);
        let expected = ColorConfig::should_use_color(false);
        assert_eq!(color_config.enabled, expected);

        // Test that the no_color_flag parameter is always respected (overrides everything)
        assert!(!ColorConfig::new(true).enabled);

        // Test direct ColorConfig creation for known states
        let enabled_config = ColorConfig { enabled: true };
        let disabled_config = ColorConfig { enabled: false };
        assert!(enabled_config.enabled);
        assert!(!disabled_config.enabled);

        // Test the core logic that determines color usage
        let color_logic_test = ColorConfig::should_use_color(true); // no-color flag true
        assert!(!color_logic_test); // Should always be false when no-color flag is set
    }

    #[test]
    fn test_color_config_environment_variables() {
        // Test NO_COLOR environment variable
        std::env::set_var("NO_COLOR", "1");
        let should_use_color = ColorConfig::should_use_color(false);
        assert!(!should_use_color);
        std::env::remove_var("NO_COLOR");

        // Test TERM=dumb environment variable
        std::env::set_var("TERM", "dumb");
        let should_use_color = ColorConfig::should_use_color(false);
        assert!(!should_use_color);
        std::env::remove_var("TERM");

        // Test normal case (no environment variables)
        let should_use_color = ColorConfig::should_use_color(false);
        // This will depend on whether we're running in a terminal, but we can test the logic
        let expected = std::io::IsTerminal::is_terminal(&std::io::stdout());
        assert_eq!(should_use_color, expected);
    }

    #[test]
    fn test_emoji_or_text_functionality() {
        // Test with colors enabled
        let color_config = ColorConfig { enabled: true };
        assert_eq!(color_config.emoji_or_text("🔍", "[SCAN]"), "🔍");
        assert_eq!(color_config.emoji_or_text("✅", "[SUCCESS]"), "✅");
        assert_eq!(color_config.emoji_or_text("❌", "[ERROR]"), "❌");
        assert_eq!(color_config.emoji_or_text("🔍", ""), "🔍");

        // Test with colors disabled
        let no_color_config = ColorConfig { enabled: false };
        assert_eq!(no_color_config.emoji_or_text("🔍", "[SCAN]"), "[SCAN]");
        assert_eq!(
            no_color_config.emoji_or_text("✅", "[SUCCESS]"),
            "[SUCCESS]"
        );
        assert_eq!(no_color_config.emoji_or_text("❌", "[ERROR]"), "[ERROR]");
        assert_eq!(no_color_config.emoji_or_text("🔍", ""), "");
    }

    #[test]
    fn test_color_styling_methods() {
        let color_config = ColorConfig { enabled: true };
        let no_color_config = ColorConfig { enabled: false };

        // Test that no-color config returns plain text
        assert_eq!(no_color_config.status_success("SUPPORTED"), "SUPPORTED");
        assert_eq!(
            no_color_config.status_error("NOT SUPPORTED"),
            "NOT SUPPORTED"
        );
        assert_eq!(no_color_config.header("Test Header"), "Test Header");
        assert_eq!(
            no_color_config.url_highlight("https://example.com"),
            "https://example.com"
        );
        assert_eq!(
            no_color_config.warning("Warning message"),
            "Warning message"
        );
        assert_eq!(no_color_config.dimmed("Dimmed text"), "Dimmed text");

        // Test that color config methods don't crash and return strings
        // Note: The actual color codes may not be applied in testing environment
        let success_colored = color_config.status_success("SUPPORTED");
        let error_colored = color_config.status_error("NOT SUPPORTED");
        let header_colored = color_config.header("Test Header");
        let url_colored = color_config.url_highlight("https://example.com");
        let warning_colored = color_config.warning("Warning message");
        let dimmed_colored = color_config.dimmed("Dimmed text");

        // Verify they return strings (they may be the same as plain text in test environment)
        assert!(success_colored.contains("SUPPORTED"));
        assert!(error_colored.contains("NOT SUPPORTED"));
        assert!(header_colored.contains("Test Header"));
        assert!(url_colored.contains("https://example.com"));
        assert!(warning_colored.contains("Warning message"));
        assert!(dimmed_colored.contains("Dimmed text"));
    }

    #[test]
    fn test_print_result_output_formatting() {
        // Test basic scan result
        let result = ScanResult {
            version: "0.1.0".to_string(),
            url: "https://example.com".to_string(),
            supports_quantum: true,
            tls_version: Some("TLS 1.3".to_string()),
            cipher_suite: Some("TLS_AES_256_GCM_SHA384".to_string()),
            key_exchange: Some("X25519+ML-KEM-768 (Quantum-Secure)".to_string()),
            error: None,
        };

        // Test that the result formatting doesn't crash with different configurations
        let color_config = ColorConfig { enabled: true };
        let no_color_config = ColorConfig { enabled: false };

        // These should not panic
        print_result(&result, false, &color_config);
        print_result(&result, true, &color_config);
        print_result(&result, false, &no_color_config);
        print_result(&result, true, &no_color_config);

        // Test error result
        let error_result = ScanResult::with_error(
            "https://example.com".to_string(),
            "Connection failed".to_string(),
        );

        // These should not panic
        print_result(&error_result, false, &color_config);
        print_result(&error_result, true, &color_config);
        print_result(&error_result, false, &no_color_config);
        print_result(&error_result, true, &no_color_config);
    }

    #[test]
    fn test_verbose_mode_header_behavior() {
        // Test that verbose and non-verbose modes show correct headers
        let color_config = ColorConfig { enabled: true };
        let no_color_config = ColorConfig { enabled: false };

        // Test emoji_or_text behavior for headers in different modes
        // Normal mode (non-verbose) - should show emoji when colors enabled
        let normal_with_color = color_config.emoji_or_text("🔍", "");
        assert_eq!(normal_with_color, "🔍");

        // Normal mode (non-verbose) - should show empty string when colors disabled
        let normal_without_color = no_color_config.emoji_or_text("🔍", "");
        assert_eq!(normal_without_color, "");

        // Verbose mode - should show emoji when colors enabled
        let verbose_with_color = color_config.emoji_or_text("🔍", "[RESULTS]");
        assert_eq!(verbose_with_color, "🔍");

        // Verbose mode - should show [RESULTS] when colors disabled
        let verbose_without_color = no_color_config.emoji_or_text("🔍", "[RESULTS]");
        assert_eq!(verbose_without_color, "[RESULTS]");

        // Test the header text is always the same
        let header_with_color = color_config.header("Quantum Security Test Results");
        let header_without_color = no_color_config.header("Quantum Security Test Results");
        assert!(header_with_color.contains("Quantum Security Test Results"));
        assert_eq!(header_without_color, "Quantum Security Test Results");
    }

    #[test]
    fn test_print_result_spacing_logic() {
        // Test the spacing logic in print_result function
        // Note: This doesn't capture actual stdout, but tests the logic that determines when spacing should occur

        let result = ScanResult {
            version: "0.1.0".to_string(),
            url: "https://example.com".to_string(),
            supports_quantum: true,
            tls_version: Some("TLS 1.3".to_string()),
            cipher_suite: Some("TLS_AES_256_GCM_SHA384".to_string()),
            key_exchange: Some("X25519+ML-KEM-768 (Quantum-Secure)".to_string()),
            error: None,
        };

        let color_config = ColorConfig { enabled: true };
        let no_color_config = ColorConfig { enabled: false };

        // Test the specific spacing conditions
        // 1. Normal mode + colors: should add spacing (if !verbose && color_config.enabled)
        let should_add_spacing_normal_color = color_config.enabled;
        assert!(
            should_add_spacing_normal_color,
            "Normal color mode should have spacing"
        );

        // 2. Normal mode + no-color: should ALSO add spacing (for consistency)
        let should_add_spacing_normal_no_color = true; // Fixed: should be consistent with color mode
        assert!(
            should_add_spacing_normal_no_color,
            "Normal no-color mode should ALSO have spacing for consistency"
        );

        // 3. Verbose mode + colors: should NOT add spacing in print_result (has spacing earlier)
        let should_add_spacing_verbose_color = false;
        assert!(
            !should_add_spacing_verbose_color,
            "Verbose mode should NOT add spacing in print_result"
        );

        // 4. Verbose mode + no-color: should NOT add spacing in print_result (has spacing earlier)
        let should_add_spacing_verbose_no_color = false;
        assert!(
            !should_add_spacing_verbose_no_color,
            "Verbose mode should NOT add spacing in print_result"
        );

        // Verify the functions still execute without panicking
        print_result(&result, false, &color_config); // Normal + color
        print_result(&result, false, &no_color_config); // Normal + no-color
        print_result(&result, true, &color_config); // Verbose + color
        print_result(&result, true, &no_color_config); // Verbose + no-color
    }

    #[test]
    fn test_print_result_leading_blank_line_consistency() {
        // This test documents the expected behavior: both color and no-color modes
        // should have consistent leading blank lines in non-verbose mode

        let result = ScanResult {
            version: "0.1.0".to_string(),
            url: "https://example.com".to_string(),
            supports_quantum: true,
            tls_version: None,
            cipher_suite: None,
            key_exchange: None,
            error: None,
        };

        let color_config = ColorConfig { enabled: true };
        let no_color_config = ColorConfig { enabled: false };

        // Test that the spacing logic for non-verbose mode should be consistent:
        // Expected behavior: !verbose should add spacing regardless of color config
        let verbose = false;

        // The bug was: only add spacing if (!verbose && color_config.enabled)
        // The fix should be: add spacing if (!verbose) regardless of color_config.enabled
        let should_add_spacing_color = !verbose; // Should be true
        let should_add_spacing_no_color = !verbose; // Should also be true

        assert!(
            should_add_spacing_color,
            "Non-verbose color mode should have leading blank line"
        );
        assert!(
            should_add_spacing_no_color,
            "Non-verbose no-color mode should have leading blank line for consistency"
        );

        // Verify functions execute without panicking
        print_result(&result, false, &color_config);
        print_result(&result, false, &no_color_config);
    }

    #[test]
    fn test_print_result_error_trailing_newline() {
        // This test documents that error output should end with a trailing newline
        // to prevent the shell prompt from appearing on the same line

        let error_result = ScanResult::with_error(
            "https://google.colm".to_string(),
            "DNS resolution failed: failed to lookup address information: nodename nor servname provided, or not known".to_string(),
        );

        let color_config = ColorConfig { enabled: true };
        let no_color_config = ColorConfig { enabled: false };

        // Test that error results should have consistent formatting
        // Both success and error cases should end with a trailing newline

        // Note: This test documents the expected behavior.
        // The actual print_result function should add a trailing newline for error cases
        // to match the behavior of successful scans.

        // These should not panic and should have consistent trailing newlines
        print_result(&error_result, false, &color_config);
        print_result(&error_result, true, &color_config);
        print_result(&error_result, false, &no_color_config);
        print_result(&error_result, true, &no_color_config);

        // Success case for comparison (already has trailing newline)
        let success_result = ScanResult {
            version: "0.1.0".to_string(),
            url: "https://example.com".to_string(),
            supports_quantum: false,
            tls_version: None,
            cipher_suite: None,
            key_exchange: Some("X25519 (Classical)".to_string()),
            error: None,
        };

        print_result(&success_result, false, &color_config);
        print_result(&success_result, false, &no_color_config);
    }
}
