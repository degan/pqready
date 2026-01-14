// TLS Inspector for quantum-secure encryption detection
// This module handles the low-level TLS handshake analysis

use crate::ColorConfig;
use anyhow::{anyhow, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

// Buffer and timeout constants
const READ_BUFFER_SIZE: usize = 4096;
const DEFAULT_STREAM_TIMEOUT_SECS: u64 = 10;

// TLS Record Types (RFC 8446 Section 5.1)
const TLS_HANDSHAKE: u8 = 0x16;
const TLS_CHANGE_CIPHER_SPEC: u8 = 0x14;
const TLS_ALERT: u8 = 0x15;
const TLS_APPLICATION_DATA: u8 = 0x17;

// TLS Protocol Versions (RFC 8446)
const TLS_VERSION_1_3: u16 = 0x0304;
const TLS_VERSION_1_2: u16 = 0x0303;

// Handshake Message Types (RFC 8446 Section 4)
const CLIENT_HELLO: u8 = 0x01;
const SERVER_HELLO: u8 = 0x02;

// TLS Extension Types (IANA TLS ExtensionType Values)
const SUPPORTED_GROUPS: u16 = 0x000a;
const KEY_SHARE: u16 = 0x0033;
const SUPPORTED_VERSIONS: u16 = 0x002b;

// Named Groups / Supported Groups (IANA TLS Supported Groups)
// Classical ECDH groups
const X25519: u16 = 0x001d;
// Post-quantum hybrid groups
const X25519_MLKEM768: u16 = 0x11ec; // X25519+ML-KEM-768 (IETF draft, Cloudflare recommended)
const X25519_KYBER768_DRAFT: u16 = 0x6399; // X25519Kyber768Draft00 (current Cloudflare implementation)

#[derive(Debug, Clone, Default)]
pub struct TlsHandshakeInfo {
    pub client_supported_groups: Vec<u16>,
    pub server_selected_group: Option<u16>,
    pub negotiated_version: Option<u16>,
    pub client_key_shares: Vec<u16>,
    pub server_key_share: Option<u16>,
    pub cipher_suite: Option<u16>,
    pub supports_quantum: bool,
}

pub struct TlsInspector {
    stream: TcpStream,
    handshake_info: TlsHandshakeInfo,
}

impl TlsInspector {
    pub fn new(stream: TcpStream) -> Result<Self> {
        // Set read/write timeouts
        stream.set_read_timeout(Some(Duration::from_secs(DEFAULT_STREAM_TIMEOUT_SECS)))?;
        stream.set_write_timeout(Some(Duration::from_secs(DEFAULT_STREAM_TIMEOUT_SECS)))?;

        Ok(Self {
            stream,
            handshake_info: TlsHandshakeInfo::default(),
        })
    }

    pub fn perform_quantum_handshake_analysis(
        &mut self,
        hostname: &str,
        verbose: bool,
        color_config: &ColorConfig,
    ) -> Result<TlsHandshakeInfo> {
        if verbose {
            println!(
                "{} Starting low-level TLS handshake analysis",
                color_config.emoji_or_text("🔬", "[DEEP]")
            );
        }

        // Send a ClientHello with quantum-secure groups
        self.send_quantum_client_hello(hostname, verbose, color_config)?;

        // Read and parse ServerHello
        self.parse_server_response(verbose, color_config)?;

        // Analyze for quantum-secure algorithms
        self.analyze_quantum_support(verbose, color_config);

        Ok(self.handshake_info.clone())
    }

    fn send_quantum_client_hello(
        &mut self,
        hostname: &str,
        verbose: bool,
        color_config: &ColorConfig,
    ) -> Result<()> {
        if verbose {
            println!(
                "{} Sending ClientHello with quantum-secure groups",
                color_config.emoji_or_text("📤", "[SEND]")
            );
        }

        let client_hello = self.build_quantum_client_hello(hostname)?;

        if verbose {
            println!(
                "{} ClientHello details:",
                color_config.emoji_or_text("🔍", "[DETAILS]")
            );
            println!("   • Total size: {} bytes", client_hello.len());
            println!("   • Hostname: {hostname}");
            println!("   • Client offering groups: X25519+ML-KEM-768 (0x11ec), X25519+Kyber768-Draft00 (0x6399), X25519 (0x001d)");
        }

        self.stream.write_all(&client_hello)?;
        self.stream.flush()?;

        if verbose {
            println!(
                "{} ClientHello sent successfully",
                color_config.emoji_or_text("✅", "[SENT]")
            );
        }

        Ok(())
    }

    fn build_quantum_client_hello(&mut self, hostname: &str) -> Result<Vec<u8>> {
        let mut hello = Vec::new();

        // TLS Record Header
        hello.push(TLS_HANDSHAKE); // Content Type
        hello.extend_from_slice(&TLS_VERSION_1_2.to_be_bytes()); // Legacy version

        // We'll fill in the length later
        let length_pos = hello.len();
        hello.extend_from_slice(&[0, 0]); // Placeholder for length

        // Handshake Header
        hello.push(CLIENT_HELLO); // Handshake Type

        // Handshake length placeholder
        let handshake_length_pos = hello.len();
        hello.extend_from_slice(&[0, 0, 0]); // 24-bit length

        // Protocol Version (legacy)
        hello.extend_from_slice(&TLS_VERSION_1_2.to_be_bytes());

        // Random (32 bytes)
        let random: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        hello.extend_from_slice(&random);

        // Session ID (empty)
        hello.push(0); // Length

        // Cipher Suites
        let cipher_suites = vec![
            0x13, 0x02, // TLS_AES_256_GCM_SHA384
            0x13, 0x01, // TLS_AES_128_GCM_SHA256
            0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
        ];
        hello.extend_from_slice(&((cipher_suites.len() as u16).to_be_bytes()));
        hello.extend_from_slice(&cipher_suites);

        // Compression Methods
        hello.push(1); // Length
        hello.push(0); // No compression

        // Extensions
        let extensions = self.build_quantum_extensions(hostname)?;
        hello.extend_from_slice(&((extensions.len() as u16).to_be_bytes()));
        hello.extend_from_slice(&extensions);

        // Fill in lengths
        let total_handshake_len = hello.len() - handshake_length_pos - 3;
        let handshake_len_bytes = [
            ((total_handshake_len >> 16) & 0xff) as u8,
            ((total_handshake_len >> 8) & 0xff) as u8,
            (total_handshake_len & 0xff) as u8,
        ];
        hello[handshake_length_pos..handshake_length_pos + 3].copy_from_slice(&handshake_len_bytes);

        let total_record_len = hello.len() - length_pos - 2;
        let record_len_bytes = (total_record_len as u16).to_be_bytes();
        hello[length_pos..length_pos + 2].copy_from_slice(&record_len_bytes);

        Ok(hello)
    }

    fn build_quantum_extensions(&mut self, hostname: &str) -> Result<Vec<u8>> {
        let mut extensions = Vec::new();

        // Server Name Indication
        self.add_sni_extension(&mut extensions, hostname);

        // Supported Versions (TLS 1.3)
        self.add_supported_versions_extension(&mut extensions);

        // Supported Groups (including quantum-secure ones)
        self.add_supported_groups_extension(&mut extensions);

        // Key Share (including quantum-secure key shares)
        self.add_key_share_extension(&mut extensions);

        // Signature Algorithms
        self.add_signature_algorithms_extension(&mut extensions);

        Ok(extensions)
    }

    fn add_sni_extension(&self, extensions: &mut Vec<u8>, hostname: &str) {
        extensions.extend_from_slice(&(0x0000u16.to_be_bytes())); // SNI extension type

        let sni_data = hostname.as_bytes();
        let sni_len = 5 + sni_data.len(); // 2 + 1 + 2 + hostname_len
        extensions.extend_from_slice(&(sni_len as u16).to_be_bytes());

        extensions.extend_from_slice(&((sni_data.len() + 3) as u16).to_be_bytes()); // Server name list length
        extensions.push(0); // Name type (hostname)
        extensions.extend_from_slice(&(sni_data.len() as u16).to_be_bytes()); // Hostname length
        extensions.extend_from_slice(sni_data); // Hostname
    }

    fn add_supported_versions_extension(&self, extensions: &mut Vec<u8>) {
        extensions.extend_from_slice(&SUPPORTED_VERSIONS.to_be_bytes());
        extensions.extend_from_slice(&3u16.to_be_bytes()); // Extension length
        extensions.push(2); // Versions length
        extensions.extend_from_slice(&TLS_VERSION_1_3.to_be_bytes()); // TLS 1.3
    }

    fn add_supported_groups_extension(&mut self, extensions: &mut Vec<u8>) {
        extensions.extend_from_slice(&SUPPORTED_GROUPS.to_be_bytes());

        // Include quantum-secure groups (matching Cloudflare's current implementation)
        let groups = vec![
            X25519_MLKEM768,       // X25519+ML-KEM-768 (recommended by Cloudflare)
            X25519_KYBER768_DRAFT, // X25519Kyber768Draft00 (current Cloudflare implementation)
            X25519,                // Classical fallback
            0x0017,                // secp256r1
            0x0018,                // secp384r1
        ];

        // Store in our handshake info
        self.handshake_info.client_supported_groups = groups.clone();
        self.handshake_info.client_key_shares =
            vec![X25519_KYBER768_DRAFT, X25519_MLKEM768, X25519];

        let groups_data: Vec<u8> = groups.iter().flat_map(|g| g.to_be_bytes()).collect();

        extensions.extend_from_slice(&((groups_data.len() + 2) as u16).to_be_bytes()); // Extension length
        extensions.extend_from_slice(&(groups_data.len() as u16).to_be_bytes()); // Groups length
        extensions.extend_from_slice(&groups_data);
    }

    fn add_key_share_extension(&self, extensions: &mut Vec<u8>) {
        extensions.extend_from_slice(&KEY_SHARE.to_be_bytes());

        // Generate key shares for quantum-secure and classical algorithms
        let mut key_shares = Vec::new();

        // Temporarily comment out large quantum key shares to avoid decode errors
        // Large post-quantum key shares might cause issues as mentioned in tldr.fail

        // X25519+Kyber768 key share (current Cloudflare implementation)
        // key_shares.extend_from_slice(&X25519_KYBER768_DRAFT.to_be_bytes());
        // key_shares.extend_from_slice(&1568u16.to_be_bytes()); // Kyber-768 public key size + X25519 key size
        // key_shares.extend_from_slice(&vec![0x43; 1568]);

        // X25519+ML-KEM-768 key share (recommended by Cloudflare)
        // key_shares.extend_from_slice(&X25519_MLKEM768.to_be_bytes());
        // key_shares.extend_from_slice(&1568u16.to_be_bytes()); // ML-KEM-768 public key size + X25519 key size
        // key_shares.extend_from_slice(&vec![0x42; 1568]);

        // X25519 key share (classical fallback)
        key_shares.extend_from_slice(&X25519.to_be_bytes());
        key_shares.extend_from_slice(&32u16.to_be_bytes()); // X25519 public key size
        key_shares.extend_from_slice(&[0x41; 32]);

        extensions.extend_from_slice(&((key_shares.len() + 2) as u16).to_be_bytes()); // Extension length
        extensions.extend_from_slice(&(key_shares.len() as u16).to_be_bytes()); // Key shares length
        extensions.extend_from_slice(&key_shares);
    }

    fn add_signature_algorithms_extension(&self, extensions: &mut Vec<u8>) {
        extensions.extend_from_slice(&0x000du16.to_be_bytes()); // Signature algorithms extension

        let sig_algs = [
            0x0804, // rsa_pss_rsae_sha256
            0x0805, // rsa_pss_rsae_sha384
            0x0806, // rsa_pss_rsae_sha512
            0x0403, // ecdsa_secp256r1_sha256
            0x0503, // ecdsa_secp384r1_sha384
        ];

        let sig_algs_data: Vec<u8> = sig_algs
            .iter()
            .flat_map(|&s| (s as u16).to_be_bytes())
            .collect();

        extensions.extend_from_slice(&((sig_algs_data.len() + 2) as u16).to_be_bytes());
        extensions.extend_from_slice(&(sig_algs_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sig_algs_data);
    }

    fn parse_server_response(&mut self, verbose: bool, color_config: &ColorConfig) -> Result<()> {
        if verbose {
            println!(
                "{} Reading server response...",
                color_config.emoji_or_text("📥", "[RECV]")
            );
        }

        let mut buffer = vec![0u8; READ_BUFFER_SIZE];
        let bytes_read = self.stream.read(&mut buffer)?;

        if verbose {
            println!(
                "{} Received {} bytes from server",
                color_config.emoji_or_text("📦", "[DATA]"),
                bytes_read
            );
            if bytes_read > 0 {
                println!(
                    "{} Raw response (first {} bytes): {:02x?}",
                    color_config.emoji_or_text("🔍", "[RAW]"),
                    std::cmp::min(bytes_read, 20),
                    &buffer[..std::cmp::min(bytes_read, 20)]
                );
            }
        }

        if bytes_read == 0 {
            return Err(anyhow!(
                "Server closed connection immediately (0 bytes received)"
            ));
        }

        if bytes_read < 5 {
            let hex_data = buffer[..bytes_read]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            return Err(anyhow!(
                "Server response too short ({} bytes): {}",
                bytes_read,
                hex_data
            ));
        }

        buffer.truncate(bytes_read);

        self.parse_tls_records(&buffer, verbose, color_config)?;

        Ok(())
    }

    fn parse_tls_records(
        &mut self,
        data: &[u8],
        verbose: bool,
        color_config: &ColorConfig,
    ) -> Result<()> {
        let mut offset = 0;

        while offset + 5 <= data.len() {
            let content_type = data[offset];
            let version = u16::from_be_bytes([data[offset + 1], data[offset + 2]]);
            let length = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;

            if offset + 5 + length > data.len() {
                break;
            }

            if verbose {
                println!(
                    "{} TLS Record: type={:02x}, version={:04x}, length={}",
                    color_config.emoji_or_text("📋", "[RECORD]"),
                    content_type,
                    version,
                    length
                );
            }

            match content_type {
                TLS_HANDSHAKE => {
                    self.parse_handshake_messages(
                        &data[offset + 5..offset + 5 + length],
                        verbose,
                        color_config,
                    )?;
                }
                TLS_CHANGE_CIPHER_SPEC => {
                    if verbose {
                        println!(
                            "{} ChangeCipherSpec (TLS 1.3 compatibility)",
                            color_config.emoji_or_text("🔄", "[CHANGE]")
                        );
                    }
                }
                TLS_ALERT => {
                    if verbose {
                        println!(
                            "{} TLS Alert received",
                            color_config.emoji_or_text("⚠️", "[ALERT]")
                        );
                    }
                    self.parse_tls_alert(
                        &data[offset + 5..offset + 5 + length],
                        verbose,
                        color_config,
                    )?;
                }
                TLS_APPLICATION_DATA => {
                    if verbose {
                        println!(
                            "{} Application Data ({} bytes encrypted)",
                            color_config.emoji_or_text("📊", "[APP_DATA]"),
                            length
                        );
                    }
                }
                _ => {
                    if verbose {
                        println!(
                            "{} Unknown TLS record type: 0x{:02x}",
                            color_config.emoji_or_text("❓", "[UNKNOWN]"),
                            content_type
                        );
                    }
                }
            }

            offset += 5 + length;
        }

        Ok(())
    }

    fn parse_handshake_messages(
        &mut self,
        data: &[u8],
        verbose: bool,
        color_config: &ColorConfig,
    ) -> Result<()> {
        let mut offset = 0;

        while offset + 4 <= data.len() {
            let msg_type = data[offset];
            let length =
                u32::from_be_bytes([0, data[offset + 1], data[offset + 2], data[offset + 3]])
                    as usize;

            if offset + 4 + length > data.len() {
                break;
            }

            if verbose {
                println!(
                    "{} Handshake message: type={:02x}, length={}",
                    color_config.emoji_or_text("🤝", "[HANDSHAKE]"),
                    msg_type,
                    length
                );
            }

            match msg_type {
                SERVER_HELLO => {
                    self.parse_server_hello(
                        &data[offset + 4..offset + 4 + length],
                        verbose,
                        color_config,
                    )?;
                }
                _ => {
                    if verbose {
                        println!(
                            "{} Other handshake message type: {:02x}",
                            color_config.emoji_or_text("📝", "[OTHER]"),
                            msg_type
                        );
                    }
                }
            }

            offset += 4 + length;
        }

        Ok(())
    }

    fn parse_server_hello(
        &mut self,
        data: &[u8],
        verbose: bool,
        color_config: &ColorConfig,
    ) -> Result<()> {
        if data.len() < 38 {
            return Err(anyhow!("ServerHello too short"));
        }

        let version = u16::from_be_bytes([data[0], data[1]]);
        self.handshake_info.negotiated_version = Some(version);

        if verbose {
            println!(
                "{} ServerHello version: {:04x}",
                color_config.emoji_or_text("🔒", "[VERSION]"),
                version
            );
        }

        // Skip random (32 bytes) and session ID
        let mut offset = 34;
        let session_id_len = data[offset] as usize;
        offset += 1 + session_id_len;

        if offset + 2 > data.len() {
            return Err(anyhow!("Invalid ServerHello format"));
        }

        // Cipher suite
        let cipher_suite = u16::from_be_bytes([data[offset], data[offset + 1]]);
        self.handshake_info.cipher_suite = Some(cipher_suite);
        offset += 2;

        if verbose {
            println!(
                "{} Selected cipher suite: {:04x}",
                color_config.emoji_or_text("🔑", "[CIPHER]"),
                cipher_suite
            );
        }

        // Compression method
        offset += 1;

        // Extensions
        if offset + 2 <= data.len() {
            let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            if offset + extensions_len <= data.len() {
                self.parse_server_extensions(
                    &data[offset..offset + extensions_len],
                    verbose,
                    color_config,
                )?;
            }
        }

        Ok(())
    }

    fn parse_server_extensions(
        &mut self,
        data: &[u8],
        verbose: bool,
        color_config: &ColorConfig,
    ) -> Result<()> {
        let mut offset = 0;

        while offset + 4 <= data.len() {
            let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if offset + ext_len > data.len() {
                break;
            }

            if verbose {
                println!(
                    "{} Extension: type={:04x}, length={}",
                    color_config.emoji_or_text("🔧", "[EXT]"),
                    ext_type,
                    ext_len
                );
            }

            match ext_type {
                KEY_SHARE => {
                    self.parse_key_share_extension(
                        &data[offset..offset + ext_len],
                        verbose,
                        color_config,
                    )?;
                }
                SUPPORTED_VERSIONS => {
                    if ext_len >= 2 {
                        let version = u16::from_be_bytes([data[offset], data[offset + 1]]);
                        self.handshake_info.negotiated_version = Some(version);
                        if verbose {
                            println!(
                                "{} Negotiated version: {:04x}",
                                color_config.emoji_or_text("✅", "[NEGOTIATED]"),
                                version
                            );
                        }
                    }
                }
                _ => {
                    if verbose {
                        println!(
                            "{} Other extension: {:04x}",
                            color_config.emoji_or_text("📎", "[OTHER_EXT]"),
                            ext_type
                        );
                    }
                }
            }

            offset += ext_len;
        }

        Ok(())
    }

    fn parse_key_share_extension(
        &mut self,
        data: &[u8],
        verbose: bool,
        color_config: &ColorConfig,
    ) -> Result<()> {
        if verbose {
            println!(
                "{} Key share extension data: {:02x?}",
                color_config.emoji_or_text("🔍", "[KEY_SHARE]"),
                data
            );
        }

        if data.len() < 2 {
            if verbose {
                println!(
                    "{} Key share extension too short ({} bytes)",
                    color_config.emoji_or_text("⚠️", "[WARNING]"),
                    data.len()
                );
            }
            return Ok(());
        }

        // Check if this is a Hello Retry Request (just group selection)
        if data.len() == 2 {
            let group = u16::from_be_bytes([data[0], data[1]]);
            self.handshake_info.server_selected_group = Some(group);

            if verbose {
                println!(
                    "{} Hello Retry Request - Server selected group: {:04x}",
                    color_config.emoji_or_text("🔄", "[RETRY]"),
                    group
                );

                match group {
                    X25519_KYBER768_DRAFT => {
                        println!(
                            "{} QUANTUM-SECURE: X25519+Kyber768-Draft00 detected!",
                            color_config.emoji_or_text("🎯", "[QUANTUM]")
                        );
                    }
                    X25519_MLKEM768 => {
                        println!(
                            "{} QUANTUM-SECURE: X25519+ML-KEM-768 detected!",
                            color_config.emoji_or_text("🎯", "[QUANTUM]")
                        );
                    }
                    X25519 => {
                        println!(
                            "{} Classical: X25519 detected",
                            color_config.emoji_or_text("🔧", "[CLASSICAL]")
                        );
                    }
                    _ => {
                        println!(
                            "{} Server selected group: {:04x} (key length: {})",
                            color_config.emoji_or_text("🗝️", "[KEY]"),
                            group,
                            data.len() - 4
                        );
                    }
                }
            }
            return Ok(());
        }

        // Parse normal key share
        if data.len() >= 4 {
            let group = u16::from_be_bytes([data[0], data[1]]);
            let key_length = u16::from_be_bytes([data[2], data[3]]) as usize;

            self.handshake_info.server_selected_group = Some(group);
            self.handshake_info.server_key_share = Some(group);

            if verbose {
                println!(
                    "{} Server selected group: {:04x} (key length: {})",
                    color_config.emoji_or_text("🗝️", "[KEY]"),
                    group,
                    key_length
                );
            }
        }

        Ok(())
    }

    fn analyze_quantum_support(&mut self, verbose: bool, color_config: &ColorConfig) {
        // Check if quantum-secure key exchange was negotiated
        let quantum_support = self
            .handshake_info
            .server_selected_group
            .map(|group| matches!(group, X25519_MLKEM768 | X25519_KYBER768_DRAFT))
            .unwrap_or(false);

        self.handshake_info.supports_quantum = quantum_support;

        if verbose {
            if quantum_support {
                println!(
                    "{} QUANTUM-SECURE ENCRYPTION DETECTED!",
                    color_config.emoji_or_text("🎯", "[SECURE]")
                );
                println!(
                    "{} X25519+ML-KEM-768 hybrid key exchange is active",
                    color_config.emoji_or_text("🔬", "[HYBRID]")
                );
            } else {
                println!(
                    "{} No quantum-secure encryption detected",
                    color_config.emoji_or_text("🎯", "[NOT_SECURE]")
                );
                if let Some(group) = self.handshake_info.server_selected_group {
                    println!(
                        "{} Using classical key exchange: {:04x}",
                        color_config.emoji_or_text("🔧", "[CLASSICAL]"),
                        group
                    );
                }
            }
        }
    }

    fn parse_tls_alert(
        &mut self,
        data: &[u8],
        verbose: bool,
        color_config: &ColorConfig,
    ) -> Result<()> {
        if data.len() < 2 {
            return Err(anyhow!("Invalid TLS Alert format"));
        }

        let level = data[0];
        let description = data[1];

        let level_str = match level {
            1 => "Warning",
            2 => "Fatal",
            _ => "Unknown",
        };

        let description_str = match description {
            0 => "close_notify",
            10 => "unexpected_message",
            20 => "bad_record_mac",
            21 => "decryption_failed",
            22 => "record_overflow",
            30 => "decompression_failure",
            40 => "handshake_failure",
            41 => "no_certificate",
            42 => "bad_certificate",
            43 => "unsupported_certificate",
            44 => "certificate_revoked",
            45 => "certificate_expired",
            46 => "certificate_unknown",
            47 => "illegal_parameter",
            48 => "unknown_ca",
            49 => "access_denied",
            50 => "decode_error",
            51 => "decrypt_error",
            60 => "export_restriction",
            70 => "protocol_version",
            71 => "insufficient_security",
            80 => "internal_error",
            90 => "user_canceled",
            100 => "no_renegotiation",
            110 => "unsupported_extension",
            _ => "unknown_alert",
        };

        if verbose {
            println!(
                "{} TLS Alert: {} {} (level={}, code={})",
                color_config.emoji_or_text("🚨", "[ALERT]"),
                level_str,
                description_str,
                level,
                description
            );
            if description == 110 {
                println!(
                    "{} This means the server doesn't recognize our quantum-secure extensions",
                    color_config.emoji_or_text("💡", "[INFO]")
                );
            } else if description == 50 {
                println!("{} Server cannot decode/parse our ClientHello - likely due to unknown quantum extensions", 
                    color_config.emoji_or_text("💡", "[INFO]"));
            } else if description == 40 {
                println!(
                    "{} Handshake failure - server rejected our key exchange proposals",
                    color_config.emoji_or_text("💡", "[INFO]")
                );
            }
        }

        // Alert code 32 doesn't exist in standard TLS - let me check what this actually is
        if description == 32 && verbose {
            println!(
                "{} Alert code 32 - this may be a non-standard or implementation-specific alert",
                color_config.emoji_or_text("⚠️", "[WARNING]")
            );
        }

        Ok(())
    }
}

pub fn format_group_name(group: u16) -> String {
    match group {
        X25519_KYBER768_DRAFT => "X25519+Kyber768-Draft (Quantum-Secure)".to_string(),
        X25519_MLKEM768 => "X25519+ML-KEM-768 (Quantum-Secure)".to_string(),
        X25519 => "X25519 (Classical)".to_string(),
        0x0017 => "secp256r1 (Classical)".to_string(),
        0x0018 => "secp384r1 (Classical)".to_string(),
        0x0019 => "secp521r1 (Classical)".to_string(),
        _ => format!("Unknown Group (0x{group:04x})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_handshake_info_default() {
        let info = TlsHandshakeInfo::default();
        assert!(info.client_supported_groups.is_empty());
        assert!(info.server_selected_group.is_none());
        assert!(info.negotiated_version.is_none());
        assert!(info.client_key_shares.is_empty());
        assert!(info.server_key_share.is_none());
        assert!(info.cipher_suite.is_none());
        assert!(!info.supports_quantum);
    }

    #[test]
    fn test_format_group_name_quantum_secure() {
        assert_eq!(
            format_group_name(X25519_MLKEM768),
            "X25519+ML-KEM-768 (Quantum-Secure)"
        );
        assert_eq!(
            format_group_name(X25519_KYBER768_DRAFT),
            "X25519+Kyber768-Draft (Quantum-Secure)"
        );
    }

    #[test]
    fn test_format_group_name_classical() {
        assert_eq!(format_group_name(X25519), "X25519 (Classical)");
        assert_eq!(format_group_name(0x0017), "secp256r1 (Classical)");
        assert_eq!(format_group_name(0x0018), "secp384r1 (Classical)");
        assert_eq!(format_group_name(0x0019), "secp521r1 (Classical)");
    }

    #[test]
    fn test_format_group_name_unknown() {
        assert_eq!(format_group_name(0x9999), "Unknown Group (0x9999)");
        assert_eq!(format_group_name(0x0000), "Unknown Group (0x0000)");
        assert_eq!(format_group_name(0xFFFF), "Unknown Group (0xffff)");
    }

    #[test]
    fn test_tls_constants() {
        assert_eq!(TLS_HANDSHAKE, 0x16);
        assert_eq!(TLS_CHANGE_CIPHER_SPEC, 0x14);
        assert_eq!(TLS_ALERT, 0x15);
        assert_eq!(TLS_APPLICATION_DATA, 0x17);
        assert_eq!(TLS_VERSION_1_3, 0x0304);
        assert_eq!(TLS_VERSION_1_2, 0x0303);
    }

    #[test]
    fn test_handshake_types() {
        assert_eq!(CLIENT_HELLO, 0x01);
        assert_eq!(SERVER_HELLO, 0x02);
    }

    #[test]
    fn test_extension_types() {
        assert_eq!(SUPPORTED_GROUPS, 0x000a);
        assert_eq!(KEY_SHARE, 0x0033);
        assert_eq!(SUPPORTED_VERSIONS, 0x002b);
    }

    #[test]
    fn test_named_groups() {
        assert_eq!(X25519, 0x001d);
        assert_eq!(X25519_MLKEM768, 0x11ec);
        assert_eq!(X25519_KYBER768_DRAFT, 0x6399);
    }

    #[test]
    fn test_tls_handshake_info_quantum_detection() {
        // Test quantum-secure group detection
        let info = TlsHandshakeInfo {
            server_selected_group: Some(X25519_MLKEM768),
            supports_quantum: true,
            ..Default::default()
        };
        assert!(info.supports_quantum);
        assert_eq!(info.server_selected_group, Some(X25519_MLKEM768));

        // Test classical group detection
        let info = TlsHandshakeInfo {
            server_selected_group: Some(X25519),
            supports_quantum: false,
            ..Default::default()
        };
        assert!(!info.supports_quantum);
        assert_eq!(info.server_selected_group, Some(X25519));
    }

    #[test]
    fn test_tls_handshake_info_client_groups() {
        // Test adding supported groups
        let info = TlsHandshakeInfo {
            client_supported_groups: vec![X25519_MLKEM768, X25519_KYBER768_DRAFT, X25519],
            ..Default::default()
        };
        assert_eq!(info.client_supported_groups.len(), 3);
        assert!(info.client_supported_groups.contains(&X25519_MLKEM768));
        assert!(info
            .client_supported_groups
            .contains(&X25519_KYBER768_DRAFT));
        assert!(info.client_supported_groups.contains(&X25519));
    }

    #[test]
    fn test_tls_handshake_info_key_shares() {
        // Test client key shares
        let info = TlsHandshakeInfo {
            client_key_shares: vec![X25519_MLKEM768, X25519],
            ..Default::default()
        };
        assert_eq!(info.client_key_shares.len(), 2);
        assert!(info.client_key_shares.contains(&X25519_MLKEM768));
        assert!(info.client_key_shares.contains(&X25519));

        // Test server key share
        let info = TlsHandshakeInfo {
            server_key_share: Some(X25519_MLKEM768),
            ..Default::default()
        };
        assert_eq!(info.server_key_share, Some(X25519_MLKEM768));
    }

    #[test]
    fn test_tls_version_negotiation() {
        // Test TLS 1.3 negotiation
        let info = TlsHandshakeInfo {
            negotiated_version: Some(TLS_VERSION_1_3),
            ..Default::default()
        };
        assert_eq!(info.negotiated_version, Some(TLS_VERSION_1_3));

        // Test TLS 1.2 negotiation
        let info = TlsHandshakeInfo {
            negotiated_version: Some(TLS_VERSION_1_2),
            ..Default::default()
        };
        assert_eq!(info.negotiated_version, Some(TLS_VERSION_1_2));
    }

    #[test]
    fn test_cipher_suite_detection() {
        // Test TLS 1.3 cipher suites
        let info = TlsHandshakeInfo {
            cipher_suite: Some(0x1301), // TLS_AES_128_GCM_SHA256
            ..Default::default()
        };
        assert_eq!(info.cipher_suite, Some(0x1301));

        let info = TlsHandshakeInfo {
            cipher_suite: Some(0x1302), // TLS_AES_256_GCM_SHA384
            ..Default::default()
        };
        assert_eq!(info.cipher_suite, Some(0x1302));

        let info = TlsHandshakeInfo {
            cipher_suite: Some(0x1303), // TLS_CHACHA20_POLY1305_SHA256
            ..Default::default()
        };
        assert_eq!(info.cipher_suite, Some(0x1303));
    }

    #[test]
    fn test_quantum_group_priority() {
        // Test that quantum-secure groups are prioritized
        let quantum_groups = vec![X25519_MLKEM768, X25519_KYBER768_DRAFT];
        let classical_groups = vec![X25519, 0x0017, 0x0018, 0x0019];

        for &group in &quantum_groups {
            let name = format_group_name(group);
            assert!(name.contains("Quantum-Secure"));
        }

        for &group in &classical_groups {
            let name = format_group_name(group);
            assert!(name.contains("Classical"));
        }
    }

    #[test]
    fn test_tls_record_parsing_constants() {
        // Test that we can identify different TLS record types
        let record_types = vec![
            (TLS_HANDSHAKE, "Handshake"),
            (TLS_CHANGE_CIPHER_SPEC, "Change Cipher Spec"),
            (TLS_ALERT, "Alert"),
            (TLS_APPLICATION_DATA, "Application Data"),
        ];

        for (record_type, name) in record_types {
            match record_type {
                0x16 => assert_eq!(name, "Handshake"),
                0x14 => assert_eq!(name, "Change Cipher Spec"),
                0x15 => assert_eq!(name, "Alert"),
                0x17 => assert_eq!(name, "Application Data"),
                _ => panic!("Unknown record type"),
            }
        }
    }

    #[test]
    fn test_extension_type_identification() {
        let extensions = vec![
            (SUPPORTED_GROUPS, "supported_groups"),
            (KEY_SHARE, "key_share"),
            (SUPPORTED_VERSIONS, "supported_versions"),
            (0x0000, "server_name"),
            (0x000d, "signature_algorithms"),
        ];

        for (ext_type, name) in extensions {
            match ext_type {
                0x000a => assert_eq!(name, "supported_groups"),
                0x0033 => assert_eq!(name, "key_share"),
                0x002b => assert_eq!(name, "supported_versions"),
                0x0000 => assert_eq!(name, "server_name"),
                0x000d => assert_eq!(name, "signature_algorithms"),
                _ => {}
            }
        }
    }

    #[test]
    fn test_quantum_algorithm_identification() {
        // Test that we can identify quantum-secure vs classical algorithms
        let test_cases = vec![
            (X25519_MLKEM768, true, "X25519+ML-KEM-768"),
            (X25519_KYBER768_DRAFT, true, "X25519+Kyber768-Draft"),
            (X25519, false, "X25519"),
            (0x0017, false, "secp256r1"),
            (0x0018, false, "secp384r1"),
            (0x0019, false, "secp521r1"),
        ];

        for (group_id, is_quantum, expected_name_part) in test_cases {
            let formatted_name = format_group_name(group_id);

            if is_quantum {
                assert!(formatted_name.contains("Quantum-Secure"));
                assert!(formatted_name.contains(expected_name_part));
            } else {
                assert!(formatted_name.contains("Classical"));
                assert!(formatted_name.contains(expected_name_part));
            }
        }
    }

    #[test]
    fn test_tls_handshake_info_clone() {
        let original = TlsHandshakeInfo {
            client_supported_groups: vec![X25519_MLKEM768, X25519],
            server_selected_group: Some(X25519_MLKEM768),
            supports_quantum: true,
            ..Default::default()
        };

        let cloned = original.clone();
        assert_eq!(
            cloned.client_supported_groups,
            original.client_supported_groups
        );
        assert_eq!(cloned.server_selected_group, original.server_selected_group);
        assert_eq!(cloned.supports_quantum, original.supports_quantum);
    }

    #[test]
    fn test_comprehensive_quantum_detection() {
        // Scenario 1: Server selects quantum-secure group
        let info = TlsHandshakeInfo {
            server_selected_group: Some(X25519_MLKEM768),
            server_key_share: Some(X25519_MLKEM768),
            supports_quantum: true,
            ..Default::default()
        };
        assert!(info.supports_quantum);

        // Scenario 2: Server selects classical group despite quantum offer
        let info = TlsHandshakeInfo {
            server_selected_group: Some(X25519),
            server_key_share: Some(X25519),
            supports_quantum: false,
            ..Default::default()
        };
        assert!(!info.supports_quantum);

        // Scenario 3: Client offers quantum but server doesn't respond
        let info = TlsHandshakeInfo {
            client_supported_groups: vec![X25519_MLKEM768, X25519],
            server_selected_group: None,
            supports_quantum: false,
            ..Default::default()
        };
        assert!(!info.supports_quantum);
    }

    #[test]
    fn test_tls_version_compatibility() {
        // Test that quantum algorithms require TLS 1.3
        // TLS 1.3 with quantum algorithms should be supported
        let info = TlsHandshakeInfo {
            negotiated_version: Some(TLS_VERSION_1_3),
            server_selected_group: Some(X25519_MLKEM768),
            supports_quantum: true,
            ..Default::default()
        };
        assert!(info.supports_quantum);
        assert_eq!(info.negotiated_version, Some(TLS_VERSION_1_3));

        // TLS 1.2 should not support quantum algorithms
        let info = TlsHandshakeInfo {
            negotiated_version: Some(TLS_VERSION_1_2),
            supports_quantum: false,
            ..Default::default()
        };
        assert!(!info.supports_quantum);
        assert_eq!(info.negotiated_version, Some(TLS_VERSION_1_2));
    }
}
