use anyhow::{anyhow, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

// TLS Constants
const TLS_HANDSHAKE: u8 = 0x16;
const TLS_CHANGE_CIPHER_SPEC: u8 = 0x14;
const TLS_ALERT: u8 = 0x15;
const TLS_APPLICATION_DATA: u8 = 0x17;
const TLS_VERSION_1_3: u16 = 0x0304;
const TLS_VERSION_1_2: u16 = 0x0303;

// Handshake Types
const CLIENT_HELLO: u8 = 0x01;
const SERVER_HELLO: u8 = 0x02;

// Extension Types
const SUPPORTED_GROUPS: u16 = 0x000a;
const KEY_SHARE: u16 = 0x0033;
const SUPPORTED_VERSIONS: u16 = 0x002b;

// Named Groups (for supported_groups extension)
const X25519: u16 = 0x001d;
const X25519_MLKEM768: u16 = 0x11ec; // X25519+ML-KEM-768 (recommended by Cloudflare)
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
        // Set read timeout
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;

        Ok(Self {
            stream,
            handshake_info: TlsHandshakeInfo::default(),
        })
    }

    pub fn perform_quantum_handshake_analysis(
        &mut self,
        hostname: &str,
        verbose: bool,
    ) -> Result<TlsHandshakeInfo> {
        if verbose {
            println!("🔬 Starting low-level TLS handshake analysis");
        }

        // Send a ClientHello with quantum-secure groups
        self.send_quantum_client_hello(hostname, verbose)?;

        // Read and parse ServerHello
        self.parse_server_response(verbose)?;

        // Analyze for quantum-secure algorithms
        self.analyze_quantum_support(verbose);

        Ok(self.handshake_info.clone())
    }

    fn send_quantum_client_hello(&mut self, hostname: &str, verbose: bool) -> Result<()> {
        if verbose {
            println!("📤 Sending ClientHello with quantum-secure groups");
        }

        let client_hello = self.build_quantum_client_hello(hostname)?;

        if verbose {
            println!("🔍 ClientHello details:");
            println!("   • Total size: {} bytes", client_hello.len());
            println!("   • Hostname: {}", hostname);
            println!("   • Client offering groups: X25519+ML-KEM-768 (0x11ec), X25519+Kyber768-Draft00 (0x6399), X25519 (0x001d)");
        }

        self.stream.write_all(&client_hello)?;
        self.stream.flush()?;

        if verbose {
            println!("✅ ClientHello sent successfully");
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

    fn parse_server_response(&mut self, verbose: bool) -> Result<()> {
        if verbose {
            println!("📥 Reading server response...");
        }

        let mut buffer = vec![0u8; 4096];
        let bytes_read = self.stream.read(&mut buffer)?;

        if verbose {
            println!("📦 Received {} bytes from server", bytes_read);
            if bytes_read > 0 {
                println!(
                    "🔍 Raw response (first {} bytes): {:02x?}",
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
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            return Err(anyhow!(
                "Server response too short ({} bytes): {}",
                bytes_read,
                hex_data
            ));
        }

        buffer.truncate(bytes_read);

        self.parse_tls_records(&buffer, verbose)?;

        Ok(())
    }

    fn parse_tls_records(&mut self, data: &[u8], verbose: bool) -> Result<()> {
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
                    "📋 TLS Record: type={:02x}, version={:04x}, length={}",
                    content_type, version, length
                );
            }

            match content_type {
                TLS_HANDSHAKE => {
                    self.parse_handshake_messages(&data[offset + 5..offset + 5 + length], verbose)?;
                }
                TLS_CHANGE_CIPHER_SPEC => {
                    if verbose {
                        println!("🔄 ChangeCipherSpec (TLS 1.3 compatibility)");
                    }
                }
                TLS_ALERT => {
                    if verbose {
                        println!("⚠️  TLS Alert received");
                    }
                    self.parse_tls_alert(&data[offset + 5..offset + 5 + length], verbose)?;
                }
                TLS_APPLICATION_DATA => {
                    if verbose {
                        println!("📊 Application Data ({} bytes encrypted)", length);
                    }
                }
                _ => {
                    if verbose {
                        println!("❓ Unknown TLS record type: 0x{:02x}", content_type);
                    }
                }
            }

            offset += 5 + length;
        }

        Ok(())
    }

    fn parse_handshake_messages(&mut self, data: &[u8], verbose: bool) -> Result<()> {
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
                    "🤝 Handshake message: type={:02x}, length={}",
                    msg_type, length
                );
            }

            match msg_type {
                SERVER_HELLO => {
                    self.parse_server_hello(&data[offset + 4..offset + 4 + length], verbose)?;
                }
                _ => {
                    if verbose {
                        println!("📝 Other handshake message type: {:02x}", msg_type);
                    }
                }
            }

            offset += 4 + length;
        }

        Ok(())
    }

    fn parse_server_hello(&mut self, data: &[u8], verbose: bool) -> Result<()> {
        if data.len() < 38 {
            return Err(anyhow!("ServerHello too short"));
        }

        let version = u16::from_be_bytes([data[0], data[1]]);
        self.handshake_info.negotiated_version = Some(version);

        if verbose {
            println!("🔒 ServerHello version: {:04x}", version);
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
            println!("🔑 Selected cipher suite: {:04x}", cipher_suite);
        }

        // Compression method
        offset += 1;

        // Extensions
        if offset + 2 <= data.len() {
            let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            if offset + extensions_len <= data.len() {
                self.parse_server_extensions(&data[offset..offset + extensions_len], verbose)?;
            }
        }

        Ok(())
    }

    fn parse_server_extensions(&mut self, data: &[u8], verbose: bool) -> Result<()> {
        let mut offset = 0;

        while offset + 4 <= data.len() {
            let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if offset + ext_len > data.len() {
                break;
            }

            if verbose {
                println!("🔧 Extension: type={:04x}, length={}", ext_type, ext_len);
            }

            match ext_type {
                KEY_SHARE => {
                    self.parse_key_share_extension(&data[offset..offset + ext_len], verbose)?;
                }
                SUPPORTED_VERSIONS => {
                    if ext_len >= 2 {
                        let version = u16::from_be_bytes([data[offset], data[offset + 1]]);
                        self.handshake_info.negotiated_version = Some(version);
                        if verbose {
                            println!("✅ Negotiated version: {:04x}", version);
                        }
                    }
                }
                _ => {
                    if verbose {
                        println!("📎 Other extension: {:04x}", ext_type);
                    }
                }
            }

            offset += ext_len;
        }

        Ok(())
    }

    fn parse_key_share_extension(&mut self, data: &[u8], verbose: bool) -> Result<()> {
        if verbose {
            println!("🔍 Key share extension data: {:02x?}", data);
        }

        if data.len() < 2 {
            if verbose {
                println!("⚠️  Key share extension too short ({} bytes)", data.len());
            }
            return Ok(());
        }

        // Check if this is a Hello Retry Request (2 bytes = just the group)
        if data.len() == 2 {
            let group = u16::from_be_bytes([data[0], data[1]]);
            if verbose {
                println!(
                    "🔄 Hello Retry Request - Server selected group: {:04x}",
                    group
                );
            }
            self.handshake_info.server_selected_group = Some(group);
            return Ok(());
        }

        // Standard key share format (4+ bytes)
        if data.len() < 4 {
            if verbose {
                println!(
                    "⚠️  Key share extension too short for standard format ({} bytes)",
                    data.len()
                );
            }
            return Ok(());
        }

        let group = u16::from_be_bytes([data[0], data[1]]);
        let key_len = u16::from_be_bytes([data[2], data[3]]) as usize;

        self.handshake_info.server_selected_group = Some(group);
        self.handshake_info.server_key_share = Some(group);

        if verbose {
            println!(
                "🗝️  Server selected group: {:04x} (key length: {})",
                group, key_len
            );
            if group == X25519_KYBER768_DRAFT {
                println!("🎯 QUANTUM-SECURE: X25519+Kyber768-Draft00 detected!");
            } else if group == X25519_MLKEM768 {
                println!("🎯 QUANTUM-SECURE: X25519+ML-KEM-768 detected!");
            } else if group == X25519 {
                println!("🔧 Classical: X25519 detected");
            }
        }

        Ok(())
    }

    fn analyze_quantum_support(&mut self, verbose: bool) {
        // Check if quantum-secure key exchange was negotiated
        let quantum_support = self
            .handshake_info
            .server_selected_group
            .map(|group| group == X25519_MLKEM768 || group == X25519_KYBER768_DRAFT)
            .unwrap_or(false);

        self.handshake_info.supports_quantum = quantum_support;

        if verbose {
            if quantum_support {
                println!("🛡️  ✅ QUANTUM-SECURE ENCRYPTION DETECTED!");
                println!("🔬 X25519+ML-KEM-768 hybrid key exchange is active");
            } else {
                println!("🛡️  ❌ No quantum-secure encryption detected");
                if let Some(group) = self.handshake_info.server_selected_group {
                    println!("🔧 Using classical key exchange: {:04x}", group);
                }
            }
        }
    }

    fn parse_tls_alert(&mut self, data: &[u8], verbose: bool) -> Result<()> {
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
                "🚨 TLS Alert: {} {} (level={}, code={})",
                level_str, description_str, level, description
            );
            if description == 110 {
                println!(
                    "💡 This means the server doesn't recognize our quantum-secure extensions"
                );
            } else if description == 50 {
                println!("💡 Server cannot decode/parse our ClientHello - likely due to unknown quantum extensions");
            } else if description == 40 {
                println!("💡 Handshake failure - server rejected our key exchange proposals");
            }
        }

        // Alert code 32 doesn't exist in standard TLS - let me check what this actually is
        if description == 32 && verbose {
            println!("⚠️  Alert code 32 - this may be a non-standard or implementation-specific alert");
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
        _ => format!("Unknown Group (0x{:04x})", group),
    }
}
