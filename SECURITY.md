# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in pqready, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Send an email to [github@devinegan.com] with:
   - A description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact assessment
   - Any suggested fixes (if available)

## Response Timeline

- **Acknowledgment**: We aim to acknowledge receipt within 24 hours
- **Initial Assessment**: We will provide an initial assessment within 72 hours
- **Fix Timeline**: Critical vulnerabilities will be addressed within 7 days, others within 30 days
- **Disclosure**: We will coordinate with you on responsible disclosure timing

## Security Considerations

This tool performs network connections and TLS analysis. Please be aware:

- **Network Traffic**: The tool sends TLS handshake requests to target servers
- **DNS Queries**: Hostname resolution is performed using system DNS
- **Local Execution**: The tool runs with user privileges and does not require elevated access
- **Data Handling**: No sensitive data is stored or transmitted beyond the TLS handshake process

## Scope

Security reports should focus on:

- Remote code execution vulnerabilities
- Memory safety issues
- Cryptographic implementation flaws
- Input validation bypasses
- Privilege escalation

Out of scope:

- Denial of service via resource exhaustion
- Issues requiring physical access to the machine
- Social engineering attacks

Thank you for helping keep pqready secure!
