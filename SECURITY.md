# Security Policy

## Supported Versions

We actively support and provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

**DO NOT create a public GitHub issue for security vulnerabilities.**

Instead, please report them via one of these methods:

1. **GitHub Private Vulnerability Reporting** (preferred):
   - Go to the [Security tab](https://github.com/Unknowlars/Grafana-alloy-bootstrap/security/advisories/new)
   - Click "Report a vulnerability"
   - Fill out the template with as much detail as possible

2. **Email**: 
   - TODO: Add security contact email if available

### What to Include

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Fix Timeline**: Depends on severity (critical issues prioritized)

## Security Best Practices (For Users)

When running this script:

1. **Review before running** - Always read scripts before executing with sudo
2. **Use specific endpoints** - Don't expose Alloy UI to the public internet
3. **Limit permissions** - Only enable packs you need
4. **Keep Alloy updated** - The script checks for updates; install them promptly
5. **Secure state file** - The script sets restrictive permissions on `state.env`

## Scope

This project is a configuration generator. It does:
- Install/upgrade Grafana Alloy via official APT repository
- Generate Alloy configuration files
- Manage Alloy service (enable, start, reload)

It does NOT:
- Access external networks except user-configured endpoints
- Store credentials (only stores non-sensitive configuration URLs)
- Execute arbitrary code from untrusted sources
