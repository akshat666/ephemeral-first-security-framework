# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

The EFSF team takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose your findings.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: **security@efsf.io** (placeholder - update with real address)

Include the following information:

1. **Type of vulnerability** (e.g., cryptographic weakness, injection, information disclosure)
2. **Location** of the affected code (file path, function name)
3. **Steps to reproduce** or proof-of-concept
4. **Potential impact** of the vulnerability
5. **Suggested fix** (if you have one)

### What to Expect

- **Acknowledgment** within 48 hours
- **Initial assessment** within 7 days
- **Regular updates** on progress (at least weekly)
- **Credit** in the security advisory (if desired)

### Scope

The following are in scope for security reports:

- Cryptographic implementation weaknesses
- Authentication/authorization bypasses
- Data leakage or exposure
- TTL enforcement bypasses
- Destruction verification weaknesses
- Memory safety issues
- Injection vulnerabilities

The following are out of scope:

- Vulnerabilities in dependencies (report to the dependency maintainers)
- Issues requiring physical access to systems
- Social engineering attacks
- Denial of service attacks (unless they bypass security controls)

## Security Best Practices for Users

When deploying EFSF:

1. **Use strong KMS backends** — Prefer hardware-backed key storage (AWS KMS, Azure Key Vault, HashiCorp Vault with HSM)

2. **Enable attestation** — Always enable destruction certificates for compliance-sensitive data

3. **Monitor TTL violations** — Set up alerts for `efsf_ttl_violations_total` metric

4. **Secure Redis** — If using Redis backend:
   - Enable TLS
   - Use authentication
   - Deploy in private network
   - Enable persistence cautiously (conflicts with ephemerality goals)

5. **Audit regularly** — Review destruction certificates and audit logs

6. **Keep updated** — Apply security patches promptly

## Security Design Principles

EFSF is built with the following security principles:

1. **Defense in depth** — Multiple layers (encryption + TTL + crypto-shredding)
2. **Fail secure** — Operations fail closed, not open
3. **Minimal trust** — Don't trust storage backends to enforce deletion
4. **Verifiable claims** — All destruction claims are cryptographically signed
5. **Minimal dependencies** — Reduce attack surface

## Cryptographic Details

- **Encryption**: AES-256-GCM (authenticated encryption)
- **Key Derivation**: HKDF-SHA256
- **Signatures**: Ed25519 for destruction certificates
- **Random Generation**: `secrets` module (CSPRNG)

## Known Limitations

1. **Software-only memory zeroing** — Without hardware TEE, memory zeroing is best-effort and may be defeated by:
   - Compiler optimizations
   - Memory dumps
   - Cold boot attacks

2. **Clock dependency** — TTL enforcement relies on system clocks; clock skew can cause early/late destruction

3. **Backup systems** — EFSF cannot prevent external backup systems from retaining data; ensure backup policies align with ephemerality requirements

## Vulnerability Disclosure Timeline

1. **Day 0**: Vulnerability reported
2. **Day 2**: Acknowledgment sent
3. **Day 7**: Initial assessment complete
4. **Day 30**: Target for fix development
5. **Day 45**: Target for coordinated disclosure

We may adjust timelines based on severity and complexity. Critical vulnerabilities may be fast-tracked.

## Recognition

We maintain a Hall of Fame for security researchers who help improve EFSF:

(This section will be populated as reports are received)

---

Thank you for helping keep EFSF and its users secure!
