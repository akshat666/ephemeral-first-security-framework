# EFSF TypeScript SDK

TypeScript implementation of the Ephemeral-First Security Framework (EFSF).

## Overview

EFSF is a security framework built on the principle that **data that no longer exists cannot be stolen**. This SDK provides:

- **Ephemeral Storage**: Data with automatic TTL-based expiration
- **Crypto-Shredding**: Encryption keys destroyed on expiration, making data permanently unrecoverable
- **Destruction Certificates**: Cryptographically signed proof of data destruction for compliance
- **Sealed Execution**: Contexts where all state is guaranteed to be destroyed on exit
- **Data Classification**: Enforced TTL policies based on data sensitivity

## Installation

```bash
npm install @efsf/typescript
```

For Redis backend support:

```bash
npm install @efsf/typescript ioredis
```

## Quick Start

```typescript
import { EphemeralStore, DataClassification, sealed } from '@efsf/typescript';

// Create a store
const store = new EphemeralStore({
  backend: 'memory://',  // Use 'redis://localhost:6379' for production
  defaultTTL: '1h',
  attestation: true,
});

// Store sensitive data with TTL
const record = await store.put(
  { user_id: '123', session_token: 'secret' },
  {
    ttl: '30m',
    classification: DataClassification.TRANSIENT,
  }
);

console.log(`Stored: ${record.id}, expires at ${record.expiresAt}`);

// Retrieve data
const data = await store.get(record.id);

// Destroy with certificate (crypto-shredding)
const certificate = await store.destroy(record.id);
console.log(`Destruction certificate: ${certificate.certificateId}`);

// Data is now permanently unrecoverable
```

## Data Classifications

| Classification | Default TTL | Max TTL | Use Case |
|---------------|-------------|---------|----------|
| `TRANSIENT` | 1 hour | 24 hours | Sessions, OTPs, tokens |
| `SHORT_LIVED` | 1 day | 7 days | Shopping carts, temp uploads |
| `RETENTION_BOUND` | 90 days | 7 years | Invoices, audit logs |
| `PERSISTENT` | None | None | Legal holds, archival |

## Sealed Execution

For processing sensitive data with guaranteed cleanup:

```typescript
import { sealed, SealedExecution } from '@efsf/typescript';

// Decorator style
const processPayment = sealed({ attestation: true })(
  async (cardNumber: string, amount: number) => {
    // All local state destroyed on return
    return { success: true, masked: `****${cardNumber.slice(-4)}` };
  }
);

const result = await processPayment('4111-1111-1111-1234', 99.99);
// result._destruction_certificate contains proof of cleanup

// Context manager style
const seal = new SealedExecution({ attestation: true });
await seal.run((ctx) => {
  const sensitive = ctx.track(Buffer.from('secret'));
  // Process sensitive data...
});
// seal.certificate contains destruction proof
```

## Storage Backends

### Memory (Default)

For testing and development:

```typescript
const store = new EphemeralStore({ backend: 'memory://' });
```

### Redis

For production with native TTL support:

```typescript
const store = new EphemeralStore({ backend: 'redis://localhost:6379' });
```

## API Reference

### EphemeralStore

```typescript
const store = new EphemeralStore({
  backend: 'memory://' | 'redis://host:port',
  defaultTTL: '1h' | 3600000,  // string or milliseconds
  attestation: true,  // enable destruction certificates
});

// Store data
const record = await store.put(data, {
  ttl: '30m',
  classification: DataClassification.TRANSIENT,
  metadata: { source: 'api' },
});

// Retrieve data
const data = await store.get(record.id);

// Check existence and TTL
const exists = await store.exists(record.id);
const ttlMs = await store.ttl(record.id);

// Destroy with certificate
const certificate = await store.destroy(record.id);

// List certificates
const certs = store.listCertificates();

// Statistics
const stats = store.stats();

// Cleanup
await store.close();
```

### parseTTL

Parse human-readable TTL strings:

```typescript
import { parseTTL } from '@efsf/typescript';

parseTTL('30s');  // 30000 (30 seconds)
parseTTL('5m');   // 300000 (5 minutes)
parseTTL('2h');   // 7200000 (2 hours)
parseTTL('7d');   // 604800000 (7 days)
```

### DestructionCertificate

Certificates provide compliance-ready proof:

```typescript
{
  certificate_id: "uuid",
  version: "1.0",
  resource: {
    type: "ephemeral_data",
    id: "record-id",
    classification: "TRANSIENT",
    metadata: {}
  },
  destruction: {
    method: "crypto_shred",
    timestamp: "2025-01-25T...",
    verified_by: "efsf-local-authority"
  },
  chain_of_custody: {
    created_at: "...",
    access_count: 3,
    hash_chain: ["hash1", "hash2", ...]
  },
  signature: "base64-ed25519-signature"
}
```

## Compliance

EFSF helps with:

- **GDPR Article 17**: Right to erasure with verifiable proof
- **GDPR Article 25**: Data protection by design
- **CCPA §1798.105**: Right to deletion with audit trail
- **HIPAA §164.530**: Retention and destruction documentation
- **SOX §802**: Record retention with destruction certificates

## Security Notes

1. **Memory Zeroing**: Best-effort in JavaScript due to GC. For true guarantees, use hardware TEEs (Intel SGX, AWS Nitro Enclaves).

2. **Key Management**: DEKs stored in memory. For production, integrate with HSM or KMS.

3. **Backend Security**: Use Redis with TLS and authentication in production.

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Build
npm run build

# Type check
npm run typecheck

# Lint
npm run lint
```

## Examples

See the `examples/` directory:

- `basic-usage.ts` - Core SDK features
- `express-example.ts` - Web framework integration

## License

Apache 2.0
