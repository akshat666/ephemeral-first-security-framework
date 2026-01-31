<p align="center">
  <h1 align="center">Ephemeral-First Security Framework (EFSF)</h1>
  <p align="center">
    <strong>Security through transience, not just encryption</strong>
  </p>
  <p align="center">
    <a href="#quick-start">Quick Start</a> •
    <a href="#core-principles">Principles</a> •
    <a href="#the-five-pillars">Pillars</a> •
    <a href="docs/SPECIFICATION.md">Specification</a> •
    <a href="docs/ARCHITECTURE.md">Architecture</a> •
    <a href="#contributing">Contributing</a>
  </p>
</p>

---
## Ephemeral-First Security Framework (EFSF)

The Ephemeral-First Security Framework (EFSF) is an open-source security framework that treats **ephemerality as a first-class privacy and security primitive**, rather than relying solely on encryption and access control.

Traditional security architectures focus on protecting data at rest and in transit, but assume long-lived persistence. This assumption increases privacy risk, regulatory exposure, and blast radius in the event of compromise. EFSF challenges this model by enforcing **data minimization through guaranteed lifecycle termination**, where sensitive data is automatically destroyed after its intended use.

EFSF provides a conceptual framework and reference implementations across multiple programming languages (Python, TypeScript, Java) that enable:
- Time-bound (TTL-based) data storage
- Cryptographically verifiable data destruction
- Sealed execution contexts that prevent residual state leakage
- Explicit lifecycle control for sensitive data and computation

The framework is intended for developers, security architects, and researchers designing systems where privacy, safety, and regulatory compliance require **data to disappear by design**, not just be encrypted.

## The Problem

Modern security assumes data will exist forever and tries to protect it indefinitely. This is a losing game:

- **Encryption degrades** — Today's secure algorithm is tomorrow's vulnerability
- **Keys get compromised** — Given enough time, any secret can be exposed  
- **Data accumulates** — The more you store, the bigger the breach
- **Compliance is reactive** — "Delete within 30 days" becomes "hope we remembered"

**What if the data simply wasn't there to steal?**

## The EFSF Thesis

> **Ephemerality—the enforced destruction of compute, storage, and state after use—is a stronger and more fundamental privacy primitive than encryption alone.**

Data that no longer exists cannot be:
- Decrypted by future quantum computers
- Exfiltrated by insider threats
- Exposed in breaches
- Subpoenaed after retention periods
- Weaponized by AI systems trained on historical data

EFSF provides the primitives, patterns, and tools to make **transience the default**.

## Quick Start

### Installation

**Python:**
```bash
pip install efsf
```

**TypeScript/Node.js:**
```bash
npm install @efsf/typescript
```

**Java:**
```xml
<dependency>
    <groupId>app.hideit</groupId>
    <artifactId>efsf-java</artifactId>
    <version>0.3.0</version>
</dependency>
```

### Basic Usage

**Python:**
```python
from efsf import EphemeralStore, DataClassification

# Initialize an ephemeral store
store = EphemeralStore(
    backend="redis://localhost:6379",
    default_ttl="1h"
)

# Store data that automatically destroys itself
record = store.put(
    data={"user_id": "123", "session_token": "abc"},
    ttl="30m",  # Gone in 30 minutes, guaranteed
    classification=DataClassification.TRANSIENT
)

# Retrieve while it exists
data = store.get(record.id)

# Get cryptographic proof of destruction
certificate = store.destroy(record.id)
```

**TypeScript:**
```typescript
import { EphemeralStore, DataClassification } from '@efsf/typescript';

// Initialize an ephemeral store
const store = new EphemeralStore({
  backend: 'redis://localhost:6379',
  defaultTTL: '1h',
});

// Store data that automatically destroys itself
const record = await store.put(
  { user_id: '123', session_token: 'abc' },
  { ttl: '30m', classification: DataClassification.TRANSIENT }
);

// Retrieve while it exists
const data = await store.get(record.id);

// Get cryptographic proof of destruction
const certificate = await store.destroy(record.id);
```

**Java:**
```java
import app.hideit.EphemeralStore;
import app.hideit.record.DataClassification;

// Initialize an ephemeral store
try (EphemeralStore store = EphemeralStore.builder()
    .backend("redis://localhost:6379")
    .defaultTTL("1h")
    .build()) {

    // Store data that automatically destroys itself
    var record = store.put(
        Map.of("user_id", "123", "session_token", "abc"),
        "30m",  // Gone in 30 minutes, guaranteed
        DataClassification.TRANSIENT
    );

    // Retrieve while it exists
    var data = store.get(record.getId());

    // Get cryptographic proof of destruction
    var certificate = store.destroy(record.getId());
}
```

### Sealed Execution

**Python:**
```python
from efsf import sealed

@sealed(attestation=True)
def process_sensitive_data(ssn: str, income: float) -> str:
    # All variables in this function are automatically
    # zeroed from memory when the function exits
    risk_score = calculate_risk(ssn, income)
    return f"approved:{risk_score > 0.7}"

# State is gone. Certificate is generated.
result = process_sensitive_data("123-45-6789", 75000.00)
```

**TypeScript:**
```typescript
import { sealed } from '@efsf/typescript';

const processSensitiveData = sealed({ attestation: true })(
  async (ssn: string, income: number) => {
    // All state destroyed on return
    const riskScore = calculateRisk(ssn, income);
    return { approved: riskScore > 0.7 };
  }
);

// State is gone. Certificate is attached to result.
const result = await processSensitiveData('123-45-6789', 75000.00);
```

**Java:**
```java
import app.hideit.sealed.SealedExecution;

// Using try-with-resources for automatic cleanup
try (SealedExecution seal = SealedExecution.create()) {
    var ctx = seal.getContext();

    // Track sensitive data
    String ssn = ctx.track("123-45-6789");
    Double income = ctx.track(75000.00);

    // Process the data
    boolean approved = calculateRisk(ssn, income) > 0.7;
}
// All tracked objects are cleaned up here
```

## Core Principles

| # | Principle | Description |
|---|-----------|-------------|
| 1 | **Transience by Default** | Data should have a defined lifespan. Persistence requires explicit justification. |
| 2 | **Encryption is Necessary but Insufficient** | Encrypt everything, but don't rely on encryption surviving forever. |
| 3 | **Verifiable Destruction** | Deletion must be cryptographically provable, not just promised. |
| 4 | **Lifecycle-Aware Design** | Every piece of data has a classification and corresponding TTL policy. |
| 5 | **Ephemerality Propagation** | Derived data inherits (or shortens) the TTL of its sources. |
| 6 | **Minimum Viable Retention** | Keep data only as long as legally required, not "just in case." |
| 7 | **Defense Through Absence** | The most secure data is data that no longer exists. |

## The Five Pillars

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           APPLICATION LAYER                              │
├──────────┬──────────┬──────────┬──────────┬──────────────────────────────┤
│          │          │          │          │                              │
│ EPHEMERAL│ EPHEMERAL│ EPHEMERAL│ EPHEMERAL│       ATTESTATION            │
│   DATA   │ COMPUTE  │ IDENTITY │ CHANNELS │         LAYER                │
│          │          │          │          │                              │
│ • TTL    │ • Sealed │ • Short  │ • Forward│ • Destruction Certificates   │
│ • Crypto │   Exec   │   Creds  │   Secrecy│ • Audit Trails               │
│   Shred  │ • TEE    │ • JIT    │ • Channel│ • Compliance Evidence        │
│ • Key    │ • Memory │   Access │   Expiry │ • Chain of Custody           │
│   Rotate │   Zero   │ • Auto   │ • No     │                              │
│          │          │   Revoke │   Persist│                              │
├──────────┴──────────┴──────────┴──────────┴──────────────────────────────┤
│                    INFRASTRUCTURE (K8s, Cloud, Databases)                │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1. Ephemeral Data
Encrypted storage with enforced TTLs and crypto-shredding. When TTL expires, the encryption key is destroyed, making data permanently unrecoverable.

### 2. Ephemeral Compute  
Sealed execution contexts where all state (memory, registers, temp files) is guaranteed to be destroyed on exit. Integrates with TEEs (SGX, Nitro Enclaves) for hardware-backed guarantees.

### 3. Ephemeral Identity
Short-lived credentials that auto-expire. No long-lived API keys or service accounts. JIT (Just-In-Time) access provisioning.

### 4. Ephemeral Channels
Communication channels with built-in forward secrecy and session expiration. Messages are not persisted by default.

### 5. Attestation Layer
Cryptographic proof that destruction occurred. Generates certificates suitable for compliance audits (GDPR, CCPA, HIPAA).

## Data Classification

| Classification | TTL Range | Example | Destruction Method |
|---------------|-----------|---------|-------------------|
| `TRANSIENT` | Seconds–Hours | Session tokens, OTPs | Memory zero |
| `SHORT_LIVED` | Hours–Days | Shopping carts, temp uploads | Crypto-shred |
| `RETENTION_BOUND` | Days–Years | Invoices, audit logs | Scheduled + certificate |
| `PERSISTENT` | Indefinite | Legal holds, archival | Explicit justification required |

## Compliance Mapping

EFSF helps automate compliance with:

- **GDPR Article 17** — Right to erasure with verifiable proof
- **GDPR Article 25** — Data protection by design (ephemerality as default)
- **CCPA §1798.105** — Right to deletion with audit trail
- **HIPAA §164.530** — Retention and destruction documentation
- **SOX §802** — Record retention with destruction certificates

## Project Structure

```
efsf/
├── sdk/
│   ├── python/          # Python SDK
│   │   ├── efsf/        # Core library
│   │   ├── tests/       # Test suite
│   │   └── examples/    # Python examples
│   ├── typescript/      # TypeScript SDK
│   │   ├── src/         # Core library
│   │   ├── tests/       # Test suite
│   │   └── examples/    # TypeScript examples
│   └── java/            # Java SDK
│       ├── src/         # Core library (app.hideit.*)
│       ├── examples/    # Java examples
│       └── pom.xml      # Maven configuration
├── docs/
│   ├── SPECIFICATION.md # Formal specification
│   └── ARCHITECTURE.md  # Reference architecture
├── kubernetes/          # K8s operator (coming soon)
└── terraform/           # Cloud modules (coming soon)
```

## Roadmap

- [x] Core specification
- [x] Python SDK with Redis backend
- [x] TypeScript SDK with Redis backend
- [x] Java SDK with Redis backend
- [ ] Go SDK
- [ ] Kubernetes Operator
- [ ] AWS/GCP/Azure modules
- [ ] Terraform provider
- [ ] CNCF Sandbox submission

## Comparison with Existing Approaches

| Approach | Focus | EFSF Difference |
|----------|-------|-----------------|
| Zero Trust | "Never trust, always verify" | EFSF adds: "Never retain, always destroy" |
| Privacy by Design | Principles for privacy | EFSF provides concrete primitives |
| NIST 800-88 | End-of-life sanitization | EFSF operationalizes at runtime |
| Encryption at Rest | Protect stored data | EFSF ensures data doesn't stay stored |

## Releasing a New Version

All three SDKs share the same version number. To release a new version, update the version in these files:

| File | Field |
|------|-------|
| `sdk/python/pyproject.toml` | `version = "x.y.z"` |
| `sdk/python/efsf/__init__.py` | `__version__ = "x.y.z"` |
| `sdk/typescript/package.json` | `"version": "x.y.z"` |
| `sdk/typescript/src/index.ts` | `export const VERSION = 'x.y.z'` |
| `sdk/java/build.gradle.kts` | `version = "x.y.z"` |

Then commit, tag, and push:

```bash
git add -A && git commit -m "Release vx.y.z"
git tag vx.y.z
git push && git push --tags
```

The `v*` tag triggers the release workflow which publishes to PyPI, npm, and Maven Central.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas where we need help:
- Additional backend implementations (PostgreSQL, DynamoDB, S3)
- Language SDKs (Go, Rust)
- Kubernetes operator development
- Security audits and threat modeling
- Documentation and examples

## License

Apache 2.0 — See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>The most secure data is data that no longer exists.</strong>
</p>
