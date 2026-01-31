# EFSF Reference Architecture

## Cloud Integration Guide

**Version:** 1.0  
**Status:** Draft  
**Date:** January 2026

---

## 1. Architecture Overview

This document provides a reference architecture for implementing the Ephemeral-First Security Framework (EFSF) in cloud-native environments. It describes component interactions, integration patterns, and deployment models.

### 1.1 Design Goals

- **Cloud-Native:** Designed for Kubernetes, serverless, and microservice architectures
- **Incrementally Adoptable:** Components can be adopted independently
- **Provider Agnostic:** Works across AWS, Azure, GCP, and on-premises
- **Standards-Based:** Integrates with SPIFFE, OpenTelemetry, OPA, and other CNCF projects
- **Developer-Friendly:** SDK-first approach minimizes friction

### 1.2 Architectural Layers

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            APPLICATION LAYER                                 │
│                   (Client Apps, API Gateway, Microservices)                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                              EFSF PILLARS                                    │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────────┐  │
│  │ Ephemeral │ │ Ephemeral │ │ Ephemeral │ │ Ephemeral │ │  Attestation  │  │
│  │   Data    │ │  Compute  │ │  Identity │ │  Channels │ │    Layer      │  │
│  │           │ │           │ │           │ │           │ │               │  │
│  │ • Store   │ │ • Sealed  │ │ • Token   │ │ • mTLS    │ │ • Certs       │  │
│  │ • Crypto  │ │   Exec    │ │   Service │ │   Mesh    │ │ • Audit       │  │
│  │ • TTL     │ │ • TEE     │ │ • SPIFFE  │ │ • Forward │ │ • Compliance  │  │
│  └───────────┘ └───────────┘ └───────────┘ │   Secrecy │ └───────────────┘  │
│                                            └───────────┘                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                           CROSS-CUTTING CONCERNS                             │
│         (Policy Engine, Observability, Developer SDK, Compliance)            │
├─────────────────────────────────────────────────────────────────────────────┤
│                             INFRASTRUCTURE                                   │
│            (Kubernetes, Cloud Services, KMS, Databases, Service Mesh)        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Core Components

### 2.1 Ephemeral Data Store

**Purpose:** Provides encrypted storage with automatic lifecycle management and destruction verification.

#### Architecture

- **Storage Backend:** Pluggable (Redis, DynamoDB, PostgreSQL, S3)
- **Encryption Layer:** AES-256-GCM with per-record keys
- **Key Management:** Integration with AWS KMS, Azure Key Vault, HashiCorp Vault
- **TTL Enforcement:** Background worker + storage-native TTL where available

#### Key Lifecycle Binding

Each ephemeral data record is encrypted with a unique Data Encryption Key (DEK). The DEK is wrapped by a Key Encryption Key (KEK) managed by the KMS. When TTL expires, the DEK is destroyed, making the encrypted data permanently unrecoverable (crypto-shredding).

| Phase | Action | Key State |
|-------|--------|-----------|
| Create | Generate DEK, encrypt data | DEK active, wrapped by KEK |
| Access | Unwrap DEK, decrypt data | DEK in memory (temporary) |
| TTL Expire | Destroy DEK, issue certificate | DEK destroyed (data unrecoverable) |

#### Data Flow

```
┌──────────┐     ┌──────────────┐     ┌─────────────┐     ┌─────────┐
│  Client  │────▶│ EFSF SDK     │────▶│ Ephemeral   │────▶│ Storage │
│          │     │              │     │ Store       │     │ Backend │
└──────────┘     └──────────────┘     └─────────────┘     └─────────┘
                        │                    │
                        ▼                    ▼
                 ┌──────────────┐     ┌─────────────┐
                 │ Crypto       │     │ Attestation │
                 │ Provider     │     │ Authority   │
                 └──────────────┘     └─────────────┘
                        │
                        ▼
                 ┌──────────────┐
                 │ KMS / HSM    │
                 └──────────────┘
```

---

### 2.2 Sealed Execution Runtime

**Purpose:** Execute sensitive workloads with guaranteed state destruction on completion.

#### Implementation Options

| Option | Isolation Level | Use Case |
|--------|-----------------|----------|
| Container + SDK | Process (software) | General workloads |
| gVisor / Kata | Kernel (VM-like) | Untrusted code execution |
| AWS Nitro Enclave | Hardware (cloud) | High-security cloud workloads |
| Intel SGX / TDX | Hardware (enclave) | Maximum isolation, attestation |

#### Execution Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    SEALED EXECUTION CONTEXT                      │
│  ┌───────────┐    ┌───────────────┐    ┌───────────────────┐   │
│  │  Inputs   │───▶│   Function    │───▶│     Outputs       │   │
│  │(validated)│    │  (isolated)   │    │ (sanitized)       │   │
│  └───────────┘    └───────────────┘    └───────────────────┘   │
│                          │                                       │
│                          ▼                                       │
│                   ┌─────────────┐                                │
│                   │ Local State │ ◀── Destroyed on exit          │
│                   └─────────────┘                                │
└─────────────────────────────────────────────────────────────────┘
                          │
                          ▼
                   ┌─────────────┐
                   │ Destruction │
                   │ Certificate │
                   └─────────────┘
```

---

### 2.3 Attestation Service

**Purpose:** Issue cryptographically signed destruction certificates and maintain audit trails.

#### Certificate Format

```json
{
  "version": "1.0",
  "certificate_id": "550e8400-e29b-41d4-a716-446655440000",
  "resource": {
    "type": "ephemeral_data",
    "id": "record-abc-123",
    "classification": "TRANSIENT"
  },
  "destruction": {
    "method": "crypto_shred",
    "timestamp": "2026-01-25T15:30:00Z",
    "verified_by": "attestation-authority-prod-1"
  },
  "chain_of_custody": {
    "created_at": "2026-01-25T15:00:00Z",
    "access_count": 3,
    "hash_chain": ["a1b2c3...", "d4e5f6..."]
  },
  "signature": "base64-encoded-ed25519-signature"
}
```

#### Audit Trail Integration

- **Storage:** Append-only log (immutable ledger, S3 with Object Lock, or database)
- **Format:** OpenTelemetry-compatible for integration with existing observability
- **Retention:** Configurable per compliance requirement (7 years for SOX, etc.)
- **Query API:** REST/GraphQL for compliance reporting

---

## 3. Integration Patterns

### 3.1 Kubernetes Integration

EFSF components deploy as Kubernetes operators and sidecars:

- **EFSF Operator:** Manages EphemeralStore and SealedWorkload CRDs
- **Sidecar Injector:** Automatically injects ephemeral SDK into pods
- **Admission Controller:** Validates ephemeral policies on pod creation
- **SPIRE Integration:** Extends SPIRE for ephemeral workload identity

#### Custom Resource Definitions

```yaml
apiVersion: efsf.io/v1
kind: EphemeralStore
metadata:
  name: user-sessions
spec:
  backend: redis
  defaultTTL: 1h
  maxTTL: 24h
  destructionPolicy: crypto_shred
  keyProvider:
    type: aws_kms
    keyId: alias/efsf-sessions
  attestation:
    enabled: true
    authority: default
```

```yaml
apiVersion: efsf.io/v1
kind: SealedWorkload
metadata:
  name: payment-processor
spec:
  image: payments:v1.2.3
  isolation: nitro-enclave  # or: gvisor, kata, sgx
  maxDuration: 30s
  attestation:
    enabled: true
    reportTo: compliance-service
  resources:
    limits:
      memory: 512Mi
      cpu: 500m
```

---

### 3.2 Serverless Integration

For AWS Lambda, Azure Functions, and Google Cloud Functions:

- **Runtime Layer:** EFSF SDK as Lambda Layer / Function Extension
- **Execution Wrapper:** Wraps handler to enforce sealed execution semantics
- **Cold Start Handling:** Pre-warmed key material with secure rotation
- **Attestation Hook:** Post-invocation destruction certificate generation

#### AWS Lambda Example

```python
from efsf.aws import ephemeral_lambda

@ephemeral_lambda(
    attestation=True,
    ttl="5m",
    classification="TRANSIENT"
)
def handler(event, context):
    # All state destroyed after invocation
    sensitive_data = process(event)
    return {"statusCode": 200}
```

---

### 3.3 Service Mesh Integration

EFSF integrates with Istio, Linkerd, and other service meshes for ephemeral channels:

| Feature | EFSF Enhancement |
|---------|------------------|
| mTLS | Short-lived certificates (hours, not days) with SPIFFE integration |
| Access Logging | Optional ephemeral logs with configurable TTL |
| Session Affinity | Ephemeral session tokens with automatic expiration |

---

### 3.4 Database Integration

EFSF provides adapters for common databases:

| Database | EFSF Adapter Features |
|----------|----------------------|
| Redis | Native TTL + client-side encryption + keyspace notifications for destruction |
| DynamoDB | TTL attribute + DynamoDB Streams for destruction events + KMS integration |
| PostgreSQL | pg_cron for TTL + pgcrypto for encryption + LISTEN/NOTIFY for events |
| MongoDB | TTL indexes + client-side field-level encryption + change streams |
| S3 | Object expiration + S3 Object Lock for certificates + SSE-KMS |

---

## 4. Deployment Models

### 4.1 Single-Cluster Deployment

For organizations with a single Kubernetes cluster:

```
┌─────────────────────────────────────────────────────────────┐
│                     Kubernetes Cluster                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   EFSF      │  │ Attestation │  │    Application      │  │
│  │  Operator   │  │  Authority  │  │      Pods           │  │
│  └─────────────┘  └─────────────┘  │  ┌───────────────┐  │  │
│         │                │         │  │ + EFSF Sidecar│  │  │
│         ▼                ▼         │  └───────────────┘  │  │
│  ┌─────────────────────────────┐  └─────────────────────┘  │
│  │       Redis / Database      │                            │
│  └─────────────────────────────┘                            │
│                    │                                         │
│                    ▼                                         │
│  ┌─────────────────────────────┐                            │
│  │     Cloud KMS / Vault       │                            │
│  └─────────────────────────────┘                            │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Multi-Cluster / Multi-Cloud

For distributed deployments:

- **Federated Attestation:** Attestation authorities trust each other via certificate chain
- **Cross-Cluster Policy:** Centralized policy with local enforcement
- **Global Audit:** Aggregated audit trail with regional storage
- **Key Hierarchy:** Root KEK per region, delegated DEKs per workload

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   AWS Region 1   │     │   GCP Region 1   │     │   Azure Region 1 │
│  ┌────────────┐  │     │  ┌────────────┐  │     │  ┌────────────┐  │
│  │   EFSF     │  │     │  │   EFSF     │  │     │  │   EFSF     │  │
│  │  Cluster   │  │     │  │  Cluster   │  │     │  │  Cluster   │  │
│  └────────────┘  │     │  └────────────┘  │     │  └────────────┘  │
│        │         │     │        │         │     │        │         │
└────────┼─────────┘     └────────┼─────────┘     └────────┼─────────┘
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  ▼
                    ┌─────────────────────────┐
                    │   Federated Attestation │
                    │   & Policy Control      │
                    └─────────────────────────┘
```

### 4.3 Hybrid Cloud

For organizations with on-premises and cloud workloads, EFSF provides a unified control plane with location-aware policies. Sensitive data can be configured to remain ephemeral only within specific geographic or network boundaries.

---

## 5. Security Considerations

### 5.1 Threat Model

EFSF addresses the following threat categories:

| Threat | EFSF Mitigation |
|--------|-----------------|
| Future key compromise | Data destroyed before compromise; nothing to decrypt |
| Quantum cryptanalysis | Short-lived data destroyed before quantum computers mature |
| Insider threat | Reduced window of exposure; verifiable destruction |
| Data breach (at rest) | Less data to breach; encryption + TTL limits impact |
| Compliance violation | Automated retention enforcement; destruction certificates |
| Backup leakage | Policy enforcement on backup systems |

### 5.2 Trust Boundaries

- **Attestation Authority:** Must be protected as a critical security component
- **Key Management:** KEKs must reside in HSM or cloud KMS
- **TEE Verification:** Hardware attestation must be validated against vendor roots
- **Audit Trail:** Must be append-only with integrity verification

### 5.3 Failure Modes

| Failure | Impact | Mitigation |
|---------|--------|------------|
| TTL Drift | Early/late destruction | Use NTP and bounded tolerance |
| Key Unavailability | Can't decrypt data | Implement graceful degradation |
| Attestation Failure | No destruction proof | Queue events for retry; alert on persistent failure |
| Backup Leakage | Data persists outside EFSF | Ensure backup policies align with ephemerality |

---

## 6. Observability

### 6.1 Metrics

EFSF exposes Prometheus-compatible metrics:

| Metric | Description |
|--------|-------------|
| `efsf_records_created_total` | Ephemeral records created (by classification) |
| `efsf_records_destroyed_total` | Records destroyed (by method) |
| `efsf_ttl_violations_total` | Records exceeding TTL |
| `efsf_certificates_issued_total` | Destruction certificates issued |
| `efsf_sealed_executions_total` | Sealed execution contexts completed |
| `efsf_key_rotations_total` | Key rotation events |
| `efsf_crypto_operations_duration_seconds` | Encryption/decryption latency |

### 6.2 Tracing

OpenTelemetry spans are generated for all lifecycle events, enabling end-to-end visibility from data creation through destruction. Span attributes include:

- `efsf.record.id`
- `efsf.record.classification`
- `efsf.record.ttl_seconds`
- `efsf.destruction.method`
- `efsf.certificate.id`

### 6.3 Alerting

Recommended alerts:

| Alert | Condition | Severity |
|-------|-----------|----------|
| TTL Violation | Data exists beyond configured TTL | Critical |
| Attestation Backlog | Destruction certificates pending > threshold | Warning |
| Key Rotation Failure | KEK rotation not completed on schedule | Critical |
| Policy Drift | Ephemeral resources created without required policies | Warning |
| High Destruction Latency | P99 destruction time > threshold | Warning |

---

## 7. SDK Quick Reference

### 7.1 Python

```python
from efsf import EphemeralStore, SealedExecution, DataClassification

# Initialize store
store = EphemeralStore(
    backend="redis://localhost:6379",
    key_provider="aws_kms:alias/efsf",
    default_ttl="1h",
    attestation=True
)

# Store ephemeral data
record = store.put(
    data={"user_id": "123", "ssn": "xxx-xx-xxxx"},
    ttl="30m",
    classification=DataClassification.PII
)

# Retrieve (auto-extends TTL if configured)
data = store.get(record.id)

# Sealed execution
with SealedExecution(attestation=True) as ctx:
    sensitive = ctx.track(load_secrets())
    result = process(sensitive)
# State automatically destroyed, certificate generated

print(ctx.certificate.certificate_id)
```

### 7.2 Go

```go
import "https://github.com/akshat666/ephemeral-first-security-framework/efsf-go"

store, _ := efsf.NewStore(efsf.Config{
    Backend:     "redis://localhost:6379",
    KeyProvider: "aws_kms:alias/efsf",
    DefaultTTL:  time.Hour,
})

record, _ := store.Put(ctx, efsf.Data{
    Payload:        myData,
    TTL:            30 * time.Minute,
    Classification: efsf.PII,
})

// Sealed execution
cert, _ := efsf.Sealed(func(ctx efsf.SealedContext) error {
    return processSecurely(ctx, sensitiveData)
})
```

### 7.3 TypeScript

```typescript
import { EphemeralStore, sealed, DataClassification } from '@efsf/sdk';

const store = new EphemeralStore({
  backend: 'redis://localhost:6379',
  keyProvider: 'aws_kms:alias/efsf',
  defaultTTL: '1h',
});

const record = await store.put({
  data: { userId: '123', ssn: 'xxx-xx-xxxx' },
  ttl: '30m',
  classification: DataClassification.PII,
});

// Sealed execution decorator
@sealed({ attestation: true })
async function processSecurely(data: SensitiveData): Promise<Result> {
  // State destroyed on function exit
  return compute(data);
}
```

---

## 8. Migration Guide

### 8.1 From Traditional Storage

1. **Audit existing data stores** — Identify sensitive data and current retention
2. **Classify data** — Assign EFSF classifications to data types
3. **Deploy EFSF alongside** — Run in shadow mode, compare behavior
4. **Migrate incrementally** — Start with TRANSIENT data (lowest risk)
5. **Enable attestation** — Generate certificates for compliance evidence
6. **Decommission legacy** — Remove traditional storage once validated

### 8.2 From Encryption-Only

1. **Keep encryption** — EFSF adds TTL, doesn't replace encryption
2. **Add key lifecycle binding** — DEK TTL ≤ data TTL
3. **Implement destruction hooks** — Trigger key destruction on TTL
4. **Add attestation** — Generate certificates on destruction

---

## Appendix A: Cloud Provider Mapping

| EFSF Component | AWS | GCP | Azure |
|---------------|-----|-----|-------|
| Ephemeral Store | ElastiCache, DynamoDB | Memorystore, Firestore | Cache for Redis, Cosmos DB |
| Key Management | KMS, CloudHSM | Cloud KMS, Cloud HSM | Key Vault, Managed HSM |
| Sealed Compute | Nitro Enclaves | Confidential VMs | Confidential Computing |
| Identity | IAM, STS | IAM, Workload Identity | Managed Identity |
| Attestation Storage | S3 + Object Lock | Cloud Storage + Retention | Blob + Immutable Storage |
| Observability | CloudWatch, X-Ray | Cloud Monitoring, Trace | Monitor, App Insights |

---

## Appendix B: Compliance Checklist

### GDPR Article 17 (Right to Erasure)

- [ ] Destruction certificates generated for all deletions
- [ ] Certificates include timestamp and method
- [ ] Audit trail retained for required period
- [ ] Crypto-shredding ensures data unrecoverable

### HIPAA §164.530 (Retention)

- [ ] PHI classified as RETENTION_BOUND minimum
- [ ] Retention periods configured per policy
- [ ] Destruction documented with certificates
- [ ] Access logged in chain of custody

### SOX §802 (Record Retention)

- [ ] Financial records classified appropriately
- [ ] 7-year retention for required documents
- [ ] Immutable audit trail
- [ ] Destruction certificates for expired records

---

*This document is released under the Apache 2.0 License.*
