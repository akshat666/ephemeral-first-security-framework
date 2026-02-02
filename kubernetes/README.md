# EFSF Kubernetes Operator

> **Status**: Planned for future development

This directory will contain the EFSF Kubernetes Operator, which will provide:

- Custom Resource Definitions (CRDs) for ephemeral data policies
- Automatic TTL enforcement at the cluster level
- Integration with Kubernetes Secrets for ephemeral credentials
- Destruction certificate generation for compliance

## Coming Soon

The following components are designed in the [architecture](../docs/ARCHITECTURE.md) but not yet implemented:

### EFSF Operator
Manages `EphemeralStore` and `SealedWorkload` Custom Resource Definitions, enabling declarative configuration of ephemeral data stores and sealed execution contexts at the cluster level.

### Sidecar Injector
Automatically injects the ephemeral SDK as a sidecar container into pods at scheduling time via a mutating admission webhook, removing the need for application teams to bundle the SDK into their own container images.

### Admission Controller
Validates ephemeral policies on pod creation, ensuring workloads comply with data classification and TTL rules before they are scheduled.

### SPIRE Integration
Extends SPIRE for ephemeral workload identity, providing cryptographic attestation that ties ephemeral data lifecycle to verified workload identities.

### Custom Resource Definitions

- **`EphemeralStore`** — Configures ephemeral data backends (e.g., Redis) with TTL, destruction policy, key provider, and attestation settings
- **`SealedWorkload`** — Defines sealed execution contexts with isolation level (Nitro Enclave, gVisor, Kata, SGX), resource limits, and attestation reporting
- **`EphemeralPolicy`** — Defines data classification and TTL rules
- **`EphemeralSecret`** — Manages secrets with automatic expiration

### Additional Planned Features

- Webhook for enforcing ephemeral data policies
- Integration with external secret managers (Vault, AWS Secrets Manager)

## Contributing

This is a **medium-priority** area where the project is actively seeking contributors. See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to get involved.
