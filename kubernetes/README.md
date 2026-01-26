# EFSF Kubernetes Operator

> **Status**: Planned for future development

This directory will contain the EFSF Kubernetes Operator, which will provide:

- Custom Resource Definitions (CRDs) for ephemeral data policies
- Automatic TTL enforcement at the cluster level
- Integration with Kubernetes Secrets for ephemeral credentials
- Destruction certificate generation for compliance

## Planned Features

- `EphemeralPolicy` CRD for defining data classification and TTL rules
- `EphemeralSecret` CRD for secrets with automatic expiration
- Webhook for enforcing ephemeral data policies
- Integration with external secret managers (Vault, AWS Secrets Manager)

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to contribute to this component.
