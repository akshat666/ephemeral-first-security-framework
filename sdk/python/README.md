# EFSF Python SDK

The official Python SDK for the Ephemeral-First Security Framework.

## Installation

```bash
# Basic installation
pip install efsf

# With Redis backend support
pip install efsf[redis]

# With all optional dependencies
pip install efsf[all]
```

## Quick Start

```python
from efsf import EphemeralStore, DataClassification

# Create a store (defaults to in-memory for development)
store = EphemeralStore()

# Store sensitive data with automatic TTL and encryption
record = store.put(
    data={"user_id": "123", "ssn": "xxx-xx-xxxx"},
    ttl="30m",  # Destroyed in 30 minutes
    classification=DataClassification.PII,
)

print(f"Stored record: {record.id}")
print(f"Expires at: {record.expires_at}")

# Retrieve while valid
data = store.get(record.id)
print(f"Retrieved: {data}")

# Check remaining time
remaining = store.ttl(record.id)
print(f"Time remaining: {remaining}")

# Manually destroy early
certificate = store.destroy(record.id)
print(f"Destruction certificate: {certificate.certificate_id}")
```

## Using Redis Backend

```python
from efsf import EphemeralStore

store = EphemeralStore(
    backend="redis://localhost:6379/0",
    default_ttl="1h",
    attestation=True,
)

# Redis provides native TTL enforcement
record = store.put({"session": "data"}, ttl="15m")
```

## Sealed Execution

```python
from efsf import sealed

@sealed(attestation=True)
def process_payment(card_number: str, amount: float) -> str:
    """
    All local variables are destroyed when this function returns.
    A destruction certificate is automatically generated.
    """
    # Process payment...
    return f"payment_id_{hash(card_number) % 10000}"

result = process_payment("4111-1111-1111-1111", 99.99)
# card_number is now destroyed from memory
```

## Data Classifications

| Classification | Default TTL | Max TTL | Use Case |
|---------------|-------------|---------|----------|
| TRANSIENT | 1 hour | 24 hours | Session tokens, OTPs |
| SHORT_LIVED | 1 day | 7 days | Shopping carts, temp files |
| RETENTION_BOUND | 90 days | 7 years | Invoices, audit logs |
| PERSISTENT | None | None | Legal holds (requires justification) |

## Destruction Certificates

Every destroyed record can have a cryptographically signed certificate:

```python
from efsf import EphemeralStore

store = EphemeralStore(attestation=True)
record = store.put({"sensitive": "data"}, ttl="1m")

# Wait for expiration or destroy manually
certificate = store.destroy(record.id)

# Certificate contains:
print(certificate.to_json())
# {
#   "certificate_id": "uuid",
#   "resource": {"type": "ephemeral_data", "id": "record-id", ...},
#   "destruction": {"method": "crypto_shred", "timestamp": "...", ...},
#   "chain_of_custody": {...},
#   "signature": "base64-signature"
# }
```

## Development

```bash
# Clone the repo
git clone https://github.com/efsf/efsf.git
cd efsf/sdk/python

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with Redis (requires running Redis)
pytest --redis-url redis://localhost:6379

# Type checking
mypy efsf/

# Formatting
black efsf/ tests/
```

## License

Apache 2.0
