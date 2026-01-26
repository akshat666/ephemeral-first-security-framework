"""
EFSF - Ephemeral-First Security Framework

A framework for building systems where data transience is a first-class
security primitive.

Example:
    >>> from efsf import EphemeralStore
    >>> store = EphemeralStore(backend="redis://localhost:6379")
    >>> record = store.put({"user": "alice"}, ttl="30m")
    >>> data = store.get(record.id)
    >>> # After 30 minutes, data is automatically destroyed
"""

from efsf.store import EphemeralStore
from efsf.record import EphemeralRecord, DataClassification
from efsf.certificate import DestructionCertificate
from efsf.sealed import sealed, SealedExecution
from efsf.crypto import CryptoProvider
from efsf.exceptions import (
    EFSFError,
    RecordNotFoundError,
    RecordExpiredError,
    CryptoError,
    AttestationError,
)

__version__ = "0.1.0"
__all__ = [
    # Core
    "EphemeralStore",
    "EphemeralRecord",
    "DataClassification",
    "DestructionCertificate",
    # Sealed Execution
    "sealed",
    "SealedExecution",
    # Crypto
    "CryptoProvider",
    # Exceptions
    "EFSFError",
    "RecordNotFoundError",
    "RecordExpiredError",
    "CryptoError",
    "AttestationError",
]
