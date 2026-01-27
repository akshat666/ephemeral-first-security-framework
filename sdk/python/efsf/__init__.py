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

from efsf.certificate import DestructionCertificate
from efsf.crypto import CryptoProvider
from efsf.exceptions import (
    AttestationError,
    CryptoError,
    EFSFError,
    RecordExpiredError,
    RecordNotFoundError,
)
from efsf.record import DataClassification, EphemeralRecord
from efsf.sealed import SealedExecution, sealed
from efsf.store import EphemeralStore

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
