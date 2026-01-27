"""
EFSF Exceptions

All custom exceptions raised by the EFSF library.
"""

from typing import Optional


class EFSFError(Exception):
    """Base exception for all EFSF errors."""

    pass


class RecordNotFoundError(EFSFError):
    """Raised when attempting to access a record that doesn't exist."""

    def __init__(self, record_id: str, message: Optional[str] = None):
        self.record_id = record_id
        self.message = message or f"Record not found: {record_id}"
        super().__init__(self.message)


class RecordExpiredError(EFSFError):
    """Raised when attempting to access a record that has expired."""

    def __init__(self, record_id: str, expired_at: Optional[str] = None):
        self.record_id = record_id
        self.expired_at = expired_at
        message = f"Record expired: {record_id}"
        if expired_at:
            message += f" (expired at {expired_at})"
        super().__init__(message)


class CryptoError(EFSFError):
    """Raised when a cryptographic operation fails."""

    def __init__(self, operation: str, message: Optional[str] = None):
        self.operation = operation
        self.message = message or f"Cryptographic operation failed: {operation}"
        super().__init__(self.message)


class AttestationError(EFSFError):
    """Raised when attestation/certificate generation fails."""

    def __init__(self, message: Optional[str] = None):
        self.message = message or "Attestation failed"
        super().__init__(self.message)


class BackendError(EFSFError):
    """Raised when the storage backend encounters an error."""

    def __init__(self, backend: str, message: Optional[str] = None):
        self.backend = backend
        self.message = message or f"Backend error: {backend}"
        super().__init__(self.message)


class ValidationError(EFSFError):
    """Raised when input validation fails."""

    def __init__(self, field: str, message: Optional[str] = None):
        self.field = field
        self.message = message or f"Validation error: {field}"
        super().__init__(self.message)


class TTLViolationError(EFSFError):
    """Raised when a TTL policy is violated."""

    def __init__(self, record_id: str, expected_ttl: str, actual_ttl: Optional[str] = None):
        self.record_id = record_id
        self.expected_ttl = expected_ttl
        self.actual_ttl = actual_ttl
        message = f"TTL violation for record {record_id}: expected {expected_ttl}"
        if actual_ttl:
            message += f", got {actual_ttl}"
        super().__init__(message)
