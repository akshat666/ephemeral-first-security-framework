"""
EFSF Ephemeral Store

The primary interface for storing and retrieving ephemeral data
with automatic TTL enforcement and crypto-shredding.
"""

import json
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any, Optional, Union
from urllib.parse import urlparse

from efsf.certificate import (
    AttestationAuthority,
    ChainOfCustody,
    DestructionCertificate,
    DestructionMethod,
)
from efsf.crypto import CryptoProvider, EncryptedPayload
from efsf.exceptions import (
    BackendError,
    RecordExpiredError,
    RecordNotFoundError,
    ValidationError,
)
from efsf.record import DataClassification, EphemeralRecord, parse_ttl


class StorageBackend(ABC):
    """Abstract base class for storage backends."""

    @abstractmethod
    def set(self, key: str, value: str, ttl_seconds: int) -> bool:
        """Store a value with TTL."""
        pass

    @abstractmethod
    def get(self, key: str) -> Optional[str]:
        """Retrieve a value."""
        pass

    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete a value."""
        pass

    @abstractmethod
    def exists(self, key: str) -> bool:
        """Check if a key exists."""
        pass

    @abstractmethod
    def ttl(self, key: str) -> Optional[int]:
        """Get remaining TTL in seconds."""
        pass

    def close(self) -> None:
        """Close the backend connection."""
        pass


class MemoryBackend(StorageBackend):
    """
    In-memory storage backend for testing and development.

    Note: This does not provide TTL enforcement automatically.
    Records are checked for expiration on access.
    """

    def __init__(self) -> None:
        self._data: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def set(self, key: str, value: str, ttl_seconds: int) -> bool:
        with self._lock:
            self._data[key] = {
                "value": value,
                "expires_at": datetime.utcnow() + timedelta(seconds=ttl_seconds),
            }
        return True

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            if datetime.utcnow() >= entry["expires_at"]:
                del self._data[key]
                return None
            result: Optional[str] = entry["value"]
            return result

    def delete(self, key: str) -> bool:
        with self._lock:
            if key in self._data:
                del self._data[key]
                return True
            return False

    def exists(self, key: str) -> bool:
        return self.get(key) is not None

    def ttl(self, key: str) -> Optional[int]:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            remaining = (entry["expires_at"] - datetime.utcnow()).total_seconds()
            return max(0, int(remaining))

    def close(self) -> None:
        with self._lock:
            self._data.clear()


class RedisBackend(StorageBackend):
    """
    Redis storage backend with native TTL support.

    Requires the `redis` package: pip install redis
    """

    def __init__(self, url: str = "redis://localhost:6379", **kwargs: Any) -> None:
        try:
            import redis
        except ImportError:
            raise BackendError(
                "redis", "redis package not installed. Install with: pip install redis"
            )

        self._client = redis.from_url(url, **kwargs)
        self._prefix = "efsf:"

    def _key(self, key: str) -> str:
        return f"{self._prefix}{key}"

    def set(self, key: str, value: str, ttl_seconds: int) -> bool:
        try:
            return bool(self._client.setex(self._key(key), ttl_seconds, value))
        except Exception as e:
            raise BackendError("redis", f"Failed to set: {e}")

    def get(self, key: str) -> Optional[str]:
        try:
            value = self._client.get(self._key(key))
            return value.decode("utf-8") if value else None
        except Exception as e:
            raise BackendError("redis", f"Failed to get: {e}")

    def delete(self, key: str) -> bool:
        try:
            return bool(self._client.delete(self._key(key)) > 0)
        except Exception as e:
            raise BackendError("redis", f"Failed to delete: {e}")

    def exists(self, key: str) -> bool:
        try:
            return bool(self._client.exists(self._key(key)) > 0)
        except Exception as e:
            raise BackendError("redis", f"Failed to check exists: {e}")

    def ttl(self, key: str) -> Optional[int]:
        try:
            ttl = self._client.ttl(self._key(key))
            return ttl if ttl > 0 else None
        except Exception as e:
            raise BackendError("redis", f"Failed to get TTL: {e}")

    def close(self) -> None:
        self._client.close()


def create_backend(backend_url: str) -> StorageBackend:
    """
    Factory function to create a storage backend from URL.

    Supported formats:
        - memory:// -> MemoryBackend
        - redis://host:port/db -> RedisBackend
    """
    parsed = urlparse(backend_url)

    if parsed.scheme == "memory" or backend_url == "memory":
        return MemoryBackend()
    elif parsed.scheme == "redis":
        return RedisBackend(backend_url)
    else:
        raise ValidationError("backend", f"Unsupported backend scheme: {parsed.scheme}")


class EphemeralStore:
    """
    The primary interface for ephemeral data storage.

    Provides:
    - Encrypted storage with per-record keys
    - Automatic TTL enforcement
    - Crypto-shredding on expiration
    - Destruction certificates for compliance

    Example:
        store = EphemeralStore(backend="redis://localhost:6379")

        # Store data with 30-minute TTL
        record = store.put(
            data={"user_id": "123", "session_token": "abc"},
            ttl="30m",
            classification="PII"
        )

        # Retrieve while valid
        data = store.get(record.id)

        # Manually destroy (or wait for TTL)
        certificate = store.destroy(record.id)
    """

    def __init__(
        self,
        backend: Union[str, StorageBackend] = "memory://",
        default_ttl: Union[str, timedelta] = "1h",
        attestation: bool = True,
        crypto_provider: Optional[CryptoProvider] = None,
        attestation_authority: Optional[AttestationAuthority] = None,
    ):
        """
        Initialize an ephemeral store.

        Args:
            backend: Storage backend URL or instance
            default_ttl: Default TTL for records without explicit TTL
            attestation: Whether to generate destruction certificates
            crypto_provider: Custom crypto provider (uses default if not specified)
            attestation_authority: Custom attestation authority
        """
        # Initialize backend
        if isinstance(backend, str):
            self._backend = create_backend(backend)
        else:
            self._backend = backend

        # Parse default TTL
        if isinstance(default_ttl, str):
            self._default_ttl = parse_ttl(default_ttl)
        else:
            self._default_ttl = default_ttl

        # Initialize crypto
        self._crypto = crypto_provider or CryptoProvider()

        # Initialize attestation
        self._attestation_enabled = attestation
        self._authority: Optional[AttestationAuthority]
        if attestation:
            self._authority = attestation_authority or AttestationAuthority()
        else:
            self._authority = None

        # Track records and their metadata
        self._records: dict[str, EphemeralRecord] = {}
        self._custody: dict[str, ChainOfCustody] = {}
        self._certificates: dict[str, DestructionCertificate] = {}
        self._lock = threading.Lock()

    def put(
        self,
        data: dict[str, Any],
        ttl: Optional[Union[str, timedelta]] = None,
        classification: Union[str, DataClassification] = DataClassification.TRANSIENT,
        metadata: Optional[dict[str, Any]] = None,
    ) -> EphemeralRecord:
        """
        Store data with automatic encryption and TTL.

        Args:
            data: Dictionary data to store
            ttl: Time-to-live (uses default if not specified)
            classification: Data classification level
            metadata: Additional metadata

        Returns:
            EphemeralRecord with record ID and metadata
        """
        # Parse classification
        if isinstance(classification, str):
            classification = DataClassification(classification)

        # Parse TTL
        if ttl is None:
            effective_ttl = self._default_ttl
        elif isinstance(ttl, str):
            effective_ttl = parse_ttl(ttl)
        else:
            effective_ttl = ttl

        # Create record
        record = EphemeralRecord.create(
            classification=classification,
            ttl=effective_ttl,
            metadata=metadata,
        )

        # Generate DEK with same TTL as data
        dek = self._crypto.generate_dek(effective_ttl)
        record.key_id = dek.key_id

        # Encrypt data
        encrypted = self._crypto.encrypt_json(data, dek)

        # Create storage payload
        storage_payload = {
            "record": record.to_dict(),
            "encrypted": encrypted.to_dict(),
        }

        # Store in backend
        ttl_seconds = int(effective_ttl.total_seconds())
        self._backend.set(
            record.id,
            json.dumps(storage_payload),
            ttl_seconds,
        )

        # Track record and custody
        with self._lock:
            self._records[record.id] = record

            if self._attestation_enabled:
                custody = ChainOfCustody(
                    created_at=record.created_at,
                    created_by="ephemeral_store",
                )
                custody.add_access("ephemeral_store", "create")
                self._custody[record.id] = custody

        return record

    def get(self, record_id: str) -> dict[str, Any]:
        """
        Retrieve data by record ID.

        Args:
            record_id: The record ID returned from put()

        Returns:
            The original data dictionary

        Raises:
            RecordNotFoundError: If record doesn't exist
            RecordExpiredError: If record has expired
        """
        # Get from backend
        raw = self._backend.get(record_id)

        if raw is None:
            # Check if we have a destruction certificate
            with self._lock:
                if record_id in self._certificates:
                    raise RecordExpiredError(record_id)
            raise RecordNotFoundError(record_id)

        # Parse storage payload
        storage_payload = json.loads(raw)
        record = EphemeralRecord.from_dict(storage_payload["record"])
        encrypted = EncryptedPayload.from_dict(storage_payload["encrypted"])

        # Check expiration
        if record.is_expired:
            self._handle_expiration(record_id)
            raise RecordExpiredError(record_id, record.expires_at.isoformat())

        # Decrypt data
        data = self._crypto.decrypt_json(encrypted)

        # Update access count and custody
        with self._lock:
            if record_id in self._records:
                self._records[record_id].access_count += 1

            if record_id in self._custody:
                self._custody[record_id].add_access("ephemeral_store", "read")

        return data

    def exists(self, record_id: str) -> bool:
        """Check if a record exists and is not expired."""
        return self._backend.exists(record_id)

    def ttl(self, record_id: str) -> Optional[timedelta]:
        """Get remaining TTL for a record."""
        seconds = self._backend.ttl(record_id)
        if seconds is None:
            return None
        return timedelta(seconds=seconds)

    def destroy(self, record_id: str) -> Optional[DestructionCertificate]:
        """
        Manually destroy a record immediately.

        This performs crypto-shredding by destroying the encryption key,
        making the data permanently unrecoverable.

        Args:
            record_id: The record ID to destroy

        Returns:
            DestructionCertificate if attestation is enabled, else None
        """
        return self._handle_expiration(record_id, method=DestructionMethod.MANUAL)

    def _handle_expiration(
        self,
        record_id: str,
        method: DestructionMethod = DestructionMethod.CRYPTO_SHRED,
    ) -> Optional[DestructionCertificate]:
        """Handle record expiration/destruction."""
        with self._lock:
            record = self._records.get(record_id)
            custody = self._custody.get(record_id)

        # Delete from backend
        self._backend.delete(record_id)

        # Destroy encryption key (crypto-shredding)
        if record and record.key_id:
            self._crypto.destroy_dek(record.key_id)

        # Generate destruction certificate
        certificate = None
        if self._attestation_enabled and self._authority and record:
            if custody:
                custody.add_access("ephemeral_store", "destroy")

            certificate = self._authority.issue_certificate(
                resource_type="ephemeral_data",
                resource_id=record_id,
                classification=record.classification.value,
                destruction_method=method,
                chain_of_custody=custody,
                metadata={
                    "ttl_seconds": record.ttl.total_seconds(),
                    "access_count": record.access_count,
                    **record.metadata,
                },
            )

            with self._lock:
                self._certificates[record_id] = certificate

        # Clean up tracking
        with self._lock:
            self._records.pop(record_id, None)
            self._custody.pop(record_id, None)

        return certificate

    def get_destruction_certificate(
        self,
        record_id: str,
    ) -> Optional[DestructionCertificate]:
        """
        Get the destruction certificate for a destroyed record.

        Args:
            record_id: The record ID

        Returns:
            DestructionCertificate if available, else None
        """
        with self._lock:
            return self._certificates.get(record_id)

    def list_certificates(
        self,
        since: Optional[datetime] = None,
    ) -> list[DestructionCertificate]:
        """List all destruction certificates."""
        with self._lock:
            certs = list(self._certificates.values())

        if since:
            certs = [c for c in certs if c.destruction_timestamp >= since]

        return sorted(certs, key=lambda c: c.destruction_timestamp, reverse=True)

    def stats(self) -> dict[str, Any]:
        """Get store statistics."""
        with self._lock:
            return {
                "active_records": len(self._records),
                "certificates_issued": len(self._certificates),
                "attestation_enabled": self._attestation_enabled,
            }

    def close(self) -> None:
        """Close the store and clean up resources."""
        self._backend.close()

    def __enter__(self) -> "EphemeralStore":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
