"""
EFSF Destruction Certificates

Provides cryptographically signed proof of data destruction
for compliance and audit purposes.
"""

import base64
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

from efsf.exceptions import AttestationError


class DestructionMethod(Enum):
    """Methods used to destroy ephemeral data."""

    CRYPTO_SHRED = "crypto_shred"  # Key destroyed, data unrecoverable
    MEMORY_ZERO = "memory_zero"  # Memory overwritten with zeros
    SECURE_DELETE = "secure_delete"  # Multiple overwrites on storage
    TEE_EXIT = "tee_exit"  # TEE enclave terminated
    TTL_EXPIRE = "ttl_expire"  # Storage TTL triggered deletion
    MANUAL = "manual"  # Explicit deletion request


@dataclass
class ResourceInfo:
    """Information about the destroyed resource."""

    resource_type: str  # ephemeral_data, sealed_compute, credential, channel
    resource_id: str
    classification: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "type": self.resource_type,
            "id": self.resource_id,
            "classification": self.classification,
            "metadata": self.metadata,
        }


@dataclass
class ChainOfCustody:
    """Tracks the lifecycle of the resource from creation to destruction."""

    created_at: datetime
    created_by: Optional[str] = None
    access_log: list[dict[str, Any]] = field(default_factory=list)
    hash_chain: list[str] = field(default_factory=list)

    def add_access(self, accessor: str, action: str, timestamp: Optional[datetime] = None) -> None:
        """Record an access event."""
        ts = timestamp or datetime.utcnow()
        event = {
            "timestamp": ts.isoformat(),
            "accessor": accessor,
            "action": action,
        }
        self.access_log.append(event)

        # Extend hash chain
        event_hash = hashlib.sha256(json.dumps(event).encode()).hexdigest()
        if self.hash_chain:
            chained = hashlib.sha256((self.hash_chain[-1] + event_hash).encode()).hexdigest()
        else:
            chained = event_hash
        self.hash_chain.append(chained)

    def to_dict(self) -> dict:
        return {
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "access_count": len(self.access_log),
            "hash_chain": self.hash_chain[-5:] if self.hash_chain else [],  # Last 5 hashes
        }


@dataclass
class DestructionCertificate:
    """
    Cryptographically signed certificate attesting to data destruction.

    This certificate provides verifiable proof that:
    1. The specified resource existed
    2. It was destroyed using the specified method
    3. The destruction occurred at the specified time
    4. The certificate was issued by a trusted authority

    Attributes:
        certificate_id: Unique identifier for this certificate
        version: Certificate format version
        resource: Information about the destroyed resource
        destruction_method: How the resource was destroyed
        destruction_timestamp: When destruction occurred
        verified_by: ID of the attestation authority
        chain_of_custody: Lifecycle tracking information
        signature: Ed25519 signature over the certificate
    """

    certificate_id: str
    version: str
    resource: ResourceInfo
    destruction_method: DestructionMethod
    destruction_timestamp: datetime
    verified_by: str
    chain_of_custody: Optional[ChainOfCustody] = None
    signature: Optional[str] = None

    @classmethod
    def create(
        cls,
        resource: ResourceInfo,
        destruction_method: DestructionMethod,
        verified_by: str = "efsf-local-authority",
        chain_of_custody: Optional[ChainOfCustody] = None,
    ) -> "DestructionCertificate":
        """
        Create a new destruction certificate.

        Args:
            resource: Information about the destroyed resource
            destruction_method: How the resource was destroyed
            verified_by: ID of the attestation authority
            chain_of_custody: Optional lifecycle tracking

        Returns:
            New DestructionCertificate (unsigned)
        """
        return cls(
            certificate_id=str(uuid.uuid4()),
            version="1.0",
            resource=resource,
            destruction_method=destruction_method,
            destruction_timestamp=datetime.utcnow(),
            verified_by=verified_by,
            chain_of_custody=chain_of_custody,
        )

    def to_dict(self, include_signature: bool = True) -> dict[str, Any]:
        """Serialize certificate to dictionary."""
        data = {
            "version": self.version,
            "certificate_id": self.certificate_id,
            "resource": self.resource.to_dict(),
            "destruction": {
                "method": self.destruction_method.value,
                "timestamp": self.destruction_timestamp.isoformat(),
                "verified_by": self.verified_by,
            },
        }

        if self.chain_of_custody:
            data["chain_of_custody"] = self.chain_of_custody.to_dict()

        if include_signature and self.signature:
            data["signature"] = self.signature

        return data

    def to_json(self, indent: int = 2) -> str:
        """Serialize certificate to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def canonical_bytes(self) -> bytes:
        """
        Get canonical byte representation for signing.

        Uses sorted keys and no whitespace for deterministic output.
        """
        data = self.to_dict(include_signature=False)
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of the certificate."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


class AttestationAuthority:
    """
    Issues and verifies destruction certificates.

    In production, this would typically be backed by an HSM
    or cloud KMS for key protection.
    """

    def __init__(self, authority_id: str = "efsf-local-authority"):
        """
        Initialize the attestation authority.

        Args:
            authority_id: Unique identifier for this authority
        """
        if not HAS_CRYPTOGRAPHY:
            raise AttestationError(
                "cryptography library not installed. " "Install with: pip install cryptography"
            )

        self.authority_id = authority_id
        self._private_key = Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        self._issued_certificates: dict[str, DestructionCertificate] = {}

    @property
    def public_key_bytes(self) -> bytes:
        """Get the public key in raw bytes format."""
        return bytes(
            self._public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )

    @property
    def public_key_b64(self) -> str:
        """Get the public key as base64 string."""
        return base64.b64encode(self.public_key_bytes).decode("utf-8")

    def sign_certificate(self, certificate: DestructionCertificate) -> DestructionCertificate:
        """
        Sign a destruction certificate.

        Args:
            certificate: The certificate to sign

        Returns:
            The certificate with signature attached
        """
        message = certificate.canonical_bytes()
        signature = self._private_key.sign(message)
        certificate.signature = base64.b64encode(signature).decode("utf-8")
        certificate.verified_by = self.authority_id

        # Store for later retrieval
        self._issued_certificates[certificate.certificate_id] = certificate

        return certificate

    def verify_certificate(self, certificate: DestructionCertificate) -> bool:
        """
        Verify a certificate's signature.

        Args:
            certificate: The certificate to verify

        Returns:
            True if signature is valid

        Raises:
            AttestationError: If verification fails
        """
        if not certificate.signature:
            raise AttestationError("Certificate has no signature")

        try:
            message = certificate.canonical_bytes()
            signature = base64.b64decode(certificate.signature)
            self._public_key.verify(signature, message)
            return True
        except Exception as e:
            raise AttestationError(f"Signature verification failed: {e}")

    def issue_certificate(
        self,
        resource_type: str,
        resource_id: str,
        classification: str,
        destruction_method: DestructionMethod,
        chain_of_custody: Optional[ChainOfCustody] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> DestructionCertificate:
        """
        Issue a new signed destruction certificate.

        This is a convenience method that creates and signs a certificate.

        Args:
            resource_type: Type of resource (e.g., "ephemeral_data")
            resource_id: ID of the destroyed resource
            classification: Data classification
            destruction_method: How the resource was destroyed
            chain_of_custody: Optional lifecycle tracking
            metadata: Additional metadata

        Returns:
            Signed DestructionCertificate
        """
        resource = ResourceInfo(
            resource_type=resource_type,
            resource_id=resource_id,
            classification=classification,
            metadata=metadata or {},
        )

        certificate = DestructionCertificate.create(
            resource=resource,
            destruction_method=destruction_method,
            verified_by=self.authority_id,
            chain_of_custody=chain_of_custody,
        )

        return self.sign_certificate(certificate)

    def get_certificate(self, certificate_id: str) -> Optional[DestructionCertificate]:
        """Retrieve a certificate by ID."""
        return self._issued_certificates.get(certificate_id)

    def list_certificates(
        self,
        resource_id: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> list[DestructionCertificate]:
        """
        List issued certificates with optional filtering.

        Args:
            resource_id: Filter by resource ID
            since: Filter to certificates issued after this time

        Returns:
            List of matching certificates
        """
        certs = list(self._issued_certificates.values())

        if resource_id:
            certs = [c for c in certs if c.resource.resource_id == resource_id]

        if since:
            certs = [c for c in certs if c.destruction_timestamp >= since]

        return sorted(certs, key=lambda c: c.destruction_timestamp, reverse=True)
