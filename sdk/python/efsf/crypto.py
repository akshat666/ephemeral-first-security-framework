"""
EFSF Cryptographic Operations

Provides encryption, decryption, and key management for ephemeral data.
Uses AES-256-GCM for authenticated encryption.
"""

import base64
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional

# Use cryptography library if available, fall back to basic implementation
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

from efsf.exceptions import CryptoError


@dataclass
class EncryptedPayload:
    """
    Container for encrypted data with associated metadata.

    Attributes:
        ciphertext: The encrypted data (base64 encoded)
        nonce: The nonce/IV used for encryption (base64 encoded)
        tag: The authentication tag (included in ciphertext for GCM)
        key_id: Identifier for the encryption key
        algorithm: The encryption algorithm used
    """

    ciphertext: str
    nonce: str
    key_id: str
    algorithm: str = "AES-256-GCM"

    def to_dict(self) -> dict:
        return {
            "ciphertext": self.ciphertext,
            "nonce": self.nonce,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EncryptedPayload":
        return cls(
            ciphertext=data["ciphertext"],
            nonce=data["nonce"],
            key_id=data["key_id"],
            algorithm=data.get("algorithm", "AES-256-GCM"),
        )


@dataclass
class DataEncryptionKey:
    """
    A data encryption key (DEK) with lifecycle metadata.

    The DEK encrypts the actual data. It is itself encrypted by
    a key encryption key (KEK) and has a TTL that must be <=
    the data it protects.
    """

    key_id: str
    key_material: bytes  # 32 bytes for AES-256
    created_at: datetime
    expires_at: datetime
    destroyed: bool = False
    destroyed_at: Optional[datetime] = None

    @classmethod
    def generate(cls, ttl: timedelta, key_id: Optional[str] = None) -> "DataEncryptionKey":
        """Generate a new random DEK."""
        now = datetime.utcnow()
        return cls(
            key_id=key_id or secrets.token_hex(16),
            key_material=secrets.token_bytes(32),  # 256 bits
            created_at=now,
            expires_at=now + ttl,
        )

    def destroy(self) -> None:
        """
        Securely destroy the key material.

        Note: In Python, we can't guarantee memory is zeroed due to
        garbage collection and potential copies. For true security,
        use a hardware security module (HSM) or TEE.
        """
        # Overwrite with random data (best effort)
        random_overwrite = secrets.token_bytes(len(self.key_material))
        # Python strings are immutable, so we can't truly zero the original
        # This is a limitation of software-only key management
        self.key_material = random_overwrite
        self.key_material = b"\x00" * 32
        self.destroyed = True
        self.destroyed_at = datetime.utcnow()

    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() >= self.expires_at or self.destroyed


class CryptoProvider:
    """
    Cryptographic operations provider for EFSF.

    Handles encryption, decryption, and key management with
    support for crypto-shredding (destroying keys to make data
    permanently unrecoverable).
    """

    def __init__(self, master_key: Optional[bytes] = None):
        """
        Initialize the crypto provider.

        Args:
            master_key: Optional master key for key derivation.
                       If not provided, a random key is generated.
                       In production, this should come from a KMS.
        """
        if not HAS_CRYPTOGRAPHY:
            raise CryptoError(
                "initialization",
                "cryptography library not installed. " "Install with: pip install cryptography",
            )

        self._master_key = master_key or secrets.token_bytes(32)
        self._keys: dict[str, DataEncryptionKey] = {}

    def generate_dek(self, ttl: timedelta) -> DataEncryptionKey:
        """
        Generate a new data encryption key.

        Args:
            ttl: Time-to-live for the key

        Returns:
            New DataEncryptionKey
        """
        dek = DataEncryptionKey.generate(ttl)
        self._keys[dek.key_id] = dek
        return dek

    def get_dek(self, key_id: str) -> Optional[DataEncryptionKey]:
        """
        Retrieve a DEK by ID.

        Returns None if the key doesn't exist or has been destroyed.
        """
        dek = self._keys.get(key_id)
        if dek and (dek.destroyed or dek.is_expired):
            return None
        return dek

    def destroy_dek(self, key_id: str) -> bool:
        """
        Destroy a DEK (crypto-shredding).

        After destruction, any data encrypted with this key
        is permanently unrecoverable.

        Returns:
            True if key was destroyed, False if not found
        """
        dek = self._keys.get(key_id)
        if dek:
            dek.destroy()
            return True
        return False

    def encrypt(
        self,
        plaintext: bytes,
        dek: DataEncryptionKey,
        associated_data: Optional[bytes] = None,
    ) -> EncryptedPayload:
        """
        Encrypt data using AES-256-GCM.

        Args:
            plaintext: Data to encrypt
            dek: Data encryption key to use
            associated_data: Optional additional authenticated data

        Returns:
            EncryptedPayload containing ciphertext and metadata

        Raises:
            CryptoError: If encryption fails or key is invalid
        """
        if dek.destroyed or dek.is_expired:
            raise CryptoError("encrypt", "Key is destroyed or expired")

        try:
            aesgcm = AESGCM(dek.key_material)
            nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM

            ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

            return EncryptedPayload(
                ciphertext=base64.b64encode(ciphertext).decode("utf-8"),
                nonce=base64.b64encode(nonce).decode("utf-8"),
                key_id=dek.key_id,
            )
        except Exception as e:
            raise CryptoError("encrypt", str(e))

    def decrypt(
        self,
        payload: EncryptedPayload,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Decrypt data using AES-256-GCM.

        Args:
            payload: The encrypted payload
            associated_data: Optional additional authenticated data
                            (must match what was used during encryption)

        Returns:
            Decrypted plaintext

        Raises:
            CryptoError: If decryption fails or key is unavailable
        """
        dek = self.get_dek(payload.key_id)
        if dek is None:
            raise CryptoError(
                "decrypt", f"Key {payload.key_id} not found or destroyed (data is unrecoverable)"
            )

        try:
            aesgcm = AESGCM(dek.key_material)
            nonce = base64.b64decode(payload.nonce)
            ciphertext = base64.b64decode(payload.ciphertext)

            plaintext: bytes = aesgcm.decrypt(nonce, ciphertext, associated_data)
            return plaintext
        except Exception as e:
            raise CryptoError("decrypt", str(e))

    def encrypt_json(
        self,
        data: dict,
        dek: DataEncryptionKey,
    ) -> EncryptedPayload:
        """Convenience method to encrypt a JSON-serializable dict."""
        plaintext = json.dumps(data).encode("utf-8")
        return self.encrypt(plaintext, dek)

    def decrypt_json(self, payload: EncryptedPayload) -> dict[str, Any]:
        """Convenience method to decrypt to a JSON dict."""
        plaintext = self.decrypt(payload)
        result: dict[str, Any] = json.loads(plaintext.decode("utf-8"))
        return result

    def derive_key(
        self,
        context: bytes,
        length: int = 32,
    ) -> bytes:
        """
        Derive a key from the master key using HKDF.

        Args:
            context: Context/info for key derivation
            length: Desired key length in bytes

        Returns:
            Derived key material
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=context,
        )
        return bytes(hkdf.derive(self._master_key))


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time to prevent timing attacks.
    """
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0
