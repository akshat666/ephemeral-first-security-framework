"""
EFSF Record Types

Defines the EphemeralRecord and related data structures.
"""

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Optional


class DataClassification(Enum):
    """
    Data classification levels that determine default TTL policies.

    TRANSIENT: Seconds to hours (session tokens, OTPs)
    SHORT_LIVED: Hours to days (shopping carts, temp uploads)
    RETENTION_BOUND: Days to years (invoices, audit logs)
    PERSISTENT: Indefinite, requires explicit justification
    """

    TRANSIENT = "TRANSIENT"
    SHORT_LIVED = "SHORT_LIVED"
    RETENTION_BOUND = "RETENTION_BOUND"
    PERSISTENT = "PERSISTENT"

    @property
    def default_ttl(self) -> Optional[timedelta]:
        """Returns the default TTL for this classification."""
        defaults = {
            DataClassification.TRANSIENT: timedelta(hours=1),
            DataClassification.SHORT_LIVED: timedelta(days=1),
            DataClassification.RETENTION_BOUND: timedelta(days=90),
            DataClassification.PERSISTENT: None,  # No default TTL
        }
        return defaults[self]

    @property
    def max_ttl(self) -> Optional[timedelta]:
        """Returns the maximum allowed TTL for this classification."""
        maximums = {
            DataClassification.TRANSIENT: timedelta(hours=24),
            DataClassification.SHORT_LIVED: timedelta(days=7),
            DataClassification.RETENTION_BOUND: timedelta(days=365 * 7),  # 7 years
            DataClassification.PERSISTENT: None,  # No maximum
        }
        return maximums[self]


@dataclass
class EphemeralRecord:
    """
    Represents an ephemeral data record with lifecycle metadata.

    Attributes:
        id: Unique identifier for the record
        classification: Data classification level
        created_at: When the record was created
        expires_at: When the record will be destroyed
        ttl: Time-to-live duration
        encrypted: Whether the data is encrypted
        key_id: ID of the encryption key (for crypto-shredding)
        access_count: Number of times the record has been accessed
        metadata: Additional user-defined metadata
    """

    id: str
    classification: DataClassification
    created_at: datetime
    expires_at: datetime
    ttl: timedelta
    encrypted: bool = True
    key_id: Optional[str] = None
    access_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        classification: DataClassification = DataClassification.TRANSIENT,
        ttl: Optional[timedelta] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> "EphemeralRecord":
        """
        Factory method to create a new ephemeral record.

        Args:
            classification: Data classification level
            ttl: Time-to-live (uses classification default if not specified)
            metadata: Additional metadata

        Returns:
            New EphemeralRecord instance
        """
        now = datetime.utcnow()

        # Use provided TTL or fall back to classification default
        effective_ttl = ttl or classification.default_ttl
        if effective_ttl is None:
            raise ValueError(
                f"TTL required for {classification.value} classification " "(no default available)"
            )

        # Validate TTL against classification maximum
        max_ttl = classification.max_ttl
        if max_ttl and effective_ttl > max_ttl:
            raise ValueError(
                f"TTL {effective_ttl} exceeds maximum {max_ttl} "
                f"for {classification.value} classification"
            )

        return cls(
            id=str(uuid.uuid4()),
            classification=classification,
            created_at=now,
            expires_at=now + effective_ttl,
            ttl=effective_ttl,
            key_id=str(uuid.uuid4()),  # Generate key ID for crypto-shredding
            metadata=metadata or {},
        )

    @property
    def is_expired(self) -> bool:
        """Check if the record has expired."""
        return datetime.utcnow() >= self.expires_at

    @property
    def time_remaining(self) -> timedelta:
        """Get the remaining time before expiration."""
        remaining = self.expires_at - datetime.utcnow()
        return max(remaining, timedelta(0))

    def to_dict(self) -> dict[str, Any]:
        """Serialize the record to a dictionary."""
        return {
            "id": self.id,
            "classification": self.classification.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "ttl_seconds": self.ttl.total_seconds(),
            "encrypted": self.encrypted,
            "key_id": self.key_id,
            "access_count": self.access_count,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EphemeralRecord":
        """Deserialize a record from a dictionary."""
        return cls(
            id=data["id"],
            classification=DataClassification(data["classification"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            ttl=timedelta(seconds=data["ttl_seconds"]),
            encrypted=data.get("encrypted", True),
            key_id=data.get("key_id"),
            access_count=data.get("access_count", 0),
            metadata=data.get("metadata", {}),
        )


def parse_ttl(ttl_string: str) -> timedelta:
    """
    Parse a human-readable TTL string into a timedelta.

    Supported formats:
        - "30s" or "30sec" or "30seconds" -> 30 seconds
        - "5m" or "5min" or "5minutes" -> 5 minutes
        - "2h" or "2hr" or "2hours" -> 2 hours
        - "7d" or "7days" -> 7 days

    Args:
        ttl_string: Human-readable TTL string

    Returns:
        Equivalent timedelta

    Raises:
        ValueError: If the string cannot be parsed
    """
    if isinstance(ttl_string, timedelta):
        return ttl_string

    pattern = r"^(\d+)\s*(s|sec|seconds?|m|min|minutes?|h|hr|hours?|d|days?)$"
    match = re.match(pattern, ttl_string.lower().strip())

    if not match:
        raise ValueError(f"Cannot parse TTL string: {ttl_string}")

    value = int(match.group(1))
    unit = match.group(2)

    if unit.startswith("s"):
        return timedelta(seconds=value)
    elif unit.startswith("m"):
        return timedelta(minutes=value)
    elif unit.startswith("h"):
        return timedelta(hours=value)
    elif unit.startswith("d"):
        return timedelta(days=value)
    else:
        raise ValueError(f"Unknown time unit: {unit}")
