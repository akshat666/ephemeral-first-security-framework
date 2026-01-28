"""
Tests for EFSF EphemeralStore
"""

import time
from datetime import timedelta

import pytest

from efsf import (
    DataClassification,
    EphemeralRecord,
    EphemeralStore,
    RecordExpiredError,
    RecordNotFoundError,
)
from efsf.record import parse_ttl


class TestParsesTTL:
    """Tests for TTL string parsing."""

    def test_parse_seconds(self):
        assert parse_ttl("30s") == timedelta(seconds=30)
        assert parse_ttl("30sec") == timedelta(seconds=30)
        assert parse_ttl("30seconds") == timedelta(seconds=30)

    def test_parse_minutes(self):
        assert parse_ttl("5m") == timedelta(minutes=5)
        assert parse_ttl("5min") == timedelta(minutes=5)
        assert parse_ttl("5minutes") == timedelta(minutes=5)

    def test_parse_hours(self):
        assert parse_ttl("2h") == timedelta(hours=2)
        assert parse_ttl("2hr") == timedelta(hours=2)
        assert parse_ttl("2hours") == timedelta(hours=2)

    def test_parse_days(self):
        assert parse_ttl("7d") == timedelta(days=7)
        assert parse_ttl("7days") == timedelta(days=7)

    def test_invalid_ttl(self):
        with pytest.raises(ValueError):
            parse_ttl("invalid")

        with pytest.raises(ValueError):
            parse_ttl("10x")


class TestDataClassification:
    """Tests for data classification."""

    def test_default_ttl(self):
        assert DataClassification.TRANSIENT.default_ttl == timedelta(hours=1)
        assert DataClassification.SHORT_LIVED.default_ttl == timedelta(days=1)
        assert DataClassification.RETENTION_BOUND.default_ttl == timedelta(days=90)
        assert DataClassification.PERSISTENT.default_ttl is None

    def test_max_ttl(self):
        assert DataClassification.TRANSIENT.max_ttl == timedelta(hours=24)
        assert DataClassification.SHORT_LIVED.max_ttl == timedelta(days=7)


class TestEphemeralRecord:
    """Tests for EphemeralRecord."""

    def test_create_record(self):
        record = EphemeralRecord.create(
            classification=DataClassification.TRANSIENT,
            ttl=timedelta(minutes=30),
        )

        assert record.id is not None
        assert record.classification == DataClassification.TRANSIENT
        assert record.ttl == timedelta(minutes=30)
        assert record.encrypted is True
        assert record.key_id is not None

    def test_default_ttl(self):
        record = EphemeralRecord.create(
            classification=DataClassification.TRANSIENT,
        )

        assert record.ttl == timedelta(hours=1)  # Default for TRANSIENT

    def test_ttl_exceeds_max(self):
        with pytest.raises(ValueError, match="exceeds maximum"):
            EphemeralRecord.create(
                classification=DataClassification.TRANSIENT,
                ttl=timedelta(days=30),  # Exceeds 24h max
            )

    def test_serialization(self):
        record = EphemeralRecord.create(
            classification=DataClassification.SHORT_LIVED,
            ttl=timedelta(hours=2),
            metadata={"key": "value"},
        )

        data = record.to_dict()
        restored = EphemeralRecord.from_dict(data)

        assert restored.id == record.id
        assert restored.classification == record.classification
        assert restored.metadata == record.metadata


class TestEphemeralStore:
    """Tests for EphemeralStore."""

    def test_put_and_get(self):
        store = EphemeralStore(backend="memory://")

        data = {"user_id": "123", "session": "abc"}
        record = store.put(data, ttl="30m")

        assert record.id is not None

        retrieved = store.get(record.id)
        assert retrieved == data

    def test_put_with_classification(self):
        store = EphemeralStore(backend="memory://")

        record = store.put(
            {"data": "value"},
            ttl="1h",
            classification=DataClassification.SHORT_LIVED,
        )

        assert record.classification == DataClassification.SHORT_LIVED

    def test_put_with_string_classification(self):
        store = EphemeralStore(backend="memory://")

        record = store.put(
            {"data": "value"},
            ttl="1h",
            classification="TRANSIENT",
        )

        assert record.classification == DataClassification.TRANSIENT

    def test_record_not_found(self):
        store = EphemeralStore(backend="memory://")

        with pytest.raises(RecordNotFoundError):
            store.get("nonexistent-id")

    def test_destroy(self):
        store = EphemeralStore(backend="memory://", attestation=True)

        record = store.put({"secret": "data"}, ttl="1h")

        # Record exists
        assert store.exists(record.id)

        # Destroy it
        certificate = store.destroy(record.id)

        # Record no longer exists
        assert not store.exists(record.id)

        # Certificate was generated
        assert certificate is not None
        assert certificate.resource.resource_id == record.id
        assert certificate.signature is not None

    def test_ttl_remaining(self):
        store = EphemeralStore(backend="memory://")

        record = store.put({"data": "value"}, ttl="1h")

        remaining = store.ttl(record.id)
        assert remaining is not None
        assert remaining <= timedelta(hours=1)
        assert remaining > timedelta(minutes=59)

    def test_destruction_certificate_retrieval(self):
        store = EphemeralStore(backend="memory://", attestation=True)

        record = store.put({"data": "value"}, ttl="1h")
        store.destroy(record.id)

        cert = store.get_destruction_certificate(record.id)
        assert cert is not None
        assert cert.resource.resource_id == record.id

    def test_stats(self):
        store = EphemeralStore(backend="memory://", attestation=True)

        store.put({"data": "1"}, ttl="1h")
        store.put({"data": "2"}, ttl="1h")

        stats = store.stats()
        assert stats["active_records"] == 2
        assert stats["attestation_enabled"] is True

    def test_context_manager(self):
        with EphemeralStore(backend="memory://") as store:
            record = store.put({"data": "value"}, ttl="1h")
            assert store.exists(record.id)


class TestCryptoShredding:
    """Tests for crypto-shredding functionality."""

    def test_key_destroyed_on_destroy(self):
        store = EphemeralStore(backend="memory://")

        record = store.put({"secret": "data"}, ttl="1h")

        # Get the key ID
        key_id = record.key_id

        # Key exists before destroy
        assert store._crypto.get_dek(key_id) is not None

        # Destroy the record
        store.destroy(record.id)

        # Key no longer available
        assert store._crypto.get_dek(key_id) is None

    def test_data_unrecoverable_after_destroy(self):
        store = EphemeralStore(backend="memory://")

        record = store.put({"secret": "data"}, ttl="1h")
        store.destroy(record.id)

        # Even if we had the encrypted data, we can't decrypt it
        # because the key is destroyed
        with pytest.raises(RecordExpiredError):
            store.get(record.id)


class TestAttestation:
    """Tests for attestation and certificates."""

    def test_certificate_signature(self):
        store = EphemeralStore(backend="memory://", attestation=True)

        record = store.put({"data": "value"}, ttl="1h")
        cert = store.destroy(record.id)

        # Certificate has all required fields
        assert cert.certificate_id is not None
        assert cert.version == "1.0"
        assert cert.resource.resource_type == "ephemeral_data"
        assert cert.destruction_method.value == "manual"
        assert cert.signature is not None

        # Signature is valid
        assert store._authority.verify_certificate(cert)

    def test_chain_of_custody(self):
        store = EphemeralStore(backend="memory://", attestation=True)

        record = store.put({"data": "value"}, ttl="1h")

        # Access the record a few times
        store.get(record.id)
        store.get(record.id)

        cert = store.destroy(record.id)

        # Chain of custody tracks accesses
        assert cert.chain_of_custody is not None
        # create + 2 reads + destroy = at least 4 events
        assert len(cert.chain_of_custody.access_log) >= 3

    def test_list_certificates(self):
        store = EphemeralStore(backend="memory://", attestation=True)

        # Create and destroy multiple records
        for i in range(3):
            record = store.put({"data": i}, ttl="1h")
            store.destroy(record.id)

        certs = store.list_certificates()
        assert len(certs) == 3


# Optional: Redis integration tests
# These only run if Redis is available


@pytest.fixture
def redis_store():
    """Create a Redis-backed store if Redis is available."""
    try:
        import redis

        client = redis.Redis()
        client.ping()

        store = EphemeralStore(backend="redis://localhost:6379/15")
        yield store
        store.close()
    except Exception:
        pytest.skip("Redis not available")


class TestRedisBackend:
    """Tests for Redis backend (skipped if Redis unavailable)."""

    def test_put_and_get_redis(self, redis_store):
        data = {"user_id": "redis-test"}
        record = redis_store.put(data, ttl="1m")

        retrieved = redis_store.get(record.id)
        assert retrieved == data

    def test_ttl_enforcement_redis(self, redis_store):
        record = redis_store.put({"data": "expire"}, ttl="2s")

        # Should exist immediately
        assert redis_store.exists(record.id)

        # Wait for expiration
        time.sleep(3)

        # Should be gone
        assert not redis_store.exists(record.id)
