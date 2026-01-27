"""
Tests for EFSF Sealed Execution
"""

import pytest

from efsf import SealedExecution, sealed
from efsf.certificate import DestructionMethod


class TestSealedDecorator:
    """Tests for the @sealed decorator."""

    def test_sealed_function_returns_value(self):
        @sealed()
        def add_numbers(a: int, b: int) -> int:
            return a + b

        result = add_numbers(5, 3)
        assert result == 8

    def test_sealed_with_attestation(self):
        @sealed(attestation=True)
        def process_sensitive(data: str) -> dict:
            return {"processed": True, "length": len(data)}

        result = process_sensitive("secret-data")

        assert result["processed"] is True
        assert result["length"] == 11
        # Certificate should be attached to dict results
        assert "_destruction_certificate" in result

    def test_sealed_function_exception(self):
        @sealed()
        def failing_function():
            raise ValueError("Test error")

        with pytest.raises(ValueError, match="Test error"):
            failing_function()


class TestSealedExecution:
    """Tests for the SealedExecution context manager."""

    def test_context_manager_basic(self):
        with SealedExecution() as ctx:
            assert ctx is not None
            assert ctx.execution_id is not None

    def test_context_manager_with_attestation(self):
        seal = SealedExecution(attestation=True)

        with seal as ctx:
            ctx.track(bytearray(b"secret"))
            # Do something with sensitive data

        # Certificate should be generated
        assert seal.certificate is not None
        assert seal.certificate.destruction_method == DestructionMethod.MEMORY_ZERO

    def test_tracked_object_cleanup(self):
        with SealedExecution() as ctx:
            data = ctx.track(bytearray(b"sensitive-data"))
            original_len = len(data)

        # After context exit, the bytearray should be zeroed
        # (best effort - Python limitations apply)
        assert len(data) == original_len
        # Content should be zeroed
        assert all(b == 0 for b in data)

    def test_cleanup_callback(self):
        cleanup_called = [False]

        def my_cleanup():
            cleanup_called[0] = True

        with SealedExecution() as ctx:
            ctx.on_cleanup(my_cleanup)

        assert cleanup_called[0] is True

    def test_certificate_includes_metadata(self):
        seal = SealedExecution(
            attestation=True,
            metadata={"custom_field": "custom_value"},
        )

        with seal:
            pass

        cert = seal.certificate
        assert cert is not None
        assert cert.resource.metadata.get("custom_field") == "custom_value"

    def test_certificate_records_error(self):
        seal = SealedExecution(attestation=True)

        try:
            with seal:
                raise RuntimeError("Test error")
        except RuntimeError:
            pass

        cert = seal.certificate
        assert cert is not None
        assert cert.resource.metadata.get("error") == "Test error"

    def test_multiple_tracked_objects(self):
        with SealedExecution() as ctx:
            data1 = ctx.track(bytearray(b"secret1"))
            data2 = ctx.track(bytearray(b"secret2"))
            data3 = ctx.track({"key": "value"})  # dict tracking

        # All bytearrays should be zeroed
        assert all(b == 0 for b in data1)
        assert all(b == 0 for b in data2)
        # Dict should be empty
        assert len(data3) == 0


class TestEphemeralScope:
    """Tests for ephemeral_scope context manager."""

    def test_ephemeral_scope_basic(self):
        from efsf.sealed import ephemeral_scope

        with ephemeral_scope("test") as scope:
            scope["sensitive"] = bytearray(b"data")

        # Scope should be cleaned
        assert len(scope) == 0
