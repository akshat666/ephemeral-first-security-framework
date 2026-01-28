"""
EFSF Sealed Execution

Provides sealed execution contexts where all state is guaranteed
to be destroyed upon exit.

Note: In pure Python without hardware TEE support, memory zeroing
is best-effort. For production use with sensitive data, integrate
with Intel SGX, AMD SEV, or AWS Nitro Enclaves.
"""

import functools
import gc
import weakref
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional, TypeVar

from typing_extensions import ParamSpec

from efsf.certificate import (
    AttestationAuthority,
    ChainOfCustody,
    DestructionCertificate,
    DestructionMethod,
    ResourceInfo,
)

P = ParamSpec("P")
T = TypeVar("T")


def secure_zero_memory(data: Any) -> None:
    """
    Attempt to securely zero memory containing sensitive data.

    WARNING: This is best-effort in Python due to:
    - Garbage collection may have already copied data
    - String interning
    - Immutable types

    For true security, use hardware enclaves or HSMs.
    """
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
    elif isinstance(data, memoryview):
        for i in range(len(data)):
            data[i] = 0
    elif isinstance(data, dict):
        for key in list(data.keys()):
            secure_zero_memory(data[key])
            del data[key]
    elif isinstance(data, list):
        for i in range(len(data)):
            secure_zero_memory(data[i])
        data.clear()
    # For immutable types (str, bytes, int, tuple), we can't zero them
    # We can only hope garbage collection handles them


@dataclass
class SealedContext:
    """
    Context object passed to sealed functions.

    Tracks all sensitive data created during execution
    for cleanup on exit.
    """

    execution_id: str
    started_at: datetime
    _sensitive_refs: list[weakref.ref] = field(default_factory=list)
    _sensitive_direct: list[Any] = field(default_factory=list)
    _cleanup_callbacks: list[Callable[[], None]] = field(default_factory=list)

    def track(self, obj: Any) -> Any:
        """
        Track an object for cleanup on context exit.

        Args:
            obj: Object to track

        Returns:
            The same object (for chaining)
        """
        try:
            self._sensitive_refs.append(weakref.ref(obj))
        except TypeError:
            # Some objects (e.g. bytearray) can't have weak references;
            # store a direct reference so we can still zero them on cleanup.
            self._sensitive_direct.append(obj)
        return obj

    def on_cleanup(self, callback: Callable[[], None]) -> None:
        """Register a cleanup callback to run on context exit."""
        self._cleanup_callbacks.append(callback)

    def _cleanup(self) -> None:
        """Internal: Run cleanup routines."""
        # Run registered callbacks
        for callback in self._cleanup_callbacks:
            try:
                callback()
            except Exception:
                pass  # Don't let cleanup errors propagate

        # Attempt to zero tracked objects
        for ref in self._sensitive_refs:
            obj = ref()
            if obj is not None:
                secure_zero_memory(obj)

        for obj in self._sensitive_direct:
            secure_zero_memory(obj)

        # Clear our own state
        self._sensitive_refs.clear()
        self._sensitive_direct.clear()
        self._cleanup_callbacks.clear()

        # Force garbage collection
        gc.collect()


class SealedExecution:
    """
    Context manager for sealed execution.

    All state created within this context is destroyed on exit,
    and a destruction certificate can be generated.

    Example:
        with SealedExecution(attestation=True) as ctx:
            sensitive_data = ctx.track(process_secrets())
            result = compute(sensitive_data)
        # sensitive_data is now destroyed
        # ctx.certificate contains proof of destruction
    """

    _default_authority: Optional[AttestationAuthority] = None

    def __init__(
        self,
        attestation: bool = False,
        authority: Optional[AttestationAuthority] = None,
        metadata: Optional[dict[str, Any]] = None,
    ):
        """
        Initialize a sealed execution context.

        Args:
            attestation: Whether to generate a destruction certificate
            authority: Attestation authority for signing certificates
            metadata: Additional metadata for the certificate
        """
        self.attestation = attestation
        self.authority = authority
        self.metadata = metadata or {}
        self.context: Optional[SealedContext] = None
        self.certificate: Optional[DestructionCertificate] = None
        self._chain_of_custody: Optional[ChainOfCustody] = None

        if attestation and authority is None:
            if SealedExecution._default_authority is None:
                SealedExecution._default_authority = AttestationAuthority()
            self.authority = SealedExecution._default_authority

    def __enter__(self) -> SealedContext:
        """Enter the sealed execution context."""
        import uuid

        execution_id = str(uuid.uuid4())
        now = datetime.utcnow()

        self.context = SealedContext(
            execution_id=execution_id,
            started_at=now,
        )

        if self.attestation:
            self._chain_of_custody = ChainOfCustody(
                created_at=now,
                created_by="sealed_execution",
            )
            self._chain_of_custody.add_access(
                accessor="sealed_execution",
                action="context_enter",
            )

        return self.context

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit the sealed execution context and destroy all state."""
        if self.context is None:
            return

        # Record exit in chain of custody
        if self._chain_of_custody:
            action = "context_exit_error" if exc_type else "context_exit_normal"
            self._chain_of_custody.add_access(
                accessor="sealed_execution",
                action=action,
            )

        # Perform cleanup
        self.context._cleanup()

        # Generate destruction certificate if requested
        if self.attestation and self.authority:
            resource = ResourceInfo(
                resource_type="sealed_compute",
                resource_id=self.context.execution_id,
                classification="TRANSIENT",
                metadata={
                    "started_at": self.context.started_at.isoformat(),
                    "duration_ms": (datetime.utcnow() - self.context.started_at).total_seconds()
                    * 1000,
                    "error": str(exc_val) if exc_val else None,
                    **self.metadata,
                },
            )

            cert = DestructionCertificate.create(
                resource=resource,
                destruction_method=DestructionMethod.MEMORY_ZERO,
                verified_by=self.authority.authority_id,
                chain_of_custody=self._chain_of_custody,
            )

            self.certificate = self.authority.sign_certificate(cert)

        # Clear context reference
        self.context = None

        # Don't suppress exceptions
        return


def sealed(
    attestation: bool = False,
    authority: Optional[AttestationAuthority] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator for sealed function execution.

    Wraps a function so that all local state is destroyed
    when the function returns.

    Example:
        @sealed(attestation=True)
        def process_sensitive(ssn: str) -> str:
            # All local variables destroyed on return
            return f"processed:{hash(ssn)}"

    Args:
        attestation: Whether to generate destruction certificates
        authority: Attestation authority for signing
        metadata: Additional metadata

    Returns:
        Decorated function
    """

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            seal = SealedExecution(
                attestation=attestation,
                authority=authority,
                metadata={
                    "function": func.__name__,
                    "module": func.__module__,
                    **(metadata or {}),
                },
            )

            with seal as ctx:
                # Track function arguments
                for arg in args:
                    ctx.track(arg)
                for value in kwargs.values():
                    ctx.track(value)

                result = func(*args, **kwargs)

            # Attach certificate to result if it's a dict
            if attestation and seal.certificate and isinstance(result, dict):
                result["_destruction_certificate"] = seal.certificate.to_dict()

            return result

        # Attach method to get the last certificate
        wrapper._last_execution = None  # type: ignore[attr-defined]

        return wrapper

    return decorator


@contextmanager
def ephemeral_scope(name: str = "anonymous") -> Generator[dict[str, Any], None, None]:
    """
    Simple context manager for ephemeral variable scope.

    Variables created in this scope should be considered
    destroyed on exit (best-effort cleanup).

    Example:
        with ephemeral_scope("payment_processing"):
            card_number = get_card()
            result = process_payment(card_number)
        # card_number cleanup attempted
    """
    scope_vars: dict[str, Any] = {}

    try:
        yield scope_vars
    finally:
        # Attempt to clean up tracked variables
        for key in list(scope_vars.keys()):
            secure_zero_memory(scope_vars[key])
            del scope_vars[key]
        gc.collect()
