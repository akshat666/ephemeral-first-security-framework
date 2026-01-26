#!/usr/bin/env python3
"""
EFSF Basic Usage Example

This example demonstrates the core functionality of the
Ephemeral-First Security Framework.
"""

from datetime import timedelta
from efsf import (
    EphemeralStore,
    DataClassification,
    sealed,
    SealedExecution,
)


def main():
    print("=" * 60)
    print("EFSF Basic Usage Example")
    print("=" * 60)
    
    # =========================================================
    # 1. Basic Ephemeral Storage
    # =========================================================
    print("\n1. Basic Ephemeral Storage")
    print("-" * 40)
    
    # Create a store (in-memory for this example)
    store = EphemeralStore(
        backend="memory://",
        default_ttl="1h",
        attestation=True,
    )
    
    # Store some sensitive data
    sensitive_data = {
        "user_id": "user_12345",
        "session_token": "abc123xyz789",
        "ip_address": "192.168.1.100",
    }
    
    record = store.put(
        data=sensitive_data,
        ttl="30m",  # Data will be destroyed in 30 minutes
        classification=DataClassification.TRANSIENT,
        metadata={"source": "login_service"},
    )
    
    print(f"✓ Stored record: {record.id}")
    print(f"  Classification: {record.classification.value}")
    print(f"  Expires at: {record.expires_at}")
    print(f"  Key ID: {record.key_id}")
    
    # Retrieve the data
    retrieved = store.get(record.id)
    print(f"✓ Retrieved data: {retrieved}")
    
    # Check TTL
    remaining = store.ttl(record.id)
    print(f"✓ Time remaining: {remaining}")
    
    # =========================================================
    # 2. Manual Destruction with Certificate
    # =========================================================
    print("\n2. Manual Destruction with Certificate")
    print("-" * 40)
    
    # Destroy the record early
    certificate = store.destroy(record.id)
    
    print(f"✓ Record destroyed")
    print(f"  Certificate ID: {certificate.certificate_id}")
    print(f"  Method: {certificate.destruction_method.value}")
    print(f"  Timestamp: {certificate.destruction_timestamp}")
    print(f"  Signature: {certificate.signature[:50]}...")
    
    # Verify the record is gone
    exists = store.exists(record.id)
    print(f"✓ Record exists: {exists}")
    
    # =========================================================
    # 3. Data Classification Levels
    # =========================================================
    print("\n3. Data Classification Levels")
    print("-" * 40)
    
    classifications = [
        (DataClassification.TRANSIENT, "Session tokens, OTPs"),
        (DataClassification.SHORT_LIVED, "Shopping carts, temp uploads"),
        (DataClassification.RETENTION_BOUND, "Invoices, audit logs"),
    ]
    
    for classification, description in classifications:
        print(f"\n  {classification.value}:")
        print(f"    Description: {description}")
        print(f"    Default TTL: {classification.default_ttl}")
        print(f"    Max TTL: {classification.max_ttl}")
    
    # =========================================================
    # 4. Sealed Execution
    # =========================================================
    print("\n4. Sealed Execution")
    print("-" * 40)
    
    @sealed(attestation=True)
    def process_credit_card(card_number: str, amount: float) -> dict:
        """
        Process a payment. All local variables (including card_number)
        are destroyed when this function returns.
        """
        # Simulate payment processing
        masked = f"****-****-****-{card_number[-4:]}"
        return {
            "success": True,
            "masked_card": masked,
            "amount": amount,
        }
    
    result = process_credit_card("4111-1111-1111-1234", 99.99)
    print(f"✓ Payment processed: {result['masked_card']}")
    print(f"  Amount: ${result['amount']}")
    
    # Certificate is attached to dict results
    if "_destruction_certificate" in result:
        cert = result["_destruction_certificate"]
        print(f"  Destruction certificate: {cert['certificate_id']}")
    
    # =========================================================
    # 5. Sealed Execution Context Manager
    # =========================================================
    print("\n5. Sealed Execution Context Manager")
    print("-" * 40)
    
    seal = SealedExecution(attestation=True, metadata={"operation": "pii_processing"})
    
    with seal as ctx:
        # Track sensitive data for automatic cleanup
        ssn = ctx.track(bytearray(b"123-45-6789"))
        income = ctx.track(bytearray(b"75000"))
        
        # Process the data
        print(f"  Processing SSN: ***-**-{ssn[-4:].decode()}")
        
        # Register custom cleanup
        ctx.on_cleanup(lambda: print("  Custom cleanup executed!"))
    
    print(f"✓ Context exited, state destroyed")
    print(f"  Certificate: {seal.certificate.certificate_id}")
    print(f"  SSN buffer now: {bytes(ssn)}")  # Should be zeroed
    
    # =========================================================
    # 6. Store Statistics
    # =========================================================
    print("\n6. Store Statistics")
    print("-" * 40)
    
    # Create a few more records
    for i in range(3):
        store.put({"item": i}, ttl="1h")
    
    stats = store.stats()
    print(f"✓ Active records: {stats['active_records']}")
    print(f"  Certificates issued: {stats['certificates_issued']}")
    print(f"  Attestation enabled: {stats['attestation_enabled']}")
    
    # List all certificates
    certs = store.list_certificates()
    print(f"  Certificate history: {len(certs)} certificates")
    
    # =========================================================
    # Cleanup
    # =========================================================
    store.close()
    
    print("\n" + "=" * 60)
    print("Example complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
