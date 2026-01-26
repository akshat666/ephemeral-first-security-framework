/**
 * EFSF Basic Usage Example (TypeScript)
 *
 * Demonstrates core SDK features:
 * - Ephemeral storage with TTL
 * - Data classification
 * - Crypto-shredding on destruction
 * - Destruction certificates for compliance
 * - Sealed execution contexts
 *
 * Run with: npx ts-node examples/basic-usage.ts
 */

import {
  EphemeralStore,
  DataClassification,
  sealed,
  SealedExecution,
} from '../src/index.js';

async function main() {
  console.log('='.repeat(60));
  console.log('EFSF Basic Usage Example (TypeScript)');
  console.log('='.repeat(60));

  // ============================================================
  // 1. Basic Ephemeral Storage
  // ============================================================
  console.log('\n1. Basic Ephemeral Storage');
  console.log('-'.repeat(40));

  // Create a store with memory backend (use redis:// for production)
  const store = new EphemeralStore({
    backend: 'memory://',
    defaultTTL: '1h',
    attestation: true,
  });

  // Store sensitive session data
  const sensitiveData = {
    user_id: 'user_12345',
    session_token: 'abc123xyz789',
    ip_address: '192.168.1.100',
  };

  const record = await store.put(sensitiveData, {
    ttl: '30m', // Expires in 30 minutes
    classification: DataClassification.TRANSIENT,
    metadata: { source: 'login_service' },
  });

  console.log(`Stored record: ${record.id}`);
  console.log(`  Classification: ${record.classification}`);
  console.log(`  TTL: ${record.ttl / 1000}s`);
  console.log(`  Expires at: ${record.expiresAt.toISOString()}`);
  console.log(`  Key ID: ${record.keyId}`);

  // Retrieve the data
  const retrieved = await store.get(record.id);
  console.log(`\nRetrieved data: ${JSON.stringify(retrieved)}`);

  // Check remaining TTL
  const remainingTTL = await store.ttl(record.id);
  console.log(`Remaining TTL: ${remainingTTL! / 1000}s`);

  // ============================================================
  // 2. Manual Destruction with Certificate
  // ============================================================
  console.log('\n2. Manual Destruction with Certificate');
  console.log('-'.repeat(40));

  // Destroy the record (crypto-shredding)
  const certificate = await store.destroy(record.id);

  console.log(`Record destroyed!`);
  console.log(`  Certificate ID: ${certificate?.certificateId}`);
  console.log(`  Method: ${certificate?.destructionMethod}`);
  console.log(`  Timestamp: ${certificate?.destructionTimestamp.toISOString()}`);
  console.log(`  Verified by: ${certificate?.verifiedBy}`);

  // Verify the certificate
  if (certificate && store._authority) {
    const isValid = store._authority.verifyCertificate(certificate);
    console.log(`  Signature valid: ${isValid}`);
  }

  // The data is now permanently unrecoverable
  try {
    await store.get(record.id);
  } catch (error) {
    console.log(`\nAttempt to retrieve destroyed record: ${(error as Error).name}`);
  }

  // ============================================================
  // 3. Data Classifications
  // ============================================================
  console.log('\n3. Data Classifications');
  console.log('-'.repeat(40));

  // TRANSIENT: Sessions, OTPs (max 24h)
  const transientRecord = await store.put(
    { otp: '123456' },
    {
      ttl: '5m',
      classification: DataClassification.TRANSIENT,
    }
  );
  console.log(`TRANSIENT record: ${transientRecord.id} (${transientRecord.ttl / 1000}s TTL)`);

  // SHORT_LIVED: Shopping carts, temp uploads (max 7d)
  const shortLivedRecord = await store.put(
    { cart_items: ['item1', 'item2'] },
    {
      ttl: '1d',
      classification: DataClassification.SHORT_LIVED,
    }
  );
  console.log(`SHORT_LIVED record: ${shortLivedRecord.id} (${shortLivedRecord.ttl / 1000 / 60 / 60}h TTL)`);

  // RETENTION_BOUND: Invoices, audit logs (max 7y)
  const retentionRecord = await store.put(
    { invoice_id: 'INV-001', amount: 99.99 },
    {
      ttl: '90d',
      classification: DataClassification.RETENTION_BOUND,
    }
  );
  console.log(`RETENTION_BOUND record: ${retentionRecord.id} (${retentionRecord.ttl / 1000 / 60 / 60 / 24}d TTL)`);

  // ============================================================
  // 4. Sealed Execution (Context Manager Style)
  // ============================================================
  console.log('\n4. Sealed Execution (Context Manager Style)');
  console.log('-'.repeat(40));

  const seal = new SealedExecution({ attestation: true });

  const result = await seal.run((ctx) => {
    // Track sensitive data for automatic cleanup
    const ssn = ctx.track(Buffer.from('123-45-6789'));

    console.log(`  Processing SSN: ***-**-${ssn.subarray(-4).toString()}`);

    // Register cleanup callback
    ctx.onCleanup(() => {
      console.log('  Cleanup callback executed!');
    });

    return { processed: true };
  });

  console.log(`  Result: ${JSON.stringify(result)}`);
  console.log(`  Certificate ID: ${seal.certificate?.certificateId}`);
  console.log(`  Duration: ${seal.certificate?.resource.metadata.duration_ms}ms`);

  // ============================================================
  // 5. Sealed Decorator Style
  // ============================================================
  console.log('\n5. Sealed Decorator Style');
  console.log('-'.repeat(40));

  // Define a sealed function
  const processPayment = sealed({ attestation: true })(
    async (cardNumber: string, amount: number) => {
      // Card number will be destroyed on return
      const masked = `****-****-****-${cardNumber.slice(-4)}`;
      console.log(`  Processing payment: ${masked} for $${amount}`);
      return { success: true, masked_card: masked, amount };
    }
  );

  const paymentResult = await processPayment('4111-1111-1111-1234', 99.99);
  console.log(`  Result: ${JSON.stringify(paymentResult, null, 2)}`);

  // ============================================================
  // 6. Listing Certificates
  // ============================================================
  console.log('\n6. Compliance - Listing Destruction Certificates');
  console.log('-'.repeat(40));

  // Destroy remaining records
  await store.destroy(transientRecord.id);
  await store.destroy(shortLivedRecord.id);
  await store.destroy(retentionRecord.id);

  const allCerts = store.listCertificates();
  console.log(`Total certificates: ${allCerts.length}`);

  for (const cert of allCerts.slice(0, 3)) {
    console.log(`  - ${cert.resource.resourceId}: ${cert.destructionMethod} at ${cert.destructionTimestamp.toISOString()}`);
  }

  // ============================================================
  // 7. Store Statistics
  // ============================================================
  console.log('\n7. Store Statistics');
  console.log('-'.repeat(40));

  const stats = store.stats();
  console.log(`Active records: ${stats.activeRecords}`);
  console.log(`Certificates issued: ${stats.certificatesIssued}`);
  console.log(`Attestation enabled: ${stats.attestationEnabled}`);

  // Clean up
  await store.close();

  console.log('\n' + '='.repeat(60));
  console.log('Example complete!');
  console.log('='.repeat(60));
}

main().catch(console.error);
