package io.efsf.examples;

import io.efsf.EphemeralStore;
import io.efsf.certificate.AttestationAuthority;
import io.efsf.certificate.DestructionCertificate;
import io.efsf.record.DataClassification;
import io.efsf.record.EphemeralRecord;
import io.efsf.sealed.SealedExecution;
import io.efsf.store.MemoryBackend;

import java.util.Map;

/**
 * Basic usage example for the EFSF Java SDK.
 *
 * Run with: mvn exec:java -Dexec.mainClass="io.efsf.examples.BasicUsageExample"
 */
public class BasicUsageExample {

    public static void main(String[] args) throws Exception {
        System.out.println("=== EFSF Java SDK Basic Usage Example ===\n");

        // Example 1: Basic ephemeral storage
        basicStorageExample();

        // Example 2: Signed destruction certificates
        signedCertificateExample();

        // Example 3: Sealed execution
        sealedExecutionExample();

        // Example 4: Data classification
        classificationExample();

        System.out.println("\n=== All examples completed ===");
    }

    static void basicStorageExample() {
        System.out.println("--- Example 1: Basic Ephemeral Storage ---");

        try (EphemeralStore store = EphemeralStore.builder()
            .backend(new MemoryBackend())
            .defaultTTL("1h")
            .build()) {

            // Store sensitive data with automatic TTL
            Map<String, Object> userData = Map.of(
                "user_id", "user-123",
                "session_token", "abc123xyz",
                "ip_address", "192.168.1.1"
            );

            EphemeralRecord record = store.put(userData, "30m");
            System.out.println("Stored record: " + record.getId());
            System.out.println("Expires at: " + record.getExpiresAt());

            // Retrieve the data
            Map<String, Object> retrieved = store.get(record.getId());
            System.out.println("Retrieved data: " + retrieved);

            // Check TTL
            store.ttl(record.getId()).ifPresent(ttl ->
                System.out.println("Remaining TTL: " + ttl.toMinutes() + " minutes")
            );

            // Destroy with certificate
            DestructionCertificate cert = store.destroy(record.getId());
            System.out.println("Destruction certificate: " + cert.getId());
            System.out.println("Method: " + cert.getMethod());
        }

        System.out.println();
    }

    static void signedCertificateExample() {
        System.out.println("--- Example 2: Signed Destruction Certificates ---");

        // Create an attestation authority for signing certificates
        AttestationAuthority authority = AttestationAuthority.create("compliance-authority");
        System.out.println("Authority ID: " + authority.getId());
        System.out.println("Public Key: " + authority.getPublicKeyBase64().substring(0, 20) + "...");

        try (EphemeralStore store = EphemeralStore.builder()
            .backend(new MemoryBackend())
            .authority(authority)  // Certificates will be signed
            .defaultTTL("1h")
            .build()) {

            // Store and destroy with signed certificate
            EphemeralRecord record = store.put(
                Map.of("pii", "sensitive-data"),
                "15m",
                DataClassification.TRANSIENT
            );

            DestructionCertificate cert = store.destroy(record.getId());

            // Verify the certificate signature
            boolean valid = authority.verify(cert);
            System.out.println("Certificate signed: " + cert.isSigned());
            System.out.println("Signature valid: " + valid);
            System.out.println("Certificate hash: " + cert.computeHash());
        }

        System.out.println();
    }

    static void sealedExecutionExample() throws Exception {
        System.out.println("--- Example 3: Sealed Execution ---");

        // Using try-with-resources for automatic cleanup
        try (SealedExecution seal = SealedExecution.create()) {
            var ctx = seal.getContext();

            // Track sensitive data
            String ssn = ctx.track("123-45-6789");
            Double income = ctx.track(75000.00);

            // Process the data
            boolean approved = processApplication(ssn, income);
            System.out.println("Application approved: " + approved);
            System.out.println("Tracked objects: " + ctx.getTrackedCount());

            // Register cleanup callback
            ctx.onCleanup(() -> System.out.println("  Cleanup callback executed"));
        }
        // All tracked objects are now cleaned up

        // Using the static helper with attestation
        AttestationAuthority authority = AttestationAuthority.create();
        var result = SealedExecution.runWithAttestation(authority, ctx -> {
            String secret = ctx.track("super-secret-data");
            return "processed: " + secret.length() + " chars";
        });

        System.out.println("Result: " + result.getValue());
        System.out.println("Certificate generated: " + (result.getCertificate() != null));

        System.out.println();
    }

    static void classificationExample() {
        System.out.println("--- Example 4: Data Classification ---");

        try (EphemeralStore store = EphemeralStore.builder()
            .backend(new MemoryBackend())
            .defaultTTL("1h")
            .build()) {

            // TRANSIENT: Very short-lived (seconds to hours)
            EphemeralRecord transientRecord = store.put(
                Map.of("otp", "123456"),
                "5m",
                DataClassification.TRANSIENT
            );
            System.out.println("TRANSIENT record: " + transientRecord.getClassification());

            // SHORT_LIVED: Hours to days
            EphemeralRecord shortLivedRecord = store.put(
                Map.of("cart", Map.of("items", 3)),
                "24h",
                DataClassification.SHORT_LIVED
            );
            System.out.println("SHORT_LIVED record: " + shortLivedRecord.getClassification());

            // RETENTION_BOUND: Days to years (legal requirements)
            EphemeralRecord retentionRecord = store.put(
                Map.of("invoice", "INV-2024-001"),
                "365d",
                DataClassification.RETENTION_BOUND
            );
            System.out.println("RETENTION_BOUND record: " + retentionRecord.getClassification());

            // Show stats
            System.out.println("Store stats: " + store.stats());
        }

        System.out.println();
    }

    private static boolean processApplication(String ssn, Double income) {
        // Simulated processing
        return income > 50000;
    }
}
