# EFSF Java SDK

Java SDK for the Ephemeral-First Security Framework.

## Requirements

- Java 17 or later
- Maven 3.6+

## Installation

Add the dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>io.efsf</groupId>
    <artifactId>efsf-java</artifactId>
    <version>0.3.0</version>
</dependency>
```

For Redis backend support, also add:

```xml
<dependency>
    <groupId>redis.clients</groupId>
    <artifactId>jedis</artifactId>
    <version>5.1.0</version>
</dependency>
```

## Quick Start

```java
import io.efsf.EphemeralStore;
import io.efsf.record.DataClassification;
import io.efsf.record.EphemeralRecord;
import io.efsf.certificate.DestructionCertificate;

import java.util.Map;

// Create an ephemeral store
try (EphemeralStore store = EphemeralStore.builder()
    .backend("redis://localhost:6379")
    .defaultTTL("1h")
    .build()) {

    // Store data that automatically destroys itself
    EphemeralRecord record = store.put(
        Map.of("user_id", "123", "session_token", "abc"),
        "30m",  // Gone in 30 minutes, guaranteed
        DataClassification.TRANSIENT
    );

    // Retrieve while it exists
    Map<String, Object> data = store.get(record.getId());

    // Get cryptographic proof of destruction
    DestructionCertificate certificate = store.destroy(record.getId());
}
```

## Sealed Execution

Process sensitive data with guaranteed cleanup:

```java
import io.efsf.sealed.SealedExecution;
import io.efsf.certificate.AttestationAuthority;

// Using try-with-resources
try (SealedExecution seal = SealedExecution.create()) {
    var ctx = seal.getContext();

    // Track sensitive objects
    String ssn = ctx.track("123-45-6789");
    Double income = ctx.track(75000.00);

    // Process the data
    boolean approved = calculateRisk(ssn, income) > 0.7;
}
// All tracked objects are cleaned up here

// With attestation certificate
AttestationAuthority authority = AttestationAuthority.create();
var result = SealedExecution.runWithAttestation(authority, ctx -> {
    String secret = ctx.track(loadSecret());
    return processSecret(secret);
});
// result.getValue() - the return value
// result.getCertificate() - signed destruction certificate
```

## Data Classification

| Classification | TTL Range | Example |
|---------------|-----------|---------|
| `TRANSIENT` | Seconds–Hours | Session tokens, OTPs |
| `SHORT_LIVED` | Hours–Days | Shopping carts, temp uploads |
| `RETENTION_BOUND` | Days–Years | Invoices, audit logs |
| `PERSISTENT` | Indefinite | Legal holds (requires justification) |

```java
// TRANSIENT: Auto-expires quickly
store.put(Map.of("otp", "123456"), "5m", DataClassification.TRANSIENT);

// SHORT_LIVED: Hours to days
store.put(Map.of("cart", items), "24h", DataClassification.SHORT_LIVED);

// RETENTION_BOUND: Legal requirements
store.put(Map.of("invoice", data), "7y", DataClassification.RETENTION_BOUND);
```

## Storage Backends

### Memory Backend (Testing/Development)

```java
EphemeralStore store = EphemeralStore.builder()
    .backend(new MemoryBackend())
    .defaultTTL("1h")
    .build();
```

### Redis Backend (Production)

```java
EphemeralStore store = EphemeralStore.builder()
    .backend("redis://localhost:6379")
    .defaultTTL("1h")
    .build();
```

## Signed Destruction Certificates

For compliance (GDPR, CCPA, HIPAA), generate signed certificates:

```java
// Create an attestation authority
AttestationAuthority authority = AttestationAuthority.create("compliance-authority");

// Store with attestation
EphemeralStore store = EphemeralStore.builder()
    .backend(new MemoryBackend())
    .authority(authority)
    .defaultTTL("1h")
    .build();

// Certificates are automatically signed
EphemeralRecord record = store.put(data, "30m");
DestructionCertificate cert = store.destroy(record.getId());

// Verify the certificate
assertTrue(cert.isSigned());
assertTrue(authority.verify(cert));

// Export for audit trail
Map<String, Object> certData = cert.toMap();
```

## Spring Boot Integration

```java
@Configuration
public class EfsfConfig {

    @Bean
    public AttestationAuthority attestationAuthority() {
        // Load from secure storage in production
        return AttestationAuthority.create("prod-authority");
    }

    @Bean
    public EphemeralStore ephemeralStore(AttestationAuthority authority) {
        return EphemeralStore.builder()
            .backend("redis://localhost:6379")
            .defaultTTL("1h")
            .authority(authority)
            .build();
    }
}

@Service
public class SessionService {

    @Autowired
    private EphemeralStore store;

    public String createSession(String userId) {
        EphemeralRecord record = store.put(
            Map.of("user_id", userId),
            "30m",
            DataClassification.TRANSIENT
        );
        return record.getId();
    }

    public Optional<Map<String, Object>> getSession(String sessionId) {
        return store.getOptional(sessionId);
    }

    public DestructionCertificate invalidateSession(String sessionId) {
        return store.destroy(sessionId);
    }
}
```

## Building from Source

```bash
cd sdk/java
mvn clean install
```

## Running Tests

```bash
mvn test
```

## Running Examples

```bash
mvn exec:java -Dexec.mainClass="io.efsf.examples.BasicUsageExample"
mvn exec:java -Dexec.mainClass="io.efsf.examples.SpringBootExample"
```

## API Reference

### EphemeralStore

| Method | Description |
|--------|-------------|
| `put(data, ttl)` | Store data with TTL |
| `put(data, ttl, classification)` | Store with classification |
| `get(recordId)` | Retrieve data |
| `getOptional(recordId)` | Retrieve data as Optional |
| `destroy(recordId)` | Destroy and get certificate |
| `ttl(recordId)` | Get remaining TTL |
| `exists(recordId)` | Check if record exists |
| `stats()` | Get store statistics |

### SealedExecution

| Method | Description |
|--------|-------------|
| `create()` | Create sealed context |
| `withAttestation(authority)` | Create with certificate generation |
| `run(function)` | Execute function in sealed context |
| `runWithAttestation(authority, function)` | Execute with certificate |

### AttestationAuthority

| Method | Description |
|--------|-------------|
| `create()` | Generate new Ed25519 keypair |
| `fromBase64PrivateKey(id, key)` | Restore from private key |
| `sign(certificate)` | Sign a destruction certificate |
| `verify(certificate)` | Verify certificate signature |

## License

Apache 2.0
