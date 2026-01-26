package io.efsf.store;

import io.efsf.EphemeralStore;
import io.efsf.certificate.AttestationAuthority;
import io.efsf.certificate.DestructionCertificate;
import io.efsf.exception.RecordExpiredException;
import io.efsf.exception.RecordNotFoundException;
import io.efsf.record.DataClassification;
import io.efsf.record.EphemeralRecord;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Ephemeral Store Tests")
class EphemeralStoreTest {

    private EphemeralStore store;

    @BeforeEach
    void setUp() {
        store = EphemeralStore.builder()
            .backend(new MemoryBackend())
            .defaultTTL("1h")
            .build();
    }

    @AfterEach
    void tearDown() {
        store.close();
    }

    @Test
    @DisplayName("Put and get data")
    void testPutAndGet() {
        Map<String, Object> data = Map.of("user_id", "123", "session", "abc");

        EphemeralRecord record = store.put(data, "30m");
        assertNotNull(record.getId());

        Map<String, Object> retrieved = store.get(record.getId());
        assertEquals("123", retrieved.get("user_id"));
        assertEquals("abc", retrieved.get("session"));
    }

    @Test
    @DisplayName("Put with default TTL")
    void testPutWithDefaultTTL() {
        store = EphemeralStore.builder()
            .backend(new MemoryBackend())
            .defaultTTL("2h")
            .build();

        // Put without specifying TTL uses default
        EphemeralRecord record = store.put(Map.of("key", "value"), (Duration) null);
        assertTrue(store.exists(record.getId()));
    }

    @Test
    @DisplayName("Put with classification")
    void testPutWithClassification() {
        EphemeralRecord record = store.put(
            Map.of("data", "value"),
            "7d",
            DataClassification.SHORT_LIVED
        );

        assertEquals(DataClassification.SHORT_LIVED, record.getClassification());
    }

    @Test
    @DisplayName("Get throws RecordNotFoundException for missing record")
    void testGetNotFound() {
        assertThrows(RecordNotFoundException.class, () -> store.get("nonexistent-id"));
    }

    @Test
    @DisplayName("Get returns Optional.empty for missing record")
    void testGetOptionalEmpty() {
        assertTrue(store.getOptional("nonexistent-id").isEmpty());
    }

    @Test
    @DisplayName("Get returns Optional with data for existing record")
    void testGetOptionalPresent() {
        EphemeralRecord record = store.put(Map.of("key", "value"), "30m");

        var result = store.getOptional(record.getId());
        assertTrue(result.isPresent());
        assertEquals("value", result.get().get("key"));
    }

    @Test
    @DisplayName("Destroy returns destruction certificate")
    void testDestroy() {
        EphemeralRecord record = store.put(Map.of("data", "sensitive"), "30m");
        assertTrue(store.exists(record.getId()));

        DestructionCertificate cert = store.destroy(record.getId());

        assertNotNull(cert);
        assertNotNull(cert.getId());
        assertNotNull(cert.getTimestamp());
        assertEquals(record.getId(), cert.getResource().getResourceId());
        assertFalse(store.exists(record.getId()));
    }

    @Test
    @DisplayName("Destroy with attestation authority signs certificate")
    void testDestroyWithAttestation() {
        AttestationAuthority authority = AttestationAuthority.create();
        store = EphemeralStore.builder()
            .backend(new MemoryBackend())
            .authority(authority)
            .defaultTTL("1h")
            .build();

        EphemeralRecord record = store.put(Map.of("data", "value"), "30m");
        DestructionCertificate cert = store.destroy(record.getId());

        assertTrue(cert.isSigned());
        assertTrue(authority.verify(cert));
    }

    @Test
    @DisplayName("Destroy throws RecordNotFoundException for missing record")
    void testDestroyNotFound() {
        assertThrows(RecordNotFoundException.class, () -> store.destroy("nonexistent-id"));
    }

    @Test
    @DisplayName("TTL returns remaining time")
    void testTTL() {
        EphemeralRecord record = store.put(Map.of("data", "value"), "30m");

        var ttl = store.ttl(record.getId());
        assertTrue(ttl.isPresent());
        assertTrue(ttl.get().toMinutes() <= 30);
    }

    @Test
    @DisplayName("TTL returns empty for missing record")
    void testTTLNotFound() {
        assertTrue(store.ttl("nonexistent-id").isEmpty());
    }

    @Test
    @DisplayName("Exists returns correct status")
    void testExists() {
        assertFalse(store.exists("nonexistent-id"));

        EphemeralRecord record = store.put(Map.of("data", "value"), "30m");
        assertTrue(store.exists(record.getId()));
    }

    @Test
    @DisplayName("Stats returns store statistics")
    void testStats() {
        store.put(Map.of("data", "1"), "30m");
        store.put(Map.of("data", "2"), "30m");

        Map<String, Object> stats = store.stats();

        assertEquals("memory", stats.get("backend"));
        assertEquals(2L, stats.get("puts"));
        assertEquals(0L, stats.get("gets"));
        assertEquals(0L, stats.get("destroys"));
    }

    @Test
    @DisplayName("Expired records throw RecordExpiredException")
    void testExpiredRecord() throws InterruptedException {
        EphemeralRecord record = store.put(Map.of("data", "value"), Duration.ofMillis(50));

        Thread.sleep(100);

        assertThrows(RecordExpiredException.class, () -> store.get(record.getId()));
    }

    @Test
    @DisplayName("Data is encrypted at rest")
    void testEncryption() {
        MemoryBackend backend = new MemoryBackend();
        store = EphemeralStore.builder()
            .backend(backend)
            .defaultTTL("1h")
            .build();

        Map<String, Object> data = Map.of("secret", "password123");
        EphemeralRecord record = store.put(data, "30m");

        // Get raw stored value from backend
        String raw = backend.get(record.getId()).orElseThrow();

        // Raw value should not contain plaintext
        assertFalse(raw.contains("password123"));
        // But should contain encryption indicators
        assertTrue(raw.contains("ciphertext"));
        assertTrue(raw.contains("nonce"));
    }

    @Test
    @DisplayName("Builder configures backend from URI")
    void testBuilderWithUri() {
        store = EphemeralStore.builder()
            .backend("memory://")
            .defaultTTL("1h")
            .build();

        EphemeralRecord record = store.put(Map.of("test", "data"), "30m");
        assertTrue(store.exists(record.getId()));
    }

    @Test
    @DisplayName("Store can deserialize to specific type")
    void testTypedDeserialization() {
        Map<String, String> data = Map.of("name", "Test");
        EphemeralRecord record = store.put(data, "30m");

        @SuppressWarnings("unchecked")
        Map<String, String> result = store.get(record.getId(), Map.class);
        assertEquals("Test", result.get("name"));
    }
}
