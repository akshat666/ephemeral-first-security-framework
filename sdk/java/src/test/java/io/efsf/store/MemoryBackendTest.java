package io.efsf.store;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Memory Backend Tests")
class MemoryBackendTest {

    private MemoryBackend backend;

    @BeforeEach
    void setUp() {
        backend = new MemoryBackend();
    }

    @Test
    @DisplayName("Set and get value")
    void testSetAndGet() {
        backend.set("key1", "value1", Duration.ofMinutes(5));

        assertTrue(backend.get("key1").isPresent());
        assertEquals("value1", backend.get("key1").get());
    }

    @Test
    @DisplayName("Get returns empty for non-existent key")
    void testGetNonExistent() {
        assertTrue(backend.get("nonexistent").isEmpty());
    }

    @Test
    @DisplayName("Delete removes key")
    void testDelete() {
        backend.set("key1", "value1", Duration.ofMinutes(5));
        assertTrue(backend.exists("key1"));

        assertTrue(backend.delete("key1"));
        assertFalse(backend.exists("key1"));
        assertTrue(backend.get("key1").isEmpty());
    }

    @Test
    @DisplayName("Delete returns false for non-existent key")
    void testDeleteNonExistent() {
        assertFalse(backend.delete("nonexistent"));
    }

    @Test
    @DisplayName("Exists returns correct status")
    void testExists() {
        assertFalse(backend.exists("key1"));

        backend.set("key1", "value1", Duration.ofMinutes(5));
        assertTrue(backend.exists("key1"));
    }

    @Test
    @DisplayName("TTL returns remaining time")
    void testTTL() {
        backend.set("key1", "value1", Duration.ofMinutes(5));

        var ttl = backend.ttl("key1");
        assertTrue(ttl.isPresent());
        assertTrue(ttl.get().toMinutes() <= 5);
        assertTrue(ttl.get().toSeconds() > 0);
    }

    @Test
    @DisplayName("TTL returns empty for non-existent key")
    void testTTLNonExistent() {
        assertTrue(backend.ttl("nonexistent").isEmpty());
    }

    @Test
    @DisplayName("Expired keys are removed on access")
    void testLazyExpiration() throws InterruptedException {
        backend.set("key1", "value1", Duration.ofMillis(50));
        assertTrue(backend.exists("key1"));

        Thread.sleep(100);

        // get() returns value even if expired (so caller can check expiration metadata)
        // but exists() returns false for expired keys
        assertTrue(backend.get("key1").isPresent());
        assertFalse(backend.exists("key1"));
        // After exists() call, the expired entry is removed
        assertTrue(backend.get("key1").isEmpty());
    }

    @Test
    @DisplayName("Cleanup removes expired entries")
    void testCleanup() throws InterruptedException {
        backend.set("key1", "value1", Duration.ofMillis(50));
        backend.set("key2", "value2", Duration.ofMinutes(5));

        Thread.sleep(100);

        assertEquals(2, backend.size());
        int removed = backend.cleanup();
        assertEquals(1, removed);
        assertEquals(1, backend.size());
        assertTrue(backend.exists("key2"));
    }

    @Test
    @DisplayName("Close clears all data")
    void testClose() {
        backend.set("key1", "value1", Duration.ofMinutes(5));
        backend.set("key2", "value2", Duration.ofMinutes(5));
        assertEquals(2, backend.size());

        backend.close();
        assertEquals(0, backend.size());
    }

    @Test
    @DisplayName("Backend name is memory")
    void testBackendName() {
        assertEquals("memory", backend.getBackendName());
    }

    @Test
    @DisplayName("Overwriting key updates value and TTL")
    void testOverwrite() throws InterruptedException {
        backend.set("key1", "value1", Duration.ofMillis(100));
        Thread.sleep(50);

        backend.set("key1", "value2", Duration.ofMinutes(5));

        assertEquals("value2", backend.get("key1").get());
        assertTrue(backend.ttl("key1").get().toMinutes() > 0);
    }
}
