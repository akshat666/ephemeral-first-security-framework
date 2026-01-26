package io.efsf.store;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory storage backend with lazy expiration.
 * Suitable for testing and single-node deployments.
 */
public final class MemoryBackend implements StorageBackend {

    private final Map<String, Entry> data;

    public MemoryBackend() {
        this.data = new ConcurrentHashMap<>();
    }

    @Override
    public void set(String key, String value, Duration ttl) {
        Instant expiresAt = Instant.now().plus(ttl);
        data.put(key, new Entry(value, expiresAt));
    }

    @Override
    public Optional<String> get(String key) {
        Entry entry = data.get(key);
        if (entry == null) {
            return Optional.empty();
        }
        // Return the value even if expired - let the caller handle expiration
        // This allows EphemeralStore to distinguish between missing and expired records
        return Optional.of(entry.value());
    }

    @Override
    public boolean delete(String key) {
        return data.remove(key) != null;
    }

    @Override
    public boolean exists(String key) {
        Entry entry = data.get(key);
        if (entry == null) {
            return false;
        }
        if (isExpired(entry)) {
            data.remove(key);
            return false;
        }
        return true;
    }

    @Override
    public Optional<Duration> ttl(String key) {
        Entry entry = data.get(key);
        if (entry == null) {
            return Optional.empty();
        }
        if (isExpired(entry)) {
            data.remove(key);
            return Optional.empty();
        }
        Duration remaining = Duration.between(Instant.now(), entry.expiresAt());
        return Optional.of(remaining.isNegative() ? Duration.ZERO : remaining);
    }

    @Override
    public String getBackendName() {
        return "memory";
    }

    @Override
    public void close() {
        data.clear();
    }

    /**
     * Gets the number of entries (including potentially expired ones).
     *
     * @return the entry count
     */
    public int size() {
        return data.size();
    }

    /**
     * Removes all expired entries.
     *
     * @return the number of entries removed
     */
    public int cleanup() {
        int removed = 0;
        var iterator = data.entrySet().iterator();
        while (iterator.hasNext()) {
            var entry = iterator.next();
            if (isExpired(entry.getValue())) {
                iterator.remove();
                removed++;
            }
        }
        return removed;
    }

    private boolean isExpired(Entry entry) {
        return Instant.now().isAfter(entry.expiresAt());
    }

    private record Entry(String value, Instant expiresAt) {}
}
