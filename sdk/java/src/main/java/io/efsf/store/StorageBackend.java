package io.efsf.store;

import java.time.Duration;
import java.util.Optional;

/**
 * Interface for storage backends that support TTL-based expiration.
 */
public interface StorageBackend extends AutoCloseable {

    /**
     * Stores a value with the specified key and TTL.
     *
     * @param key the key
     * @param value the value
     * @param ttl the time-to-live
     */
    void set(String key, String value, Duration ttl);

    /**
     * Gets a value by key.
     *
     * @param key the key
     * @return the value, or empty if not found or expired
     */
    Optional<String> get(String key);

    /**
     * Deletes a value by key.
     *
     * @param key the key
     * @return true if the key existed and was deleted
     */
    boolean delete(String key);

    /**
     * Checks if a key exists and is not expired.
     *
     * @param key the key
     * @return true if the key exists
     */
    boolean exists(String key);

    /**
     * Gets the remaining TTL for a key.
     *
     * @param key the key
     * @return the remaining TTL, or empty if the key doesn't exist
     */
    Optional<Duration> ttl(String key);

    /**
     * Gets the name of this backend type.
     *
     * @return the backend name
     */
    String getBackendName();

    /**
     * Closes the backend and releases resources.
     */
    @Override
    void close();
}
