package io.efsf;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.efsf.certificate.*;
import io.efsf.crypto.*;
import io.efsf.exception.*;
import io.efsf.record.*;
import io.efsf.store.*;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The main entry point for the EFSF SDK.
 * Provides encrypted ephemeral storage with automatic TTL enforcement.
 *
 * <pre>
 * EphemeralStore store = EphemeralStore.builder()
 *     .backend(new MemoryBackend())
 *     .defaultTTL("1h")
 *     .build();
 *
 * EphemeralRecord record = store.put(Map.of("user_id", "123"), "30m");
 * Map&lt;String, Object&gt; data = store.get(record.getId());
 * DestructionCertificate cert = store.destroy(record.getId());
 * </pre>
 */
public final class EphemeralStore implements AutoCloseable {

    private final StorageBackend backend;
    private final CryptoProvider crypto;
    private final Duration defaultTTL;
    private final DataClassification defaultClassification;
    private final AttestationAuthority authority;
    private final ObjectMapper objectMapper;

    // Statistics
    private final AtomicLong putCount = new AtomicLong(0);
    private final AtomicLong getCount = new AtomicLong(0);
    private final AtomicLong destroyCount = new AtomicLong(0);

    private EphemeralStore(Builder builder) {
        this.backend = builder.backend != null ? builder.backend : new MemoryBackend();
        this.crypto = new CryptoProvider();
        this.defaultTTL = builder.defaultTTL;
        this.defaultClassification = builder.defaultClassification;
        this.authority = builder.authority;
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
    }

    /**
     * Creates a new builder for EphemeralStore.
     *
     * @return a new Builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Stores data with the specified TTL.
     *
     * @param data the data to store
     * @param ttl the TTL string (e.g., "30m", "2h")
     * @return the created record
     */
    public EphemeralRecord put(Object data, String ttl) {
        return put(data, TTLParser.parse(ttl), defaultClassification);
    }

    /**
     * Stores data with the specified TTL and classification.
     *
     * @param data the data to store
     * @param ttl the TTL string
     * @param classification the data classification
     * @return the created record
     */
    public EphemeralRecord put(Object data, String ttl, DataClassification classification) {
        return put(data, TTLParser.parse(ttl), classification);
    }

    /**
     * Stores data with the specified TTL Duration.
     *
     * @param data the data to store
     * @param ttl the TTL Duration
     * @return the created record
     */
    public EphemeralRecord put(Object data, Duration ttl) {
        return put(data, ttl, defaultClassification);
    }

    /**
     * Stores data with the specified TTL and classification.
     *
     * @param data the data to store
     * @param ttl the TTL Duration
     * @param classification the data classification
     * @return the created record
     */
    public EphemeralRecord put(Object data, Duration ttl, DataClassification classification) {
        Duration effectiveTTL = ttl != null ? ttl : defaultTTL;
        if (effectiveTTL == null) {
            throw new IllegalArgumentException("TTL must be specified or a default TTL must be set");
        }

        DataClassification effectiveClassification = classification != null ? classification : DataClassification.TRANSIENT;

        // Create the record
        EphemeralRecord record = EphemeralRecord.create(effectiveTTL, effectiveClassification);

        // Generate a DEK for this record
        DataEncryptionKey dek = crypto.generateDEK();

        // Encrypt the data
        EncryptedPayload payload = crypto.encryptJson(data, dek);

        // Store the encrypted payload and record metadata
        Map<String, Object> stored = new LinkedHashMap<>();
        stored.put("record", record.toMap());
        stored.put("payload", payload.toMap());
        stored.put("key", dek.toBase64());

        try {
            String json = objectMapper.writeValueAsString(stored);
            backend.set(record.getId(), json, effectiveTTL);
            putCount.incrementAndGet();
        } catch (JsonProcessingException e) {
            throw new EfsfException("Failed to serialize data", e);
        }

        return record;
    }

    /**
     * Retrieves data by record ID.
     *
     * @param recordId the record ID
     * @return the decrypted data as a Map
     * @throws RecordNotFoundException if the record doesn't exist
     * @throws RecordExpiredException if the record has expired
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> get(String recordId) {
        return get(recordId, Map.class);
    }

    /**
     * Retrieves data by record ID, deserializing to the specified type.
     *
     * @param recordId the record ID
     * @param type the class to deserialize to
     * @param <T> the type
     * @return the decrypted data
     * @throws RecordNotFoundException if the record doesn't exist
     * @throws RecordExpiredException if the record has expired
     */
    @SuppressWarnings("unchecked")
    public <T> T get(String recordId, Class<T> type) {
        Optional<String> json = backend.get(recordId);
        if (json.isEmpty()) {
            throw new RecordNotFoundException(recordId);
        }

        try {
            Map<String, Object> stored = objectMapper.readValue(json.get(), Map.class);
            Map<String, Object> recordMap = (Map<String, Object>) stored.get("record");
            EphemeralRecord record = EphemeralRecord.fromMap(recordMap);

            if (record.isExpired()) {
                backend.delete(recordId);
                throw new RecordExpiredException(recordId, record.getExpiresAt());
            }

            // Reconstruct the DEK
            String keyBase64 = (String) stored.get("key");
            Map<String, Object> payloadMap = (Map<String, Object>) stored.get("payload");
            String keyId = (String) payloadMap.get("key_id");
            DataEncryptionKey dek = DataEncryptionKey.fromBase64(keyId, keyBase64);

            // Decrypt the payload
            EncryptedPayload payload = EncryptedPayload.fromMap(payloadMap);
            getCount.incrementAndGet();

            return crypto.decryptJson(payload, dek, type);
        } catch (RecordNotFoundException | RecordExpiredException e) {
            throw e;
        } catch (Exception e) {
            throw new EfsfException("Failed to retrieve data for record: " + recordId, e);
        }
    }

    /**
     * Retrieves data by record ID, returning Optional.empty() if not found.
     *
     * @param recordId the record ID
     * @return the data, or empty if not found
     */
    public Optional<Map<String, Object>> getOptional(String recordId) {
        try {
            return Optional.of(get(recordId));
        } catch (RecordNotFoundException | RecordExpiredException e) {
            return Optional.empty();
        }
    }

    /**
     * Destroys a record and returns a destruction certificate.
     *
     * @param recordId the record ID
     * @return the destruction certificate
     * @throws RecordNotFoundException if the record doesn't exist
     */
    @SuppressWarnings("unchecked")
    public DestructionCertificate destroy(String recordId) {
        Optional<String> json = backend.get(recordId);
        if (json.isEmpty()) {
            throw new RecordNotFoundException(recordId);
        }

        try {
            Map<String, Object> stored = objectMapper.readValue(json.get(), Map.class);
            Map<String, Object> payloadMap = (Map<String, Object>) stored.get("payload");

            // Calculate size for certificate
            long size = json.get().length();

            // Delete from backend
            backend.delete(recordId);

            // Destroy the DEK (crypto-shredding)
            String keyId = (String) payloadMap.get("key_id");
            crypto.destroyKey(keyId);

            // Generate destruction certificate
            ResourceInfo resource = new ResourceInfo("ephemeral_record", recordId, size, backend.getBackendName());

            ChainOfCustody chain = new ChainOfCustody()
                .addEntry("STORED", "efsf-java", "Record stored in " + backend.getBackendName())
                .addEntry("KEY_DESTROYED", "efsf-java", "Encryption key destroyed (crypto-shred)")
                .addEntry("DATA_DELETED", "efsf-java", "Record deleted from storage");

            DestructionCertificate cert = new DestructionCertificate.Builder()
                .resource(resource)
                .method(DestructionMethod.KEY_DESTRUCTION)
                .chainOfCustody(chain)
                .build();

            if (authority != null) {
                authority.sign(cert);
            }

            destroyCount.incrementAndGet();
            return cert;

        } catch (RecordNotFoundException e) {
            throw e;
        } catch (Exception e) {
            throw new EfsfException("Failed to destroy record: " + recordId, e);
        }
    }

    /**
     * Gets the remaining TTL for a record.
     *
     * @param recordId the record ID
     * @return the remaining TTL, or empty if the record doesn't exist
     */
    public Optional<Duration> ttl(String recordId) {
        return backend.ttl(recordId);
    }

    /**
     * Checks if a record exists.
     *
     * @param recordId the record ID
     * @return true if the record exists
     */
    public boolean exists(String recordId) {
        return backend.exists(recordId);
    }

    /**
     * Gets statistics about this store.
     *
     * @return a map of statistics
     */
    public Map<String, Object> stats() {
        return Map.of(
            "backend", backend.getBackendName(),
            "puts", putCount.get(),
            "gets", getCount.get(),
            "destroys", destroyCount.get(),
            "active_keys", crypto.getKeyCount()
        );
    }

    @Override
    public void close() {
        crypto.destroyAllKeys();
        backend.close();
    }

    /**
     * Builder for EphemeralStore.
     */
    public static class Builder {
        private StorageBackend backend;
        private Duration defaultTTL;
        private DataClassification defaultClassification = DataClassification.TRANSIENT;
        private AttestationAuthority authority;

        public Builder backend(StorageBackend backend) {
            this.backend = backend;
            return this;
        }

        public Builder backend(String uri) {
            if (uri.startsWith("redis://") || uri.startsWith("rediss://")) {
                this.backend = new RedisBackend(uri);
            } else if (uri.equals("memory") || uri.equals("memory://")) {
                this.backend = new MemoryBackend();
            } else {
                throw new IllegalArgumentException("Unsupported backend URI: " + uri);
            }
            return this;
        }

        public Builder defaultTTL(Duration defaultTTL) {
            this.defaultTTL = defaultTTL;
            return this;
        }

        public Builder defaultTTL(String defaultTTL) {
            this.defaultTTL = TTLParser.parse(defaultTTL);
            return this;
        }

        public Builder defaultClassification(DataClassification defaultClassification) {
            this.defaultClassification = defaultClassification;
            return this;
        }

        public Builder authority(AttestationAuthority authority) {
            this.authority = authority;
            return this;
        }

        public EphemeralStore build() {
            return new EphemeralStore(this);
        }
    }
}
