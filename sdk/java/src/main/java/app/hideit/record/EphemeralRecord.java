package app.hideit.record;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Represents an ephemeral data record with automatic TTL enforcement.
 */
public final class EphemeralRecord {

    private final String id;
    private final Instant createdAt;
    private final Instant expiresAt;
    private final Duration ttl;
    private final DataClassification classification;
    private final Map<String, Object> metadata;

    private EphemeralRecord(Builder builder) {
        this.id = builder.id;
        this.createdAt = builder.createdAt;
        this.expiresAt = builder.expiresAt;
        this.ttl = builder.ttl;
        this.classification = builder.classification;
        this.metadata = builder.metadata != null ? Map.copyOf(builder.metadata) : Map.of();
    }

    public String getId() {
        return id;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Duration getTtl() {
        return ttl;
    }

    public DataClassification getClassification() {
        return classification;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    /**
     * Checks if this record has expired.
     *
     * @return true if the record has expired
     */
    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    /**
     * Gets the remaining TTL for this record.
     *
     * @return the remaining Duration, or Duration.ZERO if expired
     */
    public Duration getRemainingTTL() {
        Duration remaining = Duration.between(Instant.now(), expiresAt);
        return remaining.isNegative() ? Duration.ZERO : remaining;
    }

    /**
     * Creates a new record with the specified TTL and classification.
     *
     * @param ttl the TTL string (e.g., "30m", "2h")
     * @param classification the data classification
     * @return a new EphemeralRecord
     */
    public static EphemeralRecord create(String ttl, DataClassification classification) {
        return new Builder()
            .ttl(ttl)
            .classification(classification)
            .build();
    }

    /**
     * Creates a new record with the specified TTL string and default TRANSIENT classification.
     *
     * @param ttl the TTL string (e.g., "30m", "2h")
     * @return a new EphemeralRecord
     */
    public static EphemeralRecord create(String ttl) {
        return create(ttl, DataClassification.TRANSIENT);
    }

    /**
     * Creates a new record with the specified Duration and classification.
     *
     * @param ttl the TTL Duration
     * @param classification the data classification
     * @return a new EphemeralRecord
     */
    public static EphemeralRecord create(Duration ttl, DataClassification classification) {
        return new Builder()
            .ttl(ttl)
            .classification(classification)
            .build();
    }

    /**
     * Converts this record to a Map representation.
     *
     * @return a Map containing the record data
     */
    public Map<String, Object> toMap() {
        return Map.of(
            "id", id,
            "created_at", createdAt.toString(),
            "expires_at", expiresAt.toString(),
            "ttl_seconds", ttl.getSeconds(),
            "classification", classification.name(),
            "metadata", metadata
        );
    }

    /**
     * Creates an EphemeralRecord from a Map representation.
     *
     * @param map the Map containing record data
     * @return a new EphemeralRecord
     */
    @SuppressWarnings("unchecked")
    public static EphemeralRecord fromMap(Map<String, Object> map) {
        Builder builder = new Builder()
            .id((String) map.get("id"))
            .createdAt(Instant.parse((String) map.get("created_at")))
            .expiresAt(Instant.parse((String) map.get("expires_at")))
            .ttl(Duration.ofSeconds(((Number) map.get("ttl_seconds")).longValue()))
            .classification(DataClassification.valueOf((String) map.get("classification")));

        Object metadata = map.get("metadata");
        if (metadata instanceof Map) {
            builder.metadata((Map<String, Object>) metadata);
        }

        return builder.build();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EphemeralRecord that = (EphemeralRecord) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "EphemeralRecord{" +
            "id='" + id + '\'' +
            ", classification=" + classification +
            ", expiresAt=" + expiresAt +
            ", expired=" + isExpired() +
            '}';
    }

    /**
     * Builder for creating EphemeralRecord instances.
     */
    public static class Builder {
        private String id;
        private Instant createdAt;
        private Instant expiresAt;
        private Duration ttl;
        private DataClassification classification = DataClassification.TRANSIENT;
        private Map<String, Object> metadata;

        public Builder id(String id) {
            this.id = id;
            return this;
        }

        public Builder createdAt(Instant createdAt) {
            this.createdAt = createdAt;
            return this;
        }

        public Builder expiresAt(Instant expiresAt) {
            this.expiresAt = expiresAt;
            return this;
        }

        public Builder ttl(Duration ttl) {
            this.ttl = ttl;
            return this;
        }

        public Builder ttl(String ttl) {
            this.ttl = TTLParser.parse(ttl);
            return this;
        }

        public Builder classification(DataClassification classification) {
            this.classification = classification;
            return this;
        }

        public Builder metadata(Map<String, Object> metadata) {
            this.metadata = metadata;
            return this;
        }

        public EphemeralRecord build() {
            if (id == null) {
                id = UUID.randomUUID().toString();
            }
            if (createdAt == null) {
                createdAt = Instant.now();
            }
            if (ttl == null) {
                throw new IllegalStateException("TTL must be specified");
            }
            if (expiresAt == null) {
                expiresAt = createdAt.plus(ttl);
            }
            return new EphemeralRecord(this);
        }
    }
}
