package app.hideit.certificate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;

/**
 * A cryptographic certificate proving that data was destroyed.
 * Can be signed by an AttestationAuthority for compliance purposes.
 */
public final class DestructionCertificate {

    private final String id;
    private final Instant timestamp;
    private final ResourceInfo resource;
    private final DestructionMethod method;
    private final ChainOfCustody chainOfCustody;
    private final String authorityId;
    private String signature;

    private DestructionCertificate(Builder builder) {
        this.id = builder.id != null ? builder.id : UUID.randomUUID().toString();
        this.timestamp = builder.timestamp != null ? builder.timestamp : Instant.now();
        this.resource = Objects.requireNonNull(builder.resource, "resource is required");
        this.method = Objects.requireNonNull(builder.method, "method is required");
        this.chainOfCustody = builder.chainOfCustody;
        this.authorityId = builder.authorityId;
        this.signature = builder.signature;
    }

    public String getId() {
        return id;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public ResourceInfo getResource() {
        return resource;
    }

    public DestructionMethod getMethod() {
        return method;
    }

    public ChainOfCustody getChainOfCustody() {
        return chainOfCustody;
    }

    public String getAuthorityId() {
        return authorityId;
    }

    public String getSignature() {
        return signature;
    }

    public boolean isSigned() {
        return signature != null;
    }

    /**
     * Gets the canonical bytes for signing.
     * This ensures consistent signing across implementations.
     *
     * @return the canonical byte representation
     */
    public byte[] getCanonicalBytes() {
        StringBuilder sb = new StringBuilder();
        sb.append("EFSF-DESTRUCTION-CERTIFICATE|");
        sb.append(id).append("|");
        sb.append(timestamp.toString()).append("|");
        sb.append(resource.getResourceType()).append("|");
        sb.append(resource.getResourceId()).append("|");
        sb.append(resource.getSizeBytes()).append("|");
        sb.append(method.name());
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Computes a hash of the certificate contents.
     *
     * @return the SHA-256 hash as a Base64 string
     */
    public String computeHash() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(getCanonicalBytes());
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Sets the signature on this certificate.
     * Should only be called by AttestationAuthority.
     *
     * @param signature the signature bytes as Base64
     * @param authorityId the signing authority ID
     */
    void setSignature(String signature, String authorityId) {
        this.signature = signature;
    }

    /**
     * Converts this certificate to a Map representation.
     *
     * @return a Map containing the certificate data
     */
    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", id);
        map.put("timestamp", timestamp.toString());
        map.put("resource", resource.toMap());
        map.put("method", method.name());
        if (chainOfCustody != null) {
            map.put("chain_of_custody", chainOfCustody.toList());
        }
        if (authorityId != null) {
            map.put("authority_id", authorityId);
        }
        if (signature != null) {
            map.put("signature", signature);
        }
        map.put("hash", computeHash());
        return map;
    }

    /**
     * Creates a DestructionCertificate from a Map representation.
     *
     * @param map the Map containing certificate data
     * @return a new DestructionCertificate
     */
    @SuppressWarnings("unchecked")
    public static DestructionCertificate fromMap(Map<String, Object> map) {
        Builder builder = new Builder()
            .id((String) map.get("id"))
            .timestamp(Instant.parse((String) map.get("timestamp")))
            .resource(ResourceInfo.fromMap((Map<String, Object>) map.get("resource")))
            .method(DestructionMethod.valueOf((String) map.get("method")));

        Object chainOfCustody = map.get("chain_of_custody");
        if (chainOfCustody instanceof List) {
            builder.chainOfCustody(ChainOfCustody.fromList((List<Map<String, Object>>) chainOfCustody));
        }

        if (map.containsKey("authority_id")) {
            builder.authorityId((String) map.get("authority_id"));
        }
        if (map.containsKey("signature")) {
            builder.signature((String) map.get("signature"));
        }

        return builder.build();
    }

    @Override
    public String toString() {
        return "DestructionCertificate{" +
            "id='" + id + '\'' +
            ", timestamp=" + timestamp +
            ", resource=" + resource.getResourceId() +
            ", method=" + method +
            ", signed=" + isSigned() +
            '}';
    }

    public static class Builder {
        private String id;
        private Instant timestamp;
        private ResourceInfo resource;
        private DestructionMethod method;
        private ChainOfCustody chainOfCustody;
        private String authorityId;
        private String signature;

        public Builder id(String id) {
            this.id = id;
            return this;
        }

        public Builder timestamp(Instant timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public Builder resource(ResourceInfo resource) {
            this.resource = resource;
            return this;
        }

        public Builder method(DestructionMethod method) {
            this.method = method;
            return this;
        }

        public Builder chainOfCustody(ChainOfCustody chainOfCustody) {
            this.chainOfCustody = chainOfCustody;
            return this;
        }

        public Builder authorityId(String authorityId) {
            this.authorityId = authorityId;
            return this;
        }

        public Builder signature(String signature) {
            this.signature = signature;
            return this;
        }

        public DestructionCertificate build() {
            return new DestructionCertificate(this);
        }
    }
}
