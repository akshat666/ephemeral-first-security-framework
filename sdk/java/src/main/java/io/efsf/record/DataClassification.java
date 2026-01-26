package io.efsf.record;

import java.time.Duration;

/**
 * Classification levels for ephemeral data, each with recommended TTL ranges.
 */
public enum DataClassification {
    /**
     * Very short-lived data (seconds to hours).
     * Examples: session tokens, OTPs, temporary cache.
     */
    TRANSIENT(Duration.ofSeconds(1), Duration.ofHours(24)),

    /**
     * Short-lived data (hours to days).
     * Examples: shopping carts, temp uploads, pending transactions.
     */
    SHORT_LIVED(Duration.ofHours(1), Duration.ofDays(30)),

    /**
     * Data with legally mandated retention periods (days to years).
     * Examples: invoices, audit logs, compliance records.
     */
    RETENTION_BOUND(Duration.ofDays(1), Duration.ofDays(365 * 7)),

    /**
     * Data that must be kept indefinitely.
     * Examples: legal holds, archival records.
     * Requires explicit justification.
     */
    PERSISTENT(Duration.ofDays(365), null);

    private final Duration minTTL;
    private final Duration maxTTL;

    DataClassification(Duration minTTL, Duration maxTTL) {
        this.minTTL = minTTL;
        this.maxTTL = maxTTL;
    }

    public Duration getMinTTL() {
        return minTTL;
    }

    public Duration getMaxTTL() {
        return maxTTL;
    }

    /**
     * Validates that a TTL is within the acceptable range for this classification.
     *
     * @param ttl the TTL to validate
     * @return true if the TTL is valid for this classification
     */
    public boolean isValidTTL(Duration ttl) {
        if (ttl == null) {
            return this == PERSISTENT;
        }
        if (ttl.compareTo(minTTL) < 0) {
            return false;
        }
        return maxTTL == null || ttl.compareTo(maxTTL) <= 0;
    }
}
