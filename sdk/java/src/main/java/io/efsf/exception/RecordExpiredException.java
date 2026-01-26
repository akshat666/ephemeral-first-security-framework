package io.efsf.exception;

import java.time.Instant;

/**
 * Thrown when attempting to access a record that has expired.
 */
public class RecordExpiredException extends EfsfException {

    private final String recordId;
    private final Instant expiresAt;

    public RecordExpiredException(String recordId, Instant expiresAt) {
        super("Record expired: " + recordId + " (expired at " + expiresAt + ")");
        this.recordId = recordId;
        this.expiresAt = expiresAt;
    }

    public RecordExpiredException(String recordId) {
        super("Record expired: " + recordId);
        this.recordId = recordId;
        this.expiresAt = null;
    }

    public String getRecordId() {
        return recordId;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }
}
