package io.efsf.exception;

/**
 * Thrown when attempting to access a record that does not exist.
 */
public class RecordNotFoundException extends EfsfException {

    private final String recordId;

    public RecordNotFoundException(String recordId) {
        super("Record not found: " + recordId);
        this.recordId = recordId;
    }

    public RecordNotFoundException(String recordId, Throwable cause) {
        super("Record not found: " + recordId, cause);
        this.recordId = recordId;
    }

    public String getRecordId() {
        return recordId;
    }
}
