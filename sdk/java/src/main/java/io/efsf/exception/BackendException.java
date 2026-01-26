package io.efsf.exception;

/**
 * Thrown when a storage backend operation fails.
 */
public class BackendException extends EfsfException {

    public BackendException(String message) {
        super(message);
    }

    public BackendException(String message, Throwable cause) {
        super(message, cause);
    }
}
