package io.efsf.exception;

/**
 * Base exception for all EFSF-related errors.
 */
public class EfsfException extends RuntimeException {

    public EfsfException(String message) {
        super(message);
    }

    public EfsfException(String message, Throwable cause) {
        super(message, cause);
    }
}
