package app.hideit.exception;

/**
 * Thrown when a cryptographic operation fails.
 */
public class CryptoException extends EfsfException {

    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
