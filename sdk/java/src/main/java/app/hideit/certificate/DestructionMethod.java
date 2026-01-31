package app.hideit.certificate;

/**
 * Methods used to destroy ephemeral data.
 */
public enum DestructionMethod {
    /**
     * Memory zeroing - overwriting memory with zeros.
     */
    MEMORY_ZERO,

    /**
     * Key destruction - destroying the encryption key (crypto-shredding).
     */
    KEY_DESTRUCTION,

    /**
     * Secure deletion from storage.
     */
    SECURE_DELETE,

    /**
     * TTL expiration - automatic deletion after TTL.
     */
    TTL_EXPIRATION,

    /**
     * Hardware-backed secure deletion (e.g., TPM, HSM).
     */
    HARDWARE_SECURE_DELETE
}
