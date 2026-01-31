package app.hideit.crypto;

import app.hideit.exception.CryptoException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

/**
 * A Data Encryption Key (DEK) with lifecycle management and secure destruction.
 */
public final class DataEncryptionKey {

    private static final String ALGORITHM = "AES";
    private static final int KEY_SIZE_BYTES = 32; // 256 bits

    private final String id;
    private final Instant createdAt;
    private byte[] keyMaterial;
    private boolean destroyed;

    private DataEncryptionKey(String id, byte[] keyMaterial, Instant createdAt) {
        this.id = id;
        this.keyMaterial = keyMaterial;
        this.createdAt = createdAt;
        this.destroyed = false;
    }

    /**
     * Generates a new random DEK.
     *
     * @return a new DataEncryptionKey
     */
    public static DataEncryptionKey generate() {
        SecureRandom random = new SecureRandom();
        byte[] keyMaterial = new byte[KEY_SIZE_BYTES];
        random.nextBytes(keyMaterial);
        return new DataEncryptionKey(
            UUID.randomUUID().toString(),
            keyMaterial,
            Instant.now()
        );
    }

    /**
     * Creates a DEK from existing key material.
     *
     * @param id the key ID
     * @param keyMaterial the raw key bytes
     * @return a new DataEncryptionKey
     */
    public static DataEncryptionKey fromBytes(String id, byte[] keyMaterial) {
        if (keyMaterial.length != KEY_SIZE_BYTES) {
            throw new CryptoException("Invalid key size: expected " + KEY_SIZE_BYTES + " bytes, got " + keyMaterial.length);
        }
        return new DataEncryptionKey(id, Arrays.copyOf(keyMaterial, keyMaterial.length), Instant.now());
    }

    /**
     * Creates a DEK from a Base64-encoded string.
     *
     * @param id the key ID
     * @param base64Key the Base64-encoded key
     * @return a new DataEncryptionKey
     */
    public static DataEncryptionKey fromBase64(String id, String base64Key) {
        byte[] keyMaterial = Base64.getDecoder().decode(base64Key);
        return fromBytes(id, keyMaterial);
    }

    public String getId() {
        return id;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public boolean isDestroyed() {
        return destroyed;
    }

    /**
     * Gets the key as a SecretKey for use with JCE.
     *
     * @return the SecretKey
     * @throws CryptoException if the key has been destroyed
     */
    public SecretKey toSecretKey() {
        ensureNotDestroyed();
        return new SecretKeySpec(keyMaterial, ALGORITHM);
    }

    /**
     * Gets the raw key bytes.
     *
     * @return a copy of the key material
     * @throws CryptoException if the key has been destroyed
     */
    public byte[] getBytes() {
        ensureNotDestroyed();
        return Arrays.copyOf(keyMaterial, keyMaterial.length);
    }

    /**
     * Gets the key as a Base64-encoded string.
     *
     * @return the Base64-encoded key
     * @throws CryptoException if the key has been destroyed
     */
    public String toBase64() {
        ensureNotDestroyed();
        return Base64.getEncoder().encodeToString(keyMaterial);
    }

    /**
     * Securely destroys the key material by overwriting it with zeros.
     * After calling this method, the key cannot be used.
     */
    public void destroy() {
        if (!destroyed && keyMaterial != null) {
            Arrays.fill(keyMaterial, (byte) 0);
            keyMaterial = null;
            destroyed = true;
        }
    }

    private void ensureNotDestroyed() {
        if (destroyed) {
            throw new CryptoException("Key has been destroyed: " + id);
        }
    }

    @Override
    public String toString() {
        return "DataEncryptionKey{" +
            "id='" + id + '\'' +
            ", createdAt=" + createdAt +
            ", destroyed=" + destroyed +
            '}';
    }
}
