package app.hideit.crypto;

import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

/**
 * Represents an encrypted payload containing ciphertext, nonce, and key reference.
 */
public final class EncryptedPayload {

    private final byte[] ciphertext;
    private final byte[] nonce;
    private final String keyId;

    public EncryptedPayload(byte[] ciphertext, byte[] nonce, String keyId) {
        this.ciphertext = Arrays.copyOf(ciphertext, ciphertext.length);
        this.nonce = Arrays.copyOf(nonce, nonce.length);
        this.keyId = Objects.requireNonNull(keyId, "keyId cannot be null");
    }

    public byte[] getCiphertext() {
        return Arrays.copyOf(ciphertext, ciphertext.length);
    }

    public byte[] getNonce() {
        return Arrays.copyOf(nonce, nonce.length);
    }

    public String getKeyId() {
        return keyId;
    }

    /**
     * Gets the total size of the encrypted data in bytes.
     *
     * @return the size in bytes
     */
    public int getSize() {
        return ciphertext.length + nonce.length;
    }

    /**
     * Converts this payload to a Map representation.
     *
     * @return a Map containing the payload data
     */
    public Map<String, Object> toMap() {
        return Map.of(
            "ciphertext", Base64.getEncoder().encodeToString(ciphertext),
            "nonce", Base64.getEncoder().encodeToString(nonce),
            "key_id", keyId
        );
    }

    /**
     * Creates an EncryptedPayload from a Map representation.
     *
     * @param map the Map containing payload data
     * @return a new EncryptedPayload
     */
    public static EncryptedPayload fromMap(Map<String, Object> map) {
        byte[] ciphertext = Base64.getDecoder().decode((String) map.get("ciphertext"));
        byte[] nonce = Base64.getDecoder().decode((String) map.get("nonce"));
        String keyId = (String) map.get("key_id");
        return new EncryptedPayload(ciphertext, nonce, keyId);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EncryptedPayload that = (EncryptedPayload) o;
        return Arrays.equals(ciphertext, that.ciphertext) &&
            Arrays.equals(nonce, that.nonce) &&
            Objects.equals(keyId, that.keyId);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(keyId);
        result = 31 * result + Arrays.hashCode(ciphertext);
        result = 31 * result + Arrays.hashCode(nonce);
        return result;
    }

    @Override
    public String toString() {
        return "EncryptedPayload{" +
            "size=" + getSize() +
            ", keyId='" + keyId + '\'' +
            '}';
    }
}
