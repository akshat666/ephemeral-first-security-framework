package io.efsf.crypto;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.efsf.exception.CryptoException;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Provides AES-256-GCM encryption with per-record DEK management.
 */
public final class CryptoProvider {

    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_NONCE_LENGTH = 12; // 96 bits
    private static final int GCM_TAG_LENGTH = 128; // bits

    private final Map<String, DataEncryptionKey> keyStore;
    private final SecureRandom secureRandom;
    private final ObjectMapper objectMapper;

    public CryptoProvider() {
        this.keyStore = new ConcurrentHashMap<>();
        this.secureRandom = new SecureRandom();
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Generates a new DEK and stores it for later use.
     *
     * @return the generated DEK
     */
    public DataEncryptionKey generateDEK() {
        DataEncryptionKey dek = DataEncryptionKey.generate();
        keyStore.put(dek.getId(), dek);
        return dek;
    }

    /**
     * Registers an existing DEK with this provider.
     *
     * @param dek the DEK to register
     */
    public void registerKey(DataEncryptionKey dek) {
        keyStore.put(dek.getId(), dek);
    }

    /**
     * Gets a DEK by its ID.
     *
     * @param keyId the key ID
     * @return the DEK, or null if not found
     */
    public DataEncryptionKey getKey(String keyId) {
        return keyStore.get(keyId);
    }

    /**
     * Encrypts data using AES-256-GCM.
     *
     * @param plaintext the data to encrypt
     * @param dek the DEK to use
     * @return the encrypted payload
     */
    public EncryptedPayload encrypt(byte[] plaintext, DataEncryptionKey dek) {
        try {
            byte[] nonce = new byte[GCM_NONCE_LENGTH];
            secureRandom.nextBytes(nonce);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, dek.toSecretKey(), spec);

            byte[] ciphertext = cipher.doFinal(plaintext);

            return new EncryptedPayload(ciphertext, nonce, dek.getId());
        } catch (Exception e) {
            throw new CryptoException("Encryption failed", e);
        }
    }

    /**
     * Encrypts a string using AES-256-GCM.
     *
     * @param plaintext the string to encrypt
     * @param dek the DEK to use
     * @return the encrypted payload
     */
    public EncryptedPayload encrypt(String plaintext, DataEncryptionKey dek) {
        return encrypt(plaintext.getBytes(StandardCharsets.UTF_8), dek);
    }

    /**
     * Encrypts an object as JSON using AES-256-GCM.
     *
     * @param data the object to encrypt
     * @param dek the DEK to use
     * @return the encrypted payload
     */
    public EncryptedPayload encryptJson(Object data, DataEncryptionKey dek) {
        try {
            String json = objectMapper.writeValueAsString(data);
            return encrypt(json, dek);
        } catch (JsonProcessingException e) {
            throw new CryptoException("JSON serialization failed", e);
        }
    }

    /**
     * Decrypts data using AES-256-GCM.
     *
     * @param payload the encrypted payload
     * @param dek the DEK to use
     * @return the decrypted data
     */
    public byte[] decrypt(EncryptedPayload payload, DataEncryptionKey dek) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, payload.getNonce());
            cipher.init(Cipher.DECRYPT_MODE, dek.toSecretKey(), spec);

            return cipher.doFinal(payload.getCiphertext());
        } catch (Exception e) {
            throw new CryptoException("Decryption failed", e);
        }
    }

    /**
     * Decrypts data to a string using AES-256-GCM.
     *
     * @param payload the encrypted payload
     * @param dek the DEK to use
     * @return the decrypted string
     */
    public String decryptToString(EncryptedPayload payload, DataEncryptionKey dek) {
        byte[] plaintext = decrypt(payload, dek);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    /**
     * Decrypts data using the stored key referenced in the payload.
     *
     * @param payload the encrypted payload
     * @return the decrypted data
     */
    public byte[] decrypt(EncryptedPayload payload) {
        DataEncryptionKey dek = keyStore.get(payload.getKeyId());
        if (dek == null) {
            throw new CryptoException("Key not found: " + payload.getKeyId());
        }
        return decrypt(payload, dek);
    }

    /**
     * Decrypts JSON data and deserializes it.
     *
     * @param payload the encrypted payload
     * @param dek the DEK to use
     * @param type the class to deserialize to
     * @return the decrypted and deserialized object
     */
    public <T> T decryptJson(EncryptedPayload payload, DataEncryptionKey dek, Class<T> type) {
        try {
            String json = decryptToString(payload, dek);
            return objectMapper.readValue(json, type);
        } catch (JsonProcessingException e) {
            throw new CryptoException("JSON deserialization failed", e);
        }
    }

    /**
     * Destroys a key by its ID (crypto-shredding).
     *
     * @param keyId the key ID to destroy
     * @return true if the key was destroyed, false if not found
     */
    public boolean destroyKey(String keyId) {
        DataEncryptionKey dek = keyStore.remove(keyId);
        if (dek != null) {
            dek.destroy();
            return true;
        }
        return false;
    }

    /**
     * Gets the number of active keys.
     *
     * @return the key count
     */
    public int getKeyCount() {
        return keyStore.size();
    }

    /**
     * Destroys all keys managed by this provider.
     */
    public void destroyAllKeys() {
        for (DataEncryptionKey dek : keyStore.values()) {
            dek.destroy();
        }
        keyStore.clear();
    }
}
