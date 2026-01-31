package app.hideit.crypto;

import app.hideit.exception.CryptoException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Crypto Provider Tests")
class CryptoProviderTest {

    private CryptoProvider crypto;

    @BeforeEach
    void setUp() {
        crypto = new CryptoProvider();
    }

    @Test
    @DisplayName("DEK generation creates valid key")
    void testDEKGeneration() {
        DataEncryptionKey dek = crypto.generateDEK();

        assertNotNull(dek.getId());
        assertNotNull(dek.getCreatedAt());
        assertFalse(dek.isDestroyed());
        assertEquals(32, dek.getBytes().length); // 256 bits
    }

    @Test
    @DisplayName("DEK can be created from bytes")
    void testDEKFromBytes() {
        DataEncryptionKey original = crypto.generateDEK();
        byte[] keyBytes = original.getBytes();

        DataEncryptionKey restored = DataEncryptionKey.fromBytes("test-id", keyBytes);

        assertArrayEquals(original.getBytes(), restored.getBytes());
    }

    @Test
    @DisplayName("DEK can be created from Base64")
    void testDEKFromBase64() {
        DataEncryptionKey original = crypto.generateDEK();
        String base64 = original.toBase64();

        DataEncryptionKey restored = DataEncryptionKey.fromBase64("test-id", base64);

        assertArrayEquals(original.getBytes(), restored.getBytes());
    }

    @Test
    @DisplayName("DEK destruction zeros key material")
    void testDEKDestruction() {
        DataEncryptionKey dek = crypto.generateDEK();
        dek.destroy();

        assertTrue(dek.isDestroyed());
        assertThrows(CryptoException.class, dek::getBytes);
        assertThrows(CryptoException.class, dek::toSecretKey);
    }

    @Test
    @DisplayName("Encrypt and decrypt bytes")
    void testEncryptDecryptBytes() {
        DataEncryptionKey dek = crypto.generateDEK();
        byte[] plaintext = "Hello, World!".getBytes();

        EncryptedPayload payload = crypto.encrypt(plaintext, dek);
        byte[] decrypted = crypto.decrypt(payload, dek);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    @DisplayName("Encrypt and decrypt string")
    void testEncryptDecryptString() {
        DataEncryptionKey dek = crypto.generateDEK();
        String plaintext = "Hello, EFSF!";

        EncryptedPayload payload = crypto.encrypt(plaintext, dek);
        String decrypted = crypto.decryptToString(payload, dek);

        assertEquals(plaintext, decrypted);
    }

    @Test
    @DisplayName("Encrypt and decrypt JSON")
    void testEncryptDecryptJson() {
        DataEncryptionKey dek = crypto.generateDEK();
        Map<String, Object> data = Map.of("user_id", "123", "session", "abc");

        EncryptedPayload payload = crypto.encryptJson(data, dek);
        Map<?, ?> decrypted = crypto.decryptJson(payload, dek, Map.class);

        assertEquals("123", decrypted.get("user_id"));
        assertEquals("abc", decrypted.get("session"));
    }

    @Test
    @DisplayName("Different encryptions produce different ciphertexts")
    void testEncryptionRandomness() {
        DataEncryptionKey dek = crypto.generateDEK();
        String plaintext = "Same message";

        EncryptedPayload payload1 = crypto.encrypt(plaintext, dek);
        EncryptedPayload payload2 = crypto.encrypt(plaintext, dek);

        // Different nonces should produce different ciphertexts
        assertFalse(java.util.Arrays.equals(payload1.getNonce(), payload2.getNonce()));
        assertFalse(java.util.Arrays.equals(payload1.getCiphertext(), payload2.getCiphertext()));

        // But both should decrypt to the same plaintext
        assertEquals(crypto.decryptToString(payload1, dek), crypto.decryptToString(payload2, dek));
    }

    @Test
    @DisplayName("EncryptedPayload serializes to/from Map")
    void testPayloadSerialization() {
        DataEncryptionKey dek = crypto.generateDEK();
        EncryptedPayload original = crypto.encrypt("test data", dek);

        Map<String, Object> map = original.toMap();
        EncryptedPayload restored = EncryptedPayload.fromMap(map);

        assertEquals(original.getKeyId(), restored.getKeyId());
        assertArrayEquals(original.getCiphertext(), restored.getCiphertext());
        assertArrayEquals(original.getNonce(), restored.getNonce());
    }

    @Test
    @DisplayName("Decryption fails with wrong key")
    void testDecryptionWithWrongKey() {
        DataEncryptionKey dek1 = crypto.generateDEK();
        DataEncryptionKey dek2 = crypto.generateDEK();

        EncryptedPayload payload = crypto.encrypt("secret data", dek1);

        assertThrows(CryptoException.class, () -> crypto.decrypt(payload, dek2));
    }

    @Test
    @DisplayName("Key destruction makes decryption impossible")
    void testCryptoShredding() {
        DataEncryptionKey dek = crypto.generateDEK();
        String keyId = dek.getId();
        EncryptedPayload payload = crypto.encrypt("sensitive data", dek);

        // Destroy the key (crypto-shredding)
        assertTrue(crypto.destroyKey(keyId));

        // Decryption should fail
        assertThrows(CryptoException.class, () -> crypto.decrypt(payload, dek));
    }

    @Test
    @DisplayName("Crypto provider tracks active keys")
    void testKeyTracking() {
        assertEquals(0, crypto.getKeyCount());

        crypto.generateDEK();
        crypto.generateDEK();
        assertEquals(2, crypto.getKeyCount());

        crypto.destroyAllKeys();
        assertEquals(0, crypto.getKeyCount());
    }
}
