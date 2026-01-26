import { describe, it, expect } from 'vitest';
import {
  CryptoProvider,
  DataEncryptionKey,
  EncryptedPayload,
  constantTimeCompare,
} from '../src/crypto.js';
import { CryptoError } from '../src/exceptions.js';

describe('DataEncryptionKey', () => {
  it('should generate a key with TTL', () => {
    const dek = DataEncryptionKey.generate(60 * 60 * 1000); // 1 hour

    expect(dek.keyId).toBeDefined();
    expect(dek.keyMaterial).toBeInstanceOf(Buffer);
    expect(dek.keyMaterial.length).toBe(32); // 256 bits
    expect(dek.createdAt).toBeInstanceOf(Date);
    expect(dek.expiresAt).toBeInstanceOf(Date);
    expect(dek.destroyed).toBe(false);
    expect(dek.isExpired).toBe(false);
  });

  it('should accept custom key ID', () => {
    const dek = DataEncryptionKey.generate(60000, 'custom-key-id');
    expect(dek.keyId).toBe('custom-key-id');
  });

  it('should destroy key material', () => {
    const dek = DataEncryptionKey.generate(60000);
    const keyMaterial = dek.keyMaterial;

    dek.destroy();

    expect(dek.destroyed).toBe(true);
    expect(dek.destroyedAt).toBeInstanceOf(Date);
    expect(dek.isExpired).toBe(true);

    // Accessing key material after destruction should throw
    expect(() => dek.keyMaterial).toThrow(CryptoError);
  });
});

describe('EncryptedPayload', () => {
  it('should serialize and deserialize', () => {
    const payload = new EncryptedPayload('ciphertext123', 'nonce456', 'key-id-789');

    const data = payload.toDict();
    expect(data).toEqual({
      ciphertext: 'ciphertext123',
      nonce: 'nonce456',
      key_id: 'key-id-789',
      algorithm: 'AES-256-GCM',
    });

    const restored = EncryptedPayload.fromDict(data);
    expect(restored.ciphertext).toBe(payload.ciphertext);
    expect(restored.nonce).toBe(payload.nonce);
    expect(restored.keyId).toBe(payload.keyId);
    expect(restored.algorithm).toBe(payload.algorithm);
  });
});

describe('CryptoProvider', () => {
  it('should generate and retrieve DEKs', () => {
    const crypto = new CryptoProvider();
    const dek = crypto.generateDEK(60000);

    expect(dek.keyId).toBeDefined();

    const retrieved = crypto.getDEK(dek.keyId);
    expect(retrieved).toBe(dek);
  });

  it('should return null for non-existent DEK', () => {
    const crypto = new CryptoProvider();
    const result = crypto.getDEK('non-existent');
    expect(result).toBeNull();
  });

  it('should destroy DEKs', () => {
    const crypto = new CryptoProvider();
    const dek = crypto.generateDEK(60000);

    const destroyed = crypto.destroyDEK(dek.keyId);
    expect(destroyed).toBe(true);

    const retrieved = crypto.getDEK(dek.keyId);
    expect(retrieved).toBeNull();
  });

  it('should encrypt and decrypt data', () => {
    const crypto = new CryptoProvider();
    const dek = crypto.generateDEK(60000);

    const plaintext = Buffer.from('Hello, World!', 'utf-8');
    const payload = crypto.encrypt(plaintext, dek);

    expect(payload.ciphertext).toBeDefined();
    expect(payload.nonce).toBeDefined();
    expect(payload.keyId).toBe(dek.keyId);

    const decrypted = crypto.decrypt(payload);
    expect(decrypted.toString('utf-8')).toBe('Hello, World!');
  });

  it('should encrypt and decrypt JSON', () => {
    const crypto = new CryptoProvider();
    const dek = crypto.generateDEK(60000);

    const data = { user_id: '123', session: 'abc', nested: { value: 42 } };
    const payload = crypto.encryptJSON(data, dek);

    const decrypted = crypto.decryptJSON(payload);
    expect(decrypted).toEqual(data);
  });

  it('should fail decryption after key destruction', () => {
    const crypto = new CryptoProvider();
    const dek = crypto.generateDEK(60000);

    const plaintext = Buffer.from('Sensitive data', 'utf-8');
    const payload = crypto.encrypt(plaintext, dek);

    // Destroy the key
    crypto.destroyDEK(dek.keyId);

    // Decryption should fail
    expect(() => crypto.decrypt(payload)).toThrow(CryptoError);
    expect(() => crypto.decrypt(payload)).toThrow(/not found or destroyed/);
  });

  it('should fail encryption with destroyed key', () => {
    const crypto = new CryptoProvider();
    const dek = crypto.generateDEK(60000);
    dek.destroy();

    const plaintext = Buffer.from('test', 'utf-8');
    expect(() => crypto.encrypt(plaintext, dek)).toThrow(CryptoError);
  });

  it('should support associated data', () => {
    const crypto = new CryptoProvider();
    const dek = crypto.generateDEK(60000);

    const plaintext = Buffer.from('secret', 'utf-8');
    const aad = Buffer.from('context', 'utf-8');

    const payload = crypto.encrypt(plaintext, dek, aad);

    // Should succeed with matching AAD
    const decrypted = crypto.decrypt(payload, aad);
    expect(decrypted.toString('utf-8')).toBe('secret');

    // Should fail with wrong AAD
    expect(() => crypto.decrypt(payload, Buffer.from('wrong', 'utf-8'))).toThrow(CryptoError);
  });

  it('should derive keys consistently', () => {
    const masterKey = Buffer.alloc(32, 0x42);
    const crypto = new CryptoProvider(masterKey);

    const context = Buffer.from('test-context', 'utf-8');
    const key1 = crypto.deriveKey(context);
    const key2 = crypto.deriveKey(context);

    expect(key1).toEqual(key2);
    expect(key1.length).toBe(32);
  });
});

describe('constantTimeCompare', () => {
  it('should return true for equal buffers', () => {
    const a = Buffer.from('hello');
    const b = Buffer.from('hello');
    expect(constantTimeCompare(a, b)).toBe(true);
  });

  it('should return false for different buffers', () => {
    const a = Buffer.from('hello');
    const b = Buffer.from('world');
    expect(constantTimeCompare(a, b)).toBe(false);
  });

  it('should return false for different lengths', () => {
    const a = Buffer.from('hello');
    const b = Buffer.from('hi');
    expect(constantTimeCompare(a, b)).toBe(false);
  });
});
