/**
 * EFSF Cryptographic Operations
 *
 * Provides encryption, decryption, and key management for ephemeral data.
 * Uses AES-256-GCM for authenticated encryption via Node.js crypto module.
 */

import * as crypto from 'crypto';
import { CryptoError } from './exceptions.js';

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32; // 256 bits
const NONCE_LENGTH = 12; // 96 bits for GCM
const TAG_LENGTH = 16; // 128 bits

/**
 * Serialized format for encrypted payloads.
 */
export interface EncryptedPayloadData {
  ciphertext: string;
  nonce: string;
  key_id: string;
  algorithm: string;
}

/**
 * Container for encrypted data with all necessary decryption metadata.
 */
export class EncryptedPayload {
  constructor(
    public readonly ciphertext: string, // base64 encoded (includes auth tag)
    public readonly nonce: string, // base64 encoded
    public readonly keyId: string,
    public readonly algorithm: string = 'AES-256-GCM'
  ) {}

  /**
   * Convert to a plain object for serialization.
   */
  toDict(): EncryptedPayloadData {
    return {
      ciphertext: this.ciphertext,
      nonce: this.nonce,
      key_id: this.keyId,
      algorithm: this.algorithm,
    };
  }

  /**
   * Reconstruct from serialized data.
   */
  static fromDict(data: EncryptedPayloadData): EncryptedPayload {
    return new EncryptedPayload(
      data.ciphertext,
      data.nonce,
      data.key_id,
      data.algorithm ?? 'AES-256-GCM'
    );
  }
}

/**
 * Data Encryption Key (DEK) with lifecycle tracking.
 *
 * Each DEK is tied to the TTL of the data it protects. When the DEK
 * is destroyed (crypto-shredding), all data encrypted with it becomes
 * permanently unrecoverable.
 */
export class DataEncryptionKey {
  private _destroyed = false;
  private _destroyedAt: Date | null = null;

  constructor(
    public readonly keyId: string,
    private _keyMaterial: Buffer,
    public readonly createdAt: Date,
    public readonly expiresAt: Date
  ) {}

  /**
   * Generate a new DEK with the specified TTL.
   *
   * @param ttlMs - Time-to-live in milliseconds
   * @param keyId - Optional key identifier (auto-generated if not provided)
   */
  static generate(ttlMs: number, keyId?: string): DataEncryptionKey {
    const now = new Date();
    return new DataEncryptionKey(
      keyId ?? crypto.randomBytes(16).toString('hex'),
      crypto.randomBytes(KEY_LENGTH),
      now,
      new Date(now.getTime() + ttlMs)
    );
  }

  /**
   * Get the key material for cryptographic operations.
   * @throws CryptoError if the key has been destroyed
   */
  get keyMaterial(): Buffer {
    if (this._destroyed) {
      throw new CryptoError('access', 'Key has been destroyed');
    }
    return this._keyMaterial;
  }

  /**
   * Check if the key has been destroyed.
   */
  get destroyed(): boolean {
    return this._destroyed;
  }

  /**
   * Get the timestamp when the key was destroyed, if applicable.
   */
  get destroyedAt(): Date | null {
    return this._destroyedAt;
  }

  /**
   * Check if the key is expired or destroyed.
   */
  get isExpired(): boolean {
    return new Date() >= this.expiresAt || this._destroyed;
  }

  /**
   * Securely destroy the key material (crypto-shredding).
   *
   * This overwrites the key material with random data then zeros,
   * making any data encrypted with this key permanently unrecoverable.
   *
   * Note: In JavaScript/Node.js, we cannot guarantee memory is fully
   * zeroed due to garbage collection. This is best-effort. For true
   * security guarantees, use hardware security modules (HSM).
   */
  destroy(): void {
    // Overwrite with random data then zeros (best effort)
    crypto.randomFillSync(this._keyMaterial);
    this._keyMaterial.fill(0);
    this._destroyed = true;
    this._destroyedAt = new Date();
  }
}

/**
 * Cryptographic provider for ephemeral data encryption.
 *
 * Manages Data Encryption Keys (DEKs) and provides AES-256-GCM
 * authenticated encryption for protecting ephemeral data.
 */
export class CryptoProvider {
  private readonly masterKey: Buffer;
  private readonly keys: Map<string, DataEncryptionKey> = new Map();

  /**
   * Create a new CryptoProvider.
   *
   * @param masterKey - Optional master key for key derivation.
   *                    If not provided, a random key is generated.
   *                    In production, this should come from a KMS.
   */
  constructor(masterKey?: Buffer) {
    this.masterKey = masterKey ?? crypto.randomBytes(KEY_LENGTH);
  }

  /**
   * Generate a new Data Encryption Key with the specified TTL.
   *
   * @param ttlMs - Time-to-live in milliseconds
   * @returns The generated DEK
   */
  generateDEK(ttlMs: number): DataEncryptionKey {
    const dek = DataEncryptionKey.generate(ttlMs);
    this.keys.set(dek.keyId, dek);
    return dek;
  }

  /**
   * Retrieve a DEK by its identifier.
   *
   * @param keyId - The key identifier
   * @returns The DEK if found and valid, null otherwise
   */
  getDEK(keyId: string): DataEncryptionKey | null {
    const dek = this.keys.get(keyId);
    if (!dek || dek.destroyed || dek.isExpired) {
      return null;
    }
    return dek;
  }

  /**
   * Destroy a DEK (crypto-shredding).
   *
   * After destruction, any data encrypted with this key becomes
   * permanently unrecoverable.
   *
   * @param keyId - The key identifier
   * @returns true if the key was found and destroyed, false otherwise
   */
  destroyDEK(keyId: string): boolean {
    const dek = this.keys.get(keyId);
    if (dek) {
      dek.destroy();
      return true;
    }
    return false;
  }

  /**
   * Encrypt plaintext using AES-256-GCM.
   *
   * @param plaintext - The data to encrypt
   * @param dek - The Data Encryption Key to use
   * @param associatedData - Optional additional authenticated data (AAD)
   * @returns The encrypted payload
   * @throws CryptoError if the key is destroyed or expired
   */
  encrypt(
    plaintext: Buffer,
    dek: DataEncryptionKey,
    associatedData?: Buffer
  ): EncryptedPayload {
    if (dek.destroyed || dek.isExpired) {
      throw new CryptoError('encrypt', 'Key is destroyed or expired');
    }

    try {
      const nonce = crypto.randomBytes(NONCE_LENGTH);
      const cipher = crypto.createCipheriv(ALGORITHM, dek.keyMaterial, nonce, {
        authTagLength: TAG_LENGTH,
      });

      if (associatedData) {
        cipher.setAAD(associatedData);
      }

      const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const authTag = cipher.getAuthTag();

      // Combine ciphertext and auth tag for storage
      const combined = Buffer.concat([encrypted, authTag]);

      return new EncryptedPayload(
        combined.toString('base64'),
        nonce.toString('base64'),
        dek.keyId
      );
    } catch (e) {
      throw new CryptoError('encrypt', String(e));
    }
  }

  /**
   * Decrypt an encrypted payload.
   *
   * @param payload - The encrypted payload to decrypt
   * @param associatedData - Optional additional authenticated data (must match encryption)
   * @returns The decrypted plaintext
   * @throws CryptoError if decryption fails or key is unavailable
   */
  decrypt(payload: EncryptedPayload, associatedData?: Buffer): Buffer {
    const dek = this.getDEK(payload.keyId);
    if (!dek) {
      throw new CryptoError(
        'decrypt',
        `Key ${payload.keyId} not found or destroyed (data is unrecoverable)`
      );
    }

    try {
      const combined = Buffer.from(payload.ciphertext, 'base64');
      const nonce = Buffer.from(payload.nonce, 'base64');

      // Split ciphertext and auth tag
      const ciphertext = combined.subarray(0, combined.length - TAG_LENGTH);
      const authTag = combined.subarray(combined.length - TAG_LENGTH);

      const decipher = crypto.createDecipheriv(ALGORITHM, dek.keyMaterial, nonce, {
        authTagLength: TAG_LENGTH,
      });

      decipher.setAuthTag(authTag);

      if (associatedData) {
        decipher.setAAD(associatedData);
      }

      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch (e) {
      throw new CryptoError('decrypt', String(e));
    }
  }

  /**
   * Encrypt a JSON-serializable object.
   *
   * @param data - The object to encrypt
   * @param dek - The Data Encryption Key to use
   * @returns The encrypted payload
   */
  encryptJSON(data: Record<string, unknown>, dek: DataEncryptionKey): EncryptedPayload {
    const plaintext = Buffer.from(JSON.stringify(data), 'utf-8');
    return this.encrypt(plaintext, dek);
  }

  /**
   * Decrypt a payload and parse as JSON.
   *
   * @param payload - The encrypted payload
   * @returns The decrypted object
   */
  decryptJSON(payload: EncryptedPayload): Record<string, unknown> {
    const plaintext = this.decrypt(payload);
    return JSON.parse(plaintext.toString('utf-8')) as Record<string, unknown>;
  }

  /**
   * Derive a key from the master key using HKDF.
   *
   * @param context - Context bytes for domain separation
   * @param length - Desired key length in bytes (default: 32)
   * @returns The derived key material
   */
  deriveKey(context: Buffer, length: number = KEY_LENGTH): Buffer {
    return Buffer.from(
      crypto.hkdfSync('sha256', this.masterKey, Buffer.alloc(0), context, length)
    );
  }
}

/**
 * Compare two buffers in constant time to prevent timing attacks.
 *
 * @param a - First buffer
 * @param b - Second buffer
 * @returns true if buffers are equal, false otherwise
 */
export function constantTimeCompare(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}
