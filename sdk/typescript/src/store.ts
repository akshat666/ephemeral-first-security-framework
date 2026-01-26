/**
 * EFSF Ephemeral Store
 *
 * The primary interface for storing and retrieving ephemeral data
 * with automatic TTL enforcement and crypto-shredding.
 */

import {
  AttestationAuthority,
  ChainOfCustody,
  DestructionCertificate,
  DestructionMethod,
} from './certificate.js';
import { CryptoProvider, EncryptedPayload } from './crypto.js';
import {
  BackendError,
  RecordExpiredError,
  RecordNotFoundError,
  ValidationError,
} from './exceptions.js';
import {
  DataClassification,
  EphemeralRecord,
  EphemeralRecordData,
  parseTTL,
} from './record.js';

// ============================================================
// Storage Backend Interface
// ============================================================

/**
 * Interface for pluggable storage backends.
 *
 * Implementations must support TTL-based expiration.
 */
export interface StorageBackend {
  /**
   * Store a value with TTL.
   * @param key - Storage key
   * @param value - Value to store (JSON string)
   * @param ttlSeconds - Time-to-live in seconds
   */
  set(key: string, value: string, ttlSeconds: number): Promise<boolean>;

  /**
   * Retrieve a value by key.
   * @param key - Storage key
   * @returns The value or null if not found/expired
   */
  get(key: string): Promise<string | null>;

  /**
   * Delete a value by key.
   * @param key - Storage key
   * @returns true if deleted, false if not found
   */
  delete(key: string): Promise<boolean>;

  /**
   * Check if a key exists.
   * @param key - Storage key
   */
  exists(key: string): Promise<boolean>;

  /**
   * Get remaining TTL in seconds.
   * @param key - Storage key
   * @returns Remaining seconds or null if not found
   */
  ttl(key: string): Promise<number | null>;

  /**
   * Close the backend and release resources.
   */
  close(): Promise<void>;
}

// ============================================================
// Memory Backend
// ============================================================

interface MemoryEntry {
  value: string;
  expiresAt: number; // timestamp in ms
}

/**
 * In-memory storage backend for testing and development.
 *
 * TTL is enforced on access (not automatically expired).
 */
export class MemoryBackend implements StorageBackend {
  private readonly data: Map<string, MemoryEntry> = new Map();

  async set(key: string, value: string, ttlSeconds: number): Promise<boolean> {
    this.data.set(key, {
      value,
      expiresAt: Date.now() + ttlSeconds * 1000,
    });
    return true;
  }

  async get(key: string): Promise<string | null> {
    const entry = this.data.get(key);
    if (!entry) {
      return null;
    }
    if (Date.now() >= entry.expiresAt) {
      this.data.delete(key);
      return null;
    }
    return entry.value;
  }

  async delete(key: string): Promise<boolean> {
    return this.data.delete(key);
  }

  async exists(key: string): Promise<boolean> {
    const value = await this.get(key);
    return value !== null;
  }

  async ttl(key: string): Promise<number | null> {
    const entry = this.data.get(key);
    if (!entry) {
      return null;
    }
    const remaining = Math.floor((entry.expiresAt - Date.now()) / 1000);
    return Math.max(0, remaining);
  }

  async close(): Promise<void> {
    this.data.clear();
  }
}

// ============================================================
// Redis Backend
// ============================================================

/**
 * Redis storage backend for production use.
 *
 * Uses native Redis TTL for automatic expiration.
 * Requires the 'ioredis' package.
 */
export class RedisBackend implements StorageBackend {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private client: any;
  private readonly prefix = 'efsf:';

  constructor(url: string, options?: Record<string, unknown>) {
    try {
      // Dynamic import of ioredis
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const Redis = require('ioredis');
      this.client = new Redis(url, options);
    } catch {
      throw new BackendError(
        'redis',
        'ioredis package not installed. Install with: npm install ioredis'
      );
    }
  }

  private key(k: string): string {
    return `${this.prefix}${k}`;
  }

  async set(key: string, value: string, ttlSeconds: number): Promise<boolean> {
    try {
      await this.client.setex(this.key(key), ttlSeconds, value);
      return true;
    } catch (e) {
      throw new BackendError('redis', `Failed to set: ${e}`);
    }
  }

  async get(key: string): Promise<string | null> {
    try {
      return await this.client.get(this.key(key));
    } catch (e) {
      throw new BackendError('redis', `Failed to get: ${e}`);
    }
  }

  async delete(key: string): Promise<boolean> {
    try {
      const result = await this.client.del(this.key(key));
      return result > 0;
    } catch (e) {
      throw new BackendError('redis', `Failed to delete: ${e}`);
    }
  }

  async exists(key: string): Promise<boolean> {
    try {
      const result = await this.client.exists(this.key(key));
      return result > 0;
    } catch (e) {
      throw new BackendError('redis', `Failed to check exists: ${e}`);
    }
  }

  async ttl(key: string): Promise<number | null> {
    try {
      const result = await this.client.ttl(this.key(key));
      return result > 0 ? result : null;
    } catch (e) {
      throw new BackendError('redis', `Failed to get TTL: ${e}`);
    }
  }

  async close(): Promise<void> {
    await this.client.quit();
  }
}

// ============================================================
// Backend Factory
// ============================================================

/**
 * Create a storage backend from a URL.
 *
 * Supported schemes:
 * - memory:// - In-memory storage (for testing)
 * - redis://host:port/db - Redis storage
 * - rediss://host:port/db - Redis over TLS
 *
 * @param backendUrl - Backend URL
 * @returns Storage backend instance
 */
export function createBackend(backendUrl: string): StorageBackend {
  if (backendUrl === 'memory://' || backendUrl === 'memory') {
    return new MemoryBackend();
  }

  const url = new URL(backendUrl);
  if (url.protocol === 'redis:' || url.protocol === 'rediss:') {
    return new RedisBackend(backendUrl);
  }

  throw new ValidationError('backend', `Unsupported backend scheme: ${url.protocol}`);
}

// ============================================================
// Storage Payload
// ============================================================

interface StoragePayload {
  record: EphemeralRecordData;
  encrypted: {
    ciphertext: string;
    nonce: string;
    key_id: string;
    algorithm: string;
  };
}

// ============================================================
// Ephemeral Store Options
// ============================================================

/**
 * Options for creating an EphemeralStore.
 */
export interface EphemeralStoreOptions {
  /** Backend URL or instance */
  backend?: string | StorageBackend;
  /** Default TTL (string like "1h" or milliseconds) */
  defaultTTL?: string | number;
  /** Enable destruction certificate generation */
  attestation?: boolean;
  /** Custom crypto provider */
  cryptoProvider?: CryptoProvider;
  /** Custom attestation authority */
  attestationAuthority?: AttestationAuthority;
}

/**
 * Options for the put() method.
 */
export interface PutOptions {
  /** TTL (string like "30m" or milliseconds) */
  ttl?: string | number;
  /** Data classification level */
  classification?: DataClassification | string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Store statistics.
 */
export interface StoreStats {
  /** Number of active (non-expired) records */
  activeRecords: number;
  /** Number of destruction certificates issued */
  certificatesIssued: number;
  /** Whether attestation is enabled */
  attestationEnabled: boolean;
}

// ============================================================
// Ephemeral Store
// ============================================================

/**
 * The primary interface for storing and retrieving ephemeral data.
 *
 * Features:
 * - Automatic encryption with per-record keys (AES-256-GCM)
 * - TTL enforcement with crypto-shredding on expiration
 * - Destruction certificates for compliance
 * - Chain of custody tracking
 *
 * @example
 * ```typescript
 * const store = new EphemeralStore({
 *   backend: 'memory://',
 *   defaultTTL: '1h',
 *   attestation: true,
 * });
 *
 * // Store sensitive data
 * const record = await store.put(
 *   { user_id: '123', token: 'secret' },
 *   { ttl: '30m', classification: DataClassification.TRANSIENT }
 * );
 *
 * // Retrieve data
 * const data = await store.get(record.id);
 *
 * // Destroy with certificate
 * const cert = await store.destroy(record.id);
 * ```
 */
export class EphemeralStore {
  private readonly backend: StorageBackend;
  private readonly defaultTTL: number; // ms
  private readonly crypto: CryptoProvider;
  private readonly attestationEnabled: boolean;
  private readonly authority: AttestationAuthority | null;
  private readonly records: Map<string, EphemeralRecord> = new Map();
  private readonly custody: Map<string, ChainOfCustody> = new Map();
  private readonly certificates: Map<string, DestructionCertificate> = new Map();

  constructor(options: EphemeralStoreOptions = {}) {
    // Initialize backend
    if (typeof options.backend === 'string') {
      this.backend = createBackend(options.backend);
    } else if (options.backend) {
      this.backend = options.backend;
    } else {
      this.backend = new MemoryBackend();
    }

    // Parse default TTL
    if (typeof options.defaultTTL === 'string') {
      this.defaultTTL = parseTTL(options.defaultTTL);
    } else if (typeof options.defaultTTL === 'number') {
      this.defaultTTL = options.defaultTTL;
    } else {
      this.defaultTTL = 60 * 60 * 1000; // 1 hour default
    }

    // Initialize crypto
    this.crypto = options.cryptoProvider ?? new CryptoProvider();

    // Initialize attestation
    this.attestationEnabled = options.attestation ?? true;
    if (this.attestationEnabled) {
      this.authority = options.attestationAuthority ?? new AttestationAuthority();
    } else {
      this.authority = null;
    }
  }

  /**
   * Store data with automatic encryption and TTL.
   *
   * @param data - Data to store (must be JSON-serializable)
   * @param options - Storage options (TTL, classification, metadata)
   * @returns The ephemeral record metadata
   */
  async put(
    data: Record<string, unknown>,
    options: PutOptions = {}
  ): Promise<EphemeralRecord> {
    // Parse classification
    let classification: DataClassification;
    if (typeof options.classification === 'string') {
      classification = options.classification as DataClassification;
    } else {
      classification = options.classification ?? DataClassification.TRANSIENT;
    }

    // Parse TTL
    let effectiveTTL: number;
    if (options.ttl === undefined) {
      effectiveTTL = this.defaultTTL;
    } else if (typeof options.ttl === 'string') {
      effectiveTTL = parseTTL(options.ttl);
    } else {
      effectiveTTL = options.ttl;
    }

    // Create record
    const record = EphemeralRecord.create({
      classification,
      ttl: effectiveTTL,
      metadata: options.metadata,
    });

    // Generate DEK with same TTL as data
    const dek = this.crypto.generateDEK(effectiveTTL);
    record.keyId = dek.keyId;

    // Encrypt data
    const encrypted = this.crypto.encryptJSON(data, dek);

    // Create storage payload
    const storagePayload: StoragePayload = {
      record: record.toDict(),
      encrypted: encrypted.toDict(),
    };

    // Store in backend
    const ttlSeconds = Math.ceil(effectiveTTL / 1000);
    await this.backend.set(record.id, JSON.stringify(storagePayload), ttlSeconds);

    // Track record and custody
    this.records.set(record.id, record);

    if (this.attestationEnabled) {
      const custody = new ChainOfCustody(record.createdAt, 'ephemeral_store');
      custody.addAccess('ephemeral_store', 'create');
      this.custody.set(record.id, custody);
    }

    return record;
  }

  /**
   * Retrieve data by record ID.
   *
   * @param recordId - The record identifier
   * @returns The decrypted data
   * @throws RecordNotFoundError if the record doesn't exist
   * @throws RecordExpiredError if the record has expired
   */
  async get(recordId: string): Promise<Record<string, unknown>> {
    // Get from backend
    const raw = await this.backend.get(recordId);

    if (raw === null) {
      // Check if we have a destruction certificate
      if (this.certificates.has(recordId)) {
        throw new RecordExpiredError(recordId);
      }
      throw new RecordNotFoundError(recordId);
    }

    // Parse storage payload
    const storagePayload: StoragePayload = JSON.parse(raw);
    const record = EphemeralRecord.fromDict(storagePayload.record);
    const encrypted = EncryptedPayload.fromDict(storagePayload.encrypted);

    // Check expiration
    if (record.isExpired) {
      await this.handleExpiration(recordId);
      throw new RecordExpiredError(recordId, record.expiresAt.toISOString());
    }

    // Decrypt data
    const data = this.crypto.decryptJSON(encrypted);

    // Update access count and custody
    const trackedRecord = this.records.get(recordId);
    if (trackedRecord) {
      trackedRecord.accessCount++;
    }

    const custody = this.custody.get(recordId);
    if (custody) {
      custody.addAccess('ephemeral_store', 'read');
    }

    return data;
  }

  /**
   * Check if a record exists and is not expired.
   *
   * @param recordId - The record identifier
   */
  async exists(recordId: string): Promise<boolean> {
    return this.backend.exists(recordId);
  }

  /**
   * Get remaining TTL for a record in milliseconds.
   *
   * @param recordId - The record identifier
   * @returns Remaining TTL in milliseconds, or null if not found
   */
  async ttl(recordId: string): Promise<number | null> {
    const seconds = await this.backend.ttl(recordId);
    if (seconds === null) {
      return null;
    }
    return seconds * 1000;
  }

  /**
   * Manually destroy a record immediately (crypto-shredding).
   *
   * This destroys the encryption key, making the data permanently
   * unrecoverable, and generates a destruction certificate.
   *
   * @param recordId - The record identifier
   * @returns The destruction certificate, or null if attestation is disabled
   */
  async destroy(recordId: string): Promise<DestructionCertificate | null> {
    return this.handleExpiration(recordId, DestructionMethod.MANUAL);
  }

  /**
   * Handle record expiration or destruction.
   */
  private async handleExpiration(
    recordId: string,
    method: DestructionMethod = DestructionMethod.CRYPTO_SHRED
  ): Promise<DestructionCertificate | null> {
    const record = this.records.get(recordId);
    const custody = this.custody.get(recordId);

    // Delete from backend
    await this.backend.delete(recordId);

    // Destroy encryption key (crypto-shredding)
    if (record?.keyId) {
      this.crypto.destroyDEK(record.keyId);
    }

    // Generate destruction certificate
    let certificate: DestructionCertificate | null = null;
    if (this.attestationEnabled && this.authority && record) {
      if (custody) {
        custody.addAccess('ephemeral_store', 'destroy');
      }

      certificate = this.authority.issueCertificate(
        'ephemeral_data',
        recordId,
        record.classification,
        method,
        custody ?? null,
        {
          ttl_seconds: record.ttl / 1000,
          access_count: record.accessCount,
          ...record.metadata,
        }
      );

      this.certificates.set(recordId, certificate);
    }

    // Clean up tracking
    this.records.delete(recordId);
    this.custody.delete(recordId);

    return certificate;
  }

  /**
   * Get the destruction certificate for a destroyed record.
   *
   * @param recordId - The record identifier
   * @returns The certificate or null if not found
   */
  getDestructionCertificate(recordId: string): DestructionCertificate | null {
    return this.certificates.get(recordId) ?? null;
  }

  /**
   * List all destruction certificates.
   *
   * @param since - Optional date to filter certificates issued after
   * @returns List of certificates sorted by destruction timestamp (newest first)
   */
  listCertificates(since?: Date): DestructionCertificate[] {
    let certs = Array.from(this.certificates.values());

    if (since) {
      certs = certs.filter((c) => c.destructionTimestamp >= since);
    }

    return certs.sort(
      (a, b) => b.destructionTimestamp.getTime() - a.destructionTimestamp.getTime()
    );
  }

  /**
   * Get store statistics.
   */
  stats(): StoreStats {
    return {
      activeRecords: this.records.size,
      certificatesIssued: this.certificates.size,
      attestationEnabled: this.attestationEnabled,
    };
  }

  /**
   * Close the store and release resources.
   */
  async close(): Promise<void> {
    await this.backend.close();
  }

  // ============================================================
  // Internal accessors for testing
  // ============================================================

  /** @internal */
  get _crypto(): CryptoProvider {
    return this.crypto;
  }

  /** @internal */
  get _authority(): AttestationAuthority | null {
    return this.authority;
  }

  /** @internal */
  get _records(): Map<string, EphemeralRecord> {
    return this.records;
  }
}
