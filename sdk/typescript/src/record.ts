/**
 * EFSF Record Types
 *
 * Defines the EphemeralRecord class and related data structures
 * for managing ephemeral data with classification and TTL policies.
 */

import { v4 as uuidv4 } from 'uuid';

/**
 * Data classification levels with associated TTL policies.
 *
 * Each classification defines default and maximum TTL values:
 * - TRANSIENT: Short-lived data (sessions, tokens) - max 24 hours
 * - SHORT_LIVED: Temporary data (carts, uploads) - max 7 days
 * - RETENTION_BOUND: Compliance data (invoices, logs) - max 7 years
 * - PERSISTENT: Permanent data (legal holds) - no TTL limit
 */
export enum DataClassification {
  TRANSIENT = 'TRANSIENT',
  SHORT_LIVED = 'SHORT_LIVED',
  RETENTION_BOUND = 'RETENTION_BOUND',
  PERSISTENT = 'PERSISTENT',
}

/** TTL defaults in milliseconds */
const CLASSIFICATION_DEFAULTS: Record<DataClassification, number | null> = {
  [DataClassification.TRANSIENT]: 60 * 60 * 1000, // 1 hour
  [DataClassification.SHORT_LIVED]: 24 * 60 * 60 * 1000, // 1 day
  [DataClassification.RETENTION_BOUND]: 90 * 24 * 60 * 60 * 1000, // 90 days
  [DataClassification.PERSISTENT]: null,
};

/** TTL maximums in milliseconds */
const CLASSIFICATION_MAX: Record<DataClassification, number | null> = {
  [DataClassification.TRANSIENT]: 24 * 60 * 60 * 1000, // 24 hours
  [DataClassification.SHORT_LIVED]: 7 * 24 * 60 * 60 * 1000, // 7 days
  [DataClassification.RETENTION_BOUND]: 7 * 365 * 24 * 60 * 60 * 1000, // 7 years
  [DataClassification.PERSISTENT]: null,
};

/**
 * Get the default TTL for a classification in milliseconds.
 */
export function getDefaultTTL(classification: DataClassification): number | null {
  return CLASSIFICATION_DEFAULTS[classification];
}

/**
 * Get the maximum TTL for a classification in milliseconds.
 */
export function getMaxTTL(classification: DataClassification): number | null {
  return CLASSIFICATION_MAX[classification];
}

/**
 * Serialized record format for storage.
 */
export interface EphemeralRecordData {
  id: string;
  classification: string;
  created_at: string;
  expires_at: string;
  ttl_seconds: number;
  encrypted: boolean;
  key_id: string | null;
  access_count: number;
  metadata: Record<string, unknown>;
}

/**
 * Options for creating an ephemeral record.
 */
export interface EphemeralRecordCreateOptions {
  classification?: DataClassification;
  ttl?: number; // milliseconds
  metadata?: Record<string, unknown>;
}

/**
 * Represents metadata for an ephemeral record stored in the system.
 *
 * EphemeralRecord tracks the lifecycle of stored data including:
 * - Unique identifier and encryption key reference
 * - Classification and TTL policy
 * - Creation and expiration timestamps
 * - Access count for auditing
 */
export class EphemeralRecord {
  constructor(
    public readonly id: string,
    public readonly classification: DataClassification,
    public readonly createdAt: Date,
    public readonly expiresAt: Date,
    public readonly ttl: number, // milliseconds
    public readonly encrypted: boolean = true,
    public keyId: string | null = null,
    public accessCount: number = 0,
    public readonly metadata: Record<string, unknown> = {}
  ) {}

  /**
   * Factory method to create a new ephemeral record.
   *
   * @param options - Configuration options for the record
   * @returns A new EphemeralRecord instance
   * @throws Error if TTL exceeds the classification's maximum
   */
  static create(options: EphemeralRecordCreateOptions = {}): EphemeralRecord {
    const classification = options.classification ?? DataClassification.TRANSIENT;
    const now = new Date();

    // Use provided TTL or fall back to classification default
    let effectiveTTL = options.ttl ?? getDefaultTTL(classification);
    if (effectiveTTL === null) {
      throw new Error(
        `TTL required for ${classification} classification (no default available)`
      );
    }

    // Validate TTL against classification maximum
    const maxTTL = getMaxTTL(classification);
    if (maxTTL !== null && effectiveTTL > maxTTL) {
      throw new Error(
        `TTL ${effectiveTTL}ms exceeds maximum ${maxTTL}ms for ${classification} classification`
      );
    }

    const expiresAt = new Date(now.getTime() + effectiveTTL);

    return new EphemeralRecord(
      uuidv4(),
      classification,
      now,
      expiresAt,
      effectiveTTL,
      true,
      uuidv4(), // Generate key ID for crypto-shredding
      0,
      options.metadata ?? {}
    );
  }

  /**
   * Check if the record has expired.
   */
  get isExpired(): boolean {
    return new Date() >= this.expiresAt;
  }

  /**
   * Get remaining time until expiration in milliseconds.
   */
  get timeRemaining(): number {
    const remaining = this.expiresAt.getTime() - Date.now();
    return Math.max(remaining, 0);
  }

  /**
   * Convert to a plain object for serialization.
   */
  toDict(): EphemeralRecordData {
    return {
      id: this.id,
      classification: this.classification,
      created_at: this.createdAt.toISOString(),
      expires_at: this.expiresAt.toISOString(),
      ttl_seconds: this.ttl / 1000,
      encrypted: this.encrypted,
      key_id: this.keyId,
      access_count: this.accessCount,
      metadata: this.metadata,
    };
  }

  /**
   * Reconstruct an EphemeralRecord from serialized data.
   */
  static fromDict(data: EphemeralRecordData): EphemeralRecord {
    return new EphemeralRecord(
      data.id,
      data.classification as DataClassification,
      new Date(data.created_at),
      new Date(data.expires_at),
      data.ttl_seconds * 1000,
      data.encrypted ?? true,
      data.key_id ?? null,
      data.access_count ?? 0,
      data.metadata ?? {}
    );
  }
}

/**
 * Parse a human-readable TTL string into milliseconds.
 *
 * Supported formats:
 * - Seconds: "30s", "30sec", "30second", "30seconds"
 * - Minutes: "5m", "5min", "5minute", "5minutes"
 * - Hours: "2h", "2hr", "2hour", "2hours"
 * - Days: "7d", "7day", "7days"
 *
 * @param ttlString - Human-readable TTL string
 * @returns TTL in milliseconds
 * @throws Error if the string cannot be parsed
 *
 * @example
 * parseTTL("30s")  // 30000
 * parseTTL("5m")   // 300000
 * parseTTL("2h")   // 7200000
 * parseTTL("7d")   // 604800000
 */
export function parseTTL(ttlString: string): number {
  const pattern = /^(\d+)\s*(s|sec|seconds?|m|min|minutes?|h|hr|hours?|d|days?)$/i;
  const match = ttlString.trim().match(pattern);

  if (!match) {
    throw new Error(`Cannot parse TTL string: ${ttlString}`);
  }

  const value = parseInt(match[1], 10);
  const unit = match[2].toLowerCase();

  if (unit.startsWith('s')) {
    return value * 1000;
  } else if (unit.startsWith('m')) {
    return value * 60 * 1000;
  } else if (unit.startsWith('h')) {
    return value * 60 * 60 * 1000;
  } else if (unit.startsWith('d')) {
    return value * 24 * 60 * 60 * 1000;
  }

  throw new Error(`Unknown time unit: ${unit}`);
}
