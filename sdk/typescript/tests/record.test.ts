import { describe, it, expect } from 'vitest';
import {
  DataClassification,
  EphemeralRecord,
  parseTTL,
  getDefaultTTL,
  getMaxTTL,
} from '../src/record.js';

describe('parseTTL', () => {
  it('should parse seconds', () => {
    expect(parseTTL('30s')).toBe(30000);
    expect(parseTTL('30sec')).toBe(30000);
    expect(parseTTL('30second')).toBe(30000);
    expect(parseTTL('30seconds')).toBe(30000);
  });

  it('should parse minutes', () => {
    expect(parseTTL('5m')).toBe(300000);
    expect(parseTTL('5min')).toBe(300000);
    expect(parseTTL('5minute')).toBe(300000);
    expect(parseTTL('5minutes')).toBe(300000);
  });

  it('should parse hours', () => {
    expect(parseTTL('2h')).toBe(7200000);
    expect(parseTTL('2hr')).toBe(7200000);
    expect(parseTTL('2hour')).toBe(7200000);
    expect(parseTTL('2hours')).toBe(7200000);
  });

  it('should parse days', () => {
    expect(parseTTL('7d')).toBe(604800000);
    expect(parseTTL('7day')).toBe(604800000);
    expect(parseTTL('7days')).toBe(604800000);
  });

  it('should be case insensitive', () => {
    expect(parseTTL('30S')).toBe(30000);
    expect(parseTTL('5M')).toBe(300000);
    expect(parseTTL('2H')).toBe(7200000);
    expect(parseTTL('7D')).toBe(604800000);
  });

  it('should handle whitespace', () => {
    expect(parseTTL('  30s  ')).toBe(30000);
    expect(parseTTL('5 m')).toBe(300000);
  });

  it('should throw on invalid TTL', () => {
    expect(() => parseTTL('invalid')).toThrow();
    expect(() => parseTTL('10x')).toThrow();
    expect(() => parseTTL('')).toThrow();
    expect(() => parseTTL('abc')).toThrow();
  });
});

describe('DataClassification', () => {
  it('should have correct default TTLs', () => {
    expect(getDefaultTTL(DataClassification.TRANSIENT)).toBe(60 * 60 * 1000); // 1 hour
    expect(getDefaultTTL(DataClassification.SHORT_LIVED)).toBe(24 * 60 * 60 * 1000); // 1 day
    expect(getDefaultTTL(DataClassification.RETENTION_BOUND)).toBe(90 * 24 * 60 * 60 * 1000); // 90 days
    expect(getDefaultTTL(DataClassification.PERSISTENT)).toBeNull();
  });

  it('should have correct max TTLs', () => {
    expect(getMaxTTL(DataClassification.TRANSIENT)).toBe(24 * 60 * 60 * 1000); // 24 hours
    expect(getMaxTTL(DataClassification.SHORT_LIVED)).toBe(7 * 24 * 60 * 60 * 1000); // 7 days
    expect(getMaxTTL(DataClassification.RETENTION_BOUND)).toBe(7 * 365 * 24 * 60 * 60 * 1000); // 7 years
    expect(getMaxTTL(DataClassification.PERSISTENT)).toBeNull();
  });
});

describe('EphemeralRecord', () => {
  it('should create a record with factory method', () => {
    const record = EphemeralRecord.create({
      classification: DataClassification.TRANSIENT,
      ttl: 30 * 60 * 1000, // 30 minutes
    });

    expect(record.id).toBeDefined();
    expect(record.classification).toBe(DataClassification.TRANSIENT);
    expect(record.ttl).toBe(30 * 60 * 1000);
    expect(record.encrypted).toBe(true);
    expect(record.keyId).toBeDefined();
    expect(record.accessCount).toBe(0);
  });

  it('should use default TTL for classification', () => {
    const record = EphemeralRecord.create({
      classification: DataClassification.TRANSIENT,
    });

    expect(record.ttl).toBe(60 * 60 * 1000); // 1 hour default
  });

  it('should throw when TTL exceeds max', () => {
    expect(() =>
      EphemeralRecord.create({
        classification: DataClassification.TRANSIENT,
        ttl: 30 * 24 * 60 * 60 * 1000, // 30 days exceeds 24h max
      })
    ).toThrow(/exceeds maximum/);
  });

  it('should include metadata', () => {
    const record = EphemeralRecord.create({
      classification: DataClassification.TRANSIENT,
      metadata: { source: 'test', user_id: '123' },
    });

    expect(record.metadata).toEqual({ source: 'test', user_id: '123' });
  });

  it('should compute isExpired correctly', () => {
    const record = EphemeralRecord.create({
      classification: DataClassification.TRANSIENT,
      ttl: 1000, // 1 second
    });

    expect(record.isExpired).toBe(false);
  });

  it('should compute timeRemaining correctly', () => {
    const record = EphemeralRecord.create({
      classification: DataClassification.TRANSIENT,
      ttl: 60 * 60 * 1000, // 1 hour
    });

    // Should be approximately 1 hour
    expect(record.timeRemaining).toBeGreaterThan(59 * 60 * 1000);
    expect(record.timeRemaining).toBeLessThanOrEqual(60 * 60 * 1000);
  });

  it('should serialize and deserialize correctly', () => {
    const original = EphemeralRecord.create({
      classification: DataClassification.SHORT_LIVED,
      ttl: 2 * 60 * 60 * 1000, // 2 hours
      metadata: { key: 'value' },
    });

    const data = original.toDict();
    const restored = EphemeralRecord.fromDict(data);

    expect(restored.id).toBe(original.id);
    expect(restored.classification).toBe(original.classification);
    expect(restored.ttl).toBe(original.ttl);
    expect(restored.keyId).toBe(original.keyId);
    expect(restored.metadata).toEqual(original.metadata);
  });

  it('should have correct toDict format', () => {
    const record = EphemeralRecord.create({
      classification: DataClassification.TRANSIENT,
      ttl: 3600000,
    });

    const data = record.toDict();

    expect(data).toHaveProperty('id');
    expect(data).toHaveProperty('classification', 'TRANSIENT');
    expect(data).toHaveProperty('created_at');
    expect(data).toHaveProperty('expires_at');
    expect(data).toHaveProperty('ttl_seconds', 3600);
    expect(data).toHaveProperty('encrypted', true);
    expect(data).toHaveProperty('key_id');
    expect(data).toHaveProperty('access_count', 0);
    expect(data).toHaveProperty('metadata');
  });
});
