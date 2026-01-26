import { describe, it, expect, beforeEach } from 'vitest';
import {
  EphemeralStore,
  MemoryBackend,
  createBackend,
  DataClassification,
  RecordNotFoundError,
  RecordExpiredError,
} from '../src/index.js';

describe('MemoryBackend', () => {
  it('should set and get values', async () => {
    const backend = new MemoryBackend();

    await backend.set('key1', 'value1', 3600);
    const value = await backend.get('key1');

    expect(value).toBe('value1');
  });

  it('should return null for non-existent keys', async () => {
    const backend = new MemoryBackend();
    const value = await backend.get('non-existent');
    expect(value).toBeNull();
  });

  it('should delete keys', async () => {
    const backend = new MemoryBackend();

    await backend.set('key1', 'value1', 3600);
    expect(await backend.exists('key1')).toBe(true);

    await backend.delete('key1');
    expect(await backend.exists('key1')).toBe(false);
  });

  it('should return TTL', async () => {
    const backend = new MemoryBackend();

    await backend.set('key1', 'value1', 3600);
    const ttl = await backend.ttl('key1');

    expect(ttl).toBeGreaterThan(3590);
    expect(ttl).toBeLessThanOrEqual(3600);
  });

  it('should expire values after TTL', async () => {
    const backend = new MemoryBackend();

    await backend.set('key1', 'value1', 1); // 1 second TTL

    // Wait for expiration
    await new Promise((resolve) => setTimeout(resolve, 1100));

    const value = await backend.get('key1');
    expect(value).toBeNull();
  });
});

describe('createBackend', () => {
  it('should create memory backend', () => {
    const backend = createBackend('memory://');
    expect(backend).toBeInstanceOf(MemoryBackend);
  });

  it('should create memory backend with short form', () => {
    const backend = createBackend('memory');
    expect(backend).toBeInstanceOf(MemoryBackend);
  });

  it('should throw for unsupported scheme', () => {
    expect(() => createBackend('unknown://localhost')).toThrow(/Unsupported backend/);
  });
});

describe('EphemeralStore', () => {
  let store: EphemeralStore;

  beforeEach(() => {
    store = new EphemeralStore({ backend: 'memory://', attestation: true });
  });

  describe('put and get', () => {
    it('should store and retrieve data', async () => {
      const data = { user_id: '123', session: 'abc' };
      const record = await store.put(data, { ttl: '30m' });

      expect(record.id).toBeDefined();
      expect(record.classification).toBe(DataClassification.TRANSIENT);

      const retrieved = await store.get(record.id);
      expect(retrieved).toEqual(data);
    });

    it('should use default TTL', async () => {
      const store = new EphemeralStore({ backend: 'memory://', defaultTTL: '2h' });
      const record = await store.put({ data: 'test' });

      expect(record.ttl).toBe(2 * 60 * 60 * 1000); // 2 hours
    });

    it('should accept classification as string', async () => {
      const record = await store.put(
        { data: 'test' },
        { classification: 'SHORT_LIVED' }
      );

      expect(record.classification).toBe(DataClassification.SHORT_LIVED);
    });

    it('should include metadata', async () => {
      const record = await store.put(
        { data: 'test' },
        { metadata: { source: 'api', request_id: 'req-123' } }
      );

      expect(record.metadata).toEqual({ source: 'api', request_id: 'req-123' });
    });
  });

  describe('exists and ttl', () => {
    it('should check existence', async () => {
      const record = await store.put({ data: 'test' }, { ttl: '1h' });

      expect(await store.exists(record.id)).toBe(true);
      expect(await store.exists('non-existent')).toBe(false);
    });

    it('should return remaining TTL', async () => {
      const record = await store.put({ data: 'test' }, { ttl: '1h' });

      const ttl = await store.ttl(record.id);
      expect(ttl).toBeGreaterThan(59 * 60 * 1000);
      expect(ttl).toBeLessThanOrEqual(60 * 60 * 1000);
    });

    it('should return null TTL for non-existent record', async () => {
      const ttl = await store.ttl('non-existent');
      expect(ttl).toBeNull();
    });
  });

  describe('error handling', () => {
    it('should throw RecordNotFoundError for missing record', async () => {
      await expect(store.get('non-existent')).rejects.toThrow(RecordNotFoundError);
    });

    it('should throw RecordExpiredError for destroyed record', async () => {
      const record = await store.put({ data: 'test' }, { ttl: '1h' });
      await store.destroy(record.id);

      await expect(store.get(record.id)).rejects.toThrow(RecordExpiredError);
    });
  });

  describe('destroy', () => {
    it('should destroy record and return certificate', async () => {
      const record = await store.put({ secret: 'data' }, { ttl: '1h' });

      expect(await store.exists(record.id)).toBe(true);

      const certificate = await store.destroy(record.id);

      expect(await store.exists(record.id)).toBe(false);
      expect(certificate).not.toBeNull();
      expect(certificate?.resource.resourceId).toBe(record.id);
      expect(certificate?.destructionMethod).toBe('manual');
      expect(certificate?.signature).toBeDefined();
    });

    it('should destroy encryption key (crypto-shredding)', async () => {
      const record = await store.put({ secret: 'data' }, { ttl: '1h' });
      const keyId = record.keyId!;

      expect(store._crypto.getDEK(keyId)).not.toBeNull();

      await store.destroy(record.id);

      expect(store._crypto.getDEK(keyId)).toBeNull();
    });
  });

  describe('certificates', () => {
    it('should track destruction certificates', async () => {
      const record1 = await store.put({ data: '1' }, { ttl: '1h' });
      const record2 = await store.put({ data: '2' }, { ttl: '1h' });

      await store.destroy(record1.id);
      await store.destroy(record2.id);

      const certs = store.listCertificates();
      expect(certs).toHaveLength(2);
    });

    it('should retrieve certificate by record ID', async () => {
      const record = await store.put({ data: 'test' }, { ttl: '1h' });
      await store.destroy(record.id);

      const cert = store.getDestructionCertificate(record.id);
      expect(cert).not.toBeNull();
      expect(cert?.resource.resourceId).toBe(record.id);
    });

    it('should include chain of custody', async () => {
      const record = await store.put({ data: 'test' }, { ttl: '1h' });

      // Access the record a few times
      await store.get(record.id);
      await store.get(record.id);

      const cert = await store.destroy(record.id);

      expect(cert?.chainOfCustody).not.toBeNull();
      expect(cert?.chainOfCustody?.accessLog.length).toBeGreaterThanOrEqual(3); // create, 2 reads, destroy
    });
  });

  describe('stats', () => {
    it('should return store statistics', async () => {
      await store.put({ data: '1' }, { ttl: '1h' });
      await store.put({ data: '2' }, { ttl: '1h' });

      const stats = store.stats();

      expect(stats.activeRecords).toBe(2);
      expect(stats.certificatesIssued).toBe(0);
      expect(stats.attestationEnabled).toBe(true);
    });

    it('should update stats after destruction', async () => {
      const record = await store.put({ data: 'test' }, { ttl: '1h' });
      await store.destroy(record.id);

      const stats = store.stats();

      expect(stats.activeRecords).toBe(0);
      expect(stats.certificatesIssued).toBe(1);
    });
  });

  describe('close', () => {
    it('should close without error', async () => {
      await expect(store.close()).resolves.not.toThrow();
    });
  });
});

describe('EphemeralStore without attestation', () => {
  it('should not generate certificates when disabled', async () => {
    const store = new EphemeralStore({ backend: 'memory://', attestation: false });

    const record = await store.put({ data: 'test' }, { ttl: '1h' });
    const cert = await store.destroy(record.id);

    expect(cert).toBeNull();
    expect(store.stats().attestationEnabled).toBe(false);
  });
});
