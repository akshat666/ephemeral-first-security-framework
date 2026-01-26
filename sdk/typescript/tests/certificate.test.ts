import { describe, it, expect } from 'vitest';
import {
  AttestationAuthority,
  ChainOfCustody,
  DestructionCertificate,
  DestructionMethod,
  ResourceInfo,
} from '../src/certificate.js';
import { AttestationError } from '../src/exceptions.js';

describe('ResourceInfo', () => {
  it('should create and serialize resource info', () => {
    const resource = new ResourceInfo(
      'ephemeral_data',
      'record-123',
      'TRANSIENT',
      { source: 'test' }
    );

    const data = resource.toDict();
    expect(data).toEqual({
      type: 'ephemeral_data',
      id: 'record-123',
      classification: 'TRANSIENT',
      metadata: { source: 'test' },
    });
  });
});

describe('ChainOfCustody', () => {
  it('should create chain of custody', () => {
    const custody = new ChainOfCustody(new Date(), 'test-creator');

    expect(custody.createdAt).toBeInstanceOf(Date);
    expect(custody.createdBy).toBe('test-creator');
    expect(custody.accessLog).toHaveLength(0);
    expect(custody.hashChain).toHaveLength(0);
  });

  it('should add access events with hash chain', () => {
    const custody = new ChainOfCustody(new Date(), 'test');

    custody.addAccess('user1', 'create');
    expect(custody.accessLog).toHaveLength(1);
    expect(custody.hashChain).toHaveLength(1);

    custody.addAccess('user2', 'read');
    expect(custody.accessLog).toHaveLength(2);
    expect(custody.hashChain).toHaveLength(2);

    // Hash chain should be different for each event
    expect(custody.hashChain[0]).not.toBe(custody.hashChain[1]);
  });

  it('should serialize to dict', () => {
    const custody = new ChainOfCustody(new Date(), 'test');
    custody.addAccess('user1', 'create');
    custody.addAccess('user2', 'read');

    const data = custody.toDict();
    expect(data.created_by).toBe('test');
    expect(data.access_count).toBe(2);
    expect(data.hash_chain).toHaveLength(2);
  });

  it('should limit hash chain to last 5 entries', () => {
    const custody = new ChainOfCustody(new Date(), 'test');

    for (let i = 0; i < 10; i++) {
      custody.addAccess('user', `action-${i}`);
    }

    const data = custody.toDict();
    expect(data.access_count).toBe(10);
    expect(data.hash_chain).toHaveLength(5);
  });
});

describe('DestructionCertificate', () => {
  it('should create certificate with factory method', () => {
    const resource = new ResourceInfo('ephemeral_data', 'record-123', 'TRANSIENT');
    const cert = DestructionCertificate.create(
      resource,
      DestructionMethod.CRYPTO_SHRED,
      'test-authority'
    );

    expect(cert.certificateId).toBeDefined();
    expect(cert.version).toBe('1.0');
    expect(cert.resource).toBe(resource);
    expect(cert.destructionMethod).toBe(DestructionMethod.CRYPTO_SHRED);
    expect(cert.verifiedBy).toBe('test-authority');
    expect(cert.signature).toBeNull();
  });

  it('should serialize to dict', () => {
    const resource = new ResourceInfo('ephemeral_data', 'record-123', 'TRANSIENT');
    const cert = DestructionCertificate.create(resource, DestructionMethod.MANUAL);

    const data = cert.toDict();
    expect(data.version).toBe('1.0');
    expect(data.certificate_id).toBeDefined();
    expect(data.resource.type).toBe('ephemeral_data');
    expect(data.destruction.method).toBe('manual');
  });

  it('should compute canonical bytes deterministically', () => {
    const resource = new ResourceInfo('ephemeral_data', 'record-123', 'TRANSIENT');
    const cert = DestructionCertificate.create(resource, DestructionMethod.CRYPTO_SHRED);

    const bytes1 = cert.canonicalBytes();
    const bytes2 = cert.canonicalBytes();

    expect(bytes1).toEqual(bytes2);
  });

  it('should compute hash', () => {
    const resource = new ResourceInfo('ephemeral_data', 'record-123', 'TRANSIENT');
    const cert = DestructionCertificate.create(resource, DestructionMethod.CRYPTO_SHRED);

    const hash = cert.computeHash();
    expect(hash).toMatch(/^[a-f0-9]{64}$/); // SHA-256 hex
  });

  it('should convert to JSON', () => {
    const resource = new ResourceInfo('ephemeral_data', 'record-123', 'TRANSIENT');
    const cert = DestructionCertificate.create(resource, DestructionMethod.CRYPTO_SHRED);

    const json = cert.toJSON();
    expect(() => JSON.parse(json)).not.toThrow();
  });
});

describe('AttestationAuthority', () => {
  it('should create authority with key pair', () => {
    const authority = new AttestationAuthority('test-authority');

    expect(authority.authorityId).toBe('test-authority');
    expect(authority.publicKeyB64).toBeDefined();
    expect(authority.publicKeyBytes).toBeInstanceOf(Buffer);
  });

  it('should sign certificates', () => {
    const authority = new AttestationAuthority();
    const resource = new ResourceInfo('ephemeral_data', 'record-123', 'TRANSIENT');
    const cert = DestructionCertificate.create(resource, DestructionMethod.CRYPTO_SHRED);

    expect(cert.signature).toBeNull();

    const signed = authority.signCertificate(cert);

    expect(signed.signature).toBeDefined();
    expect(signed.verifiedBy).toBe(authority.authorityId);
  });

  it('should verify valid signatures', () => {
    const authority = new AttestationAuthority();
    const resource = new ResourceInfo('ephemeral_data', 'record-123', 'TRANSIENT');
    const cert = DestructionCertificate.create(resource, DestructionMethod.CRYPTO_SHRED);

    const signed = authority.signCertificate(cert);
    const isValid = authority.verifyCertificate(signed);

    expect(isValid).toBe(true);
  });

  it('should reject unsigned certificates', () => {
    const authority = new AttestationAuthority();
    const resource = new ResourceInfo('ephemeral_data', 'record-123', 'TRANSIENT');
    const cert = DestructionCertificate.create(resource, DestructionMethod.CRYPTO_SHRED);

    expect(() => authority.verifyCertificate(cert)).toThrow(AttestationError);
  });

  it('should issue certificates', () => {
    const authority = new AttestationAuthority();
    const custody = new ChainOfCustody(new Date(), 'test');
    custody.addAccess('store', 'create');
    custody.addAccess('store', 'read');
    custody.addAccess('store', 'destroy');

    const cert = authority.issueCertificate(
      'ephemeral_data',
      'record-123',
      'TRANSIENT',
      DestructionMethod.CRYPTO_SHRED,
      custody,
      { access_count: 2 }
    );

    expect(cert.signature).toBeDefined();
    expect(cert.chainOfCustody).toBe(custody);
    expect(authority.verifyCertificate(cert)).toBe(true);
  });

  it('should retrieve and list certificates', () => {
    const authority = new AttestationAuthority();

    const cert1 = authority.issueCertificate(
      'ephemeral_data',
      'record-1',
      'TRANSIENT',
      DestructionMethod.CRYPTO_SHRED
    );

    const cert2 = authority.issueCertificate(
      'ephemeral_data',
      'record-2',
      'SHORT_LIVED',
      DestructionMethod.MANUAL
    );

    // Retrieve by ID
    expect(authority.getCertificate(cert1.certificateId)).toBe(cert1);
    expect(authority.getCertificate('non-existent')).toBeNull();

    // List all
    const all = authority.listCertificates();
    expect(all).toHaveLength(2);

    // Filter by resource ID
    const filtered = authority.listCertificates('record-1');
    expect(filtered).toHaveLength(1);
    expect(filtered[0]).toBe(cert1);
  });
});
