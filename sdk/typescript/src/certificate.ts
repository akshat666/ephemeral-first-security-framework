/**
 * EFSF Destruction Certificates
 *
 * Provides cryptographically signed proof of data destruction
 * for compliance and audit purposes (GDPR, CCPA, HIPAA, SOX).
 */

import * as crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { AttestationError } from './exceptions.js';

/**
 * Methods used to destroy data.
 */
export enum DestructionMethod {
  /** Encryption key destroyed, data unrecoverable */
  CRYPTO_SHRED = 'crypto_shred',
  /** Memory overwritten with zeros */
  MEMORY_ZERO = 'memory_zero',
  /** Multiple overwrites (secure deletion) */
  SECURE_DELETE = 'secure_delete',
  /** Trusted Execution Environment terminated */
  TEE_EXIT = 'tee_exit',
  /** Storage TTL triggered automatic expiration */
  TTL_EXPIRE = 'ttl_expire',
  /** Explicit deletion request */
  MANUAL = 'manual',
}

/**
 * Serialized format for resource info.
 */
export interface ResourceInfoData {
  type: string;
  id: string;
  classification: string;
  metadata: Record<string, unknown>;
}

/**
 * Describes a resource that was destroyed.
 */
export class ResourceInfo {
  constructor(
    public readonly resourceType: string,
    public readonly resourceId: string,
    public readonly classification: string,
    public readonly metadata: Record<string, unknown> = {}
  ) {}

  /**
   * Convert to a plain object for serialization.
   */
  toDict(): ResourceInfoData {
    return {
      type: this.resourceType,
      id: this.resourceId,
      classification: this.classification,
      metadata: this.metadata,
    };
  }
}

/**
 * An access event in the chain of custody.
 */
export interface AccessEvent {
  timestamp: string;
  accessor: string;
  action: string;
}

/**
 * Serialized format for chain of custody.
 */
export interface ChainOfCustodyData {
  created_at: string;
  created_by: string | null;
  access_count: number;
  hash_chain: string[];
}

/**
 * Tracks the lifecycle of a resource with tamper-evident logging.
 *
 * The hash chain provides cryptographic proof that the access log
 * has not been modified after the fact.
 */
export class ChainOfCustody {
  public readonly accessLog: AccessEvent[] = [];
  public readonly hashChain: string[] = [];

  constructor(
    public readonly createdAt: Date,
    public readonly createdBy: string | null = null
  ) {}

  /**
   * Record an access event and extend the hash chain.
   *
   * @param accessor - Identity of the accessor
   * @param action - Action performed (create, read, destroy, etc.)
   * @param timestamp - Optional timestamp (defaults to now)
   */
  addAccess(accessor: string, action: string, timestamp?: Date): void {
    const ts = timestamp ?? new Date();
    const event: AccessEvent = {
      timestamp: ts.toISOString(),
      accessor,
      action,
    };
    this.accessLog.push(event);

    // Extend hash chain for tamper-evidence
    const eventHash = crypto
      .createHash('sha256')
      .update(JSON.stringify(event))
      .digest('hex');

    let chained: string;
    if (this.hashChain.length > 0) {
      // Chain: hash(previous_hash + event_hash)
      chained = crypto
        .createHash('sha256')
        .update(this.hashChain[this.hashChain.length - 1] + eventHash)
        .digest('hex');
    } else {
      chained = eventHash;
    }
    this.hashChain.push(chained);
  }

  /**
   * Convert to a plain object for serialization.
   * Returns only the last 5 hashes for brevity.
   */
  toDict(): ChainOfCustodyData {
    return {
      created_at: this.createdAt.toISOString(),
      created_by: this.createdBy,
      access_count: this.accessLog.length,
      hash_chain: this.hashChain.slice(-5), // Last 5 hashes
    };
  }
}

/**
 * Serialized format for destruction certificates.
 */
export interface DestructionCertificateData {
  version: string;
  certificate_id: string;
  resource: ResourceInfoData;
  destruction: {
    method: string;
    timestamp: string;
    verified_by: string;
  };
  chain_of_custody?: ChainOfCustodyData;
  signature?: string;
}

/**
 * Cryptographically signed proof of data destruction.
 *
 * Destruction certificates provide verifiable evidence for compliance
 * with data protection regulations (GDPR Article 17, CCPA, HIPAA, SOX).
 */
export class DestructionCertificate {
  constructor(
    public readonly certificateId: string,
    public readonly version: string,
    public readonly resource: ResourceInfo,
    public readonly destructionMethod: DestructionMethod,
    public readonly destructionTimestamp: Date,
    public verifiedBy: string,
    public readonly chainOfCustody: ChainOfCustody | null = null,
    public signature: string | null = null
  ) {}

  /**
   * Factory method to create a new destruction certificate.
   *
   * @param resource - The destroyed resource info
   * @param destructionMethod - How the data was destroyed
   * @param verifiedBy - Authority that verified the destruction
   * @param chainOfCustody - Optional chain of custody
   */
  static create(
    resource: ResourceInfo,
    destructionMethod: DestructionMethod,
    verifiedBy: string = 'efsf-local-authority',
    chainOfCustody: ChainOfCustody | null = null
  ): DestructionCertificate {
    return new DestructionCertificate(
      uuidv4(),
      '1.0',
      resource,
      destructionMethod,
      new Date(),
      verifiedBy,
      chainOfCustody
    );
  }

  /**
   * Convert to a plain object for serialization.
   *
   * @param includeSignature - Whether to include the signature field
   */
  toDict(includeSignature: boolean = true): DestructionCertificateData {
    const data: DestructionCertificateData = {
      version: this.version,
      certificate_id: this.certificateId,
      resource: this.resource.toDict(),
      destruction: {
        method: this.destructionMethod,
        timestamp: this.destructionTimestamp.toISOString(),
        verified_by: this.verifiedBy,
      },
    };

    if (this.chainOfCustody) {
      data.chain_of_custody = this.chainOfCustody.toDict();
    }

    if (includeSignature && this.signature) {
      data.signature = this.signature;
    }

    return data;
  }

  /**
   * Convert to JSON string.
   */
  toJSON(indent?: number): string {
    return JSON.stringify(this.toDict(), null, indent);
  }

  /**
   * Get canonical byte representation for signing.
   *
   * Uses deterministic JSON serialization (sorted keys, no whitespace)
   * to ensure consistent signatures.
   */
  canonicalBytes(): Buffer {
    const data = this.toDict(false);
    // Sort keys at all levels for deterministic output
    const sortedJson = JSON.stringify(data, Object.keys(data).sort());
    return Buffer.from(sortedJson, 'utf-8');
  }

  /**
   * Compute SHA-256 hash of the certificate.
   */
  computeHash(): string {
    return crypto.createHash('sha256').update(this.canonicalBytes()).digest('hex');
  }
}

/**
 * Authority that issues and verifies destruction certificates.
 *
 * Uses Ed25519 digital signatures for non-repudiation.
 */
export class AttestationAuthority {
  private readonly privateKey: crypto.KeyObject;
  private readonly publicKey: crypto.KeyObject;
  private readonly issuedCertificates: Map<string, DestructionCertificate> = new Map();

  /**
   * Create a new AttestationAuthority.
   *
   * @param authorityId - Identifier for this authority
   */
  constructor(public readonly authorityId: string = 'efsf-local-authority') {
    // Generate Ed25519 key pair
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /**
   * Get the public key as raw bytes.
   */
  get publicKeyBytes(): Buffer {
    return this.publicKey.export({ type: 'spki', format: 'der' });
  }

  /**
   * Get the public key as base64-encoded string.
   */
  get publicKeyB64(): string {
    return this.publicKeyBytes.toString('base64');
  }

  /**
   * Sign a destruction certificate.
   *
   * @param certificate - The certificate to sign
   * @returns The signed certificate
   */
  signCertificate(certificate: DestructionCertificate): DestructionCertificate {
    const message = certificate.canonicalBytes();
    const signature = crypto.sign(null, message, this.privateKey);
    certificate.signature = signature.toString('base64');
    certificate.verifiedBy = this.authorityId;

    this.issuedCertificates.set(certificate.certificateId, certificate);
    return certificate;
  }

  /**
   * Verify a certificate's signature.
   *
   * @param certificate - The certificate to verify
   * @returns true if the signature is valid
   * @throws AttestationError if verification fails
   */
  verifyCertificate(certificate: DestructionCertificate): boolean {
    if (!certificate.signature) {
      throw new AttestationError('Certificate has no signature');
    }

    try {
      const message = certificate.canonicalBytes();
      const signature = Buffer.from(certificate.signature, 'base64');
      return crypto.verify(null, message, this.publicKey, signature);
    } catch (e) {
      throw new AttestationError(`Signature verification failed: ${e}`);
    }
  }

  /**
   * Issue a new signed destruction certificate.
   *
   * @param resourceType - Type of resource (ephemeral_data, sealed_compute, etc.)
   * @param resourceId - Unique identifier of the resource
   * @param classification - Data classification level
   * @param destructionMethod - How the data was destroyed
   * @param chainOfCustody - Optional chain of custody
   * @param metadata - Optional additional metadata
   * @returns The signed certificate
   */
  issueCertificate(
    resourceType: string,
    resourceId: string,
    classification: string,
    destructionMethod: DestructionMethod,
    chainOfCustody: ChainOfCustody | null = null,
    metadata: Record<string, unknown> = {}
  ): DestructionCertificate {
    const resource = new ResourceInfo(resourceType, resourceId, classification, metadata);

    const certificate = DestructionCertificate.create(
      resource,
      destructionMethod,
      this.authorityId,
      chainOfCustody
    );

    return this.signCertificate(certificate);
  }

  /**
   * Retrieve a previously issued certificate by ID.
   *
   * @param certificateId - The certificate ID
   * @returns The certificate or null if not found
   */
  getCertificate(certificateId: string): DestructionCertificate | null {
    return this.issuedCertificates.get(certificateId) ?? null;
  }

  /**
   * List issued certificates with optional filtering.
   *
   * @param resourceId - Optional resource ID to filter by
   * @param since - Optional date to filter certificates issued after
   * @returns List of certificates sorted by destruction timestamp (newest first)
   */
  listCertificates(resourceId?: string, since?: Date): DestructionCertificate[] {
    let certs = Array.from(this.issuedCertificates.values());

    if (resourceId) {
      certs = certs.filter((c) => c.resource.resourceId === resourceId);
    }

    if (since) {
      certs = certs.filter((c) => c.destructionTimestamp >= since);
    }

    return certs.sort(
      (a, b) => b.destructionTimestamp.getTime() - a.destructionTimestamp.getTime()
    );
  }
}
