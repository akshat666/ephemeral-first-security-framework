/**
 * EFSF - Ephemeral-First Security Framework
 *
 * A framework for building systems where data transience is a first-class
 * security primitive. Implements the core thesis that "data that no longer
 * exists cannot be stolen."
 *
 * @packageDocumentation
 */

// ============================================================
// Core Store
// ============================================================

export { EphemeralStore } from './store.js';
export type {
  EphemeralStoreOptions,
  PutOptions,
  StoreStats,
  StorageBackend,
} from './store.js';
export { MemoryBackend, RedisBackend, createBackend } from './store.js';

// ============================================================
// Record Types
// ============================================================

export {
  EphemeralRecord,
  DataClassification,
  parseTTL,
  getDefaultTTL,
  getMaxTTL,
} from './record.js';
export type { EphemeralRecordData, EphemeralRecordCreateOptions } from './record.js';

// ============================================================
// Destruction Certificates
// ============================================================

export {
  DestructionCertificate,
  DestructionMethod,
  ResourceInfo,
  ChainOfCustody,
  AttestationAuthority,
} from './certificate.js';
export type {
  DestructionCertificateData,
  ResourceInfoData,
  ChainOfCustodyData,
  AccessEvent,
} from './certificate.js';

// ============================================================
// Sealed Execution
// ============================================================

export {
  SealedExecution,
  SealedContext,
  sealed,
  secureZeroMemory,
} from './sealed.js';
export type {
  SealedExecutionOptions,
  SealedDecoratorOptions,
  SealedContextOptions,
} from './sealed.js';

// ============================================================
// Cryptography
// ============================================================

export {
  CryptoProvider,
  EncryptedPayload,
  DataEncryptionKey,
  constantTimeCompare,
} from './crypto.js';
export type { EncryptedPayloadData } from './crypto.js';

// ============================================================
// Exceptions
// ============================================================

export {
  EFSFError,
  RecordNotFoundError,
  RecordExpiredError,
  CryptoError,
  AttestationError,
  BackendError,
  ValidationError,
  TTLViolationError,
} from './exceptions.js';

// ============================================================
// Version
// ============================================================

/** SDK version */
export const VERSION = '0.2.0';
