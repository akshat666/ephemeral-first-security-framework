/**
 * EFSF Exceptions
 *
 * Custom error classes for the Ephemeral-First Security Framework.
 * All errors extend from the base EFSFError class.
 */

/**
 * Base error class for all EFSF errors.
 */
export class EFSFError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EFSFError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Raised when a record cannot be found in the store.
 */
export class RecordNotFoundError extends EFSFError {
  constructor(
    public readonly recordId: string,
    message?: string
  ) {
    super(message ?? `Record not found: ${recordId}`);
    this.name = 'RecordNotFoundError';
  }
}

/**
 * Raised when attempting to access an expired record.
 */
export class RecordExpiredError extends EFSFError {
  constructor(
    public readonly recordId: string,
    public readonly expiredAt?: string
  ) {
    const msg = expiredAt
      ? `Record expired: ${recordId} (expired at ${expiredAt})`
      : `Record expired: ${recordId}`;
    super(msg);
    this.name = 'RecordExpiredError';
  }
}

/**
 * Raised when a cryptographic operation fails.
 */
export class CryptoError extends EFSFError {
  constructor(
    public readonly operation: string,
    message?: string
  ) {
    super(message ?? `Cryptographic operation failed: ${operation}`);
    this.name = 'CryptoError';
  }
}

/**
 * Raised when attestation or certificate operations fail.
 */
export class AttestationError extends EFSFError {
  constructor(message?: string) {
    super(message ?? 'Attestation failed');
    this.name = 'AttestationError';
  }
}

/**
 * Raised when a storage backend operation fails.
 */
export class BackendError extends EFSFError {
  constructor(
    public readonly backend: string,
    message?: string
  ) {
    super(message ?? `Backend error: ${backend}`);
    this.name = 'BackendError';
  }
}

/**
 * Raised when input validation fails.
 */
export class ValidationError extends EFSFError {
  constructor(
    public readonly field: string,
    message?: string
  ) {
    super(message ?? `Validation error: ${field}`);
    this.name = 'ValidationError';
  }
}

/**
 * Raised when a TTL policy is violated.
 */
export class TTLViolationError extends EFSFError {
  constructor(
    public readonly recordId: string,
    public readonly expectedTTL: string,
    public readonly actualTTL?: string
  ) {
    const msg = actualTTL
      ? `TTL violation for record ${recordId}: expected ${expectedTTL}, got ${actualTTL}`
      : `TTL violation for record ${recordId}: expected ${expectedTTL}`;
    super(msg);
    this.name = 'TTLViolationError';
  }
}
