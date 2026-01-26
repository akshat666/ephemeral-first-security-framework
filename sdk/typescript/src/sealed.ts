/**
 * EFSF Sealed Execution
 *
 * Provides sealed execution contexts where all state is guaranteed
 * to be destroyed upon exit.
 *
 * Note: In pure JavaScript without hardware TEE support, memory zeroing
 * is best-effort. For production use with sensitive data, integrate
 * with Intel SGX, AMD SEV, or AWS Nitro Enclaves.
 */

import { v4 as uuidv4 } from 'uuid';
import {
  AttestationAuthority,
  ChainOfCustody,
  DestructionCertificate,
  DestructionMethod,
  ResourceInfo,
} from './certificate.js';

/**
 * Attempt to securely zero memory containing sensitive data.
 *
 * WARNING: This is best-effort in JavaScript due to:
 * - Garbage collection may have already copied data
 * - String interning
 * - Immutable types cannot be modified
 *
 * For true security guarantees, use hardware enclaves or HSMs.
 *
 * @param data - The data to zero
 */
export function secureZeroMemory(data: unknown): void {
  if (data instanceof Uint8Array || Buffer.isBuffer(data)) {
    (data as Uint8Array).fill(0);
  } else if (Array.isArray(data)) {
    for (let i = 0; i < data.length; i++) {
      secureZeroMemory(data[i]);
    }
    data.length = 0;
  } else if (data && typeof data === 'object') {
    for (const key of Object.keys(data)) {
      secureZeroMemory((data as Record<string, unknown>)[key]);
      delete (data as Record<string, unknown>)[key];
    }
  }
  // For primitives (string, number, boolean), we cannot zero them
}

/**
 * Options for creating a SealedContext.
 */
export interface SealedContextOptions {
  executionId?: string;
}

/**
 * Execution context for sealed code blocks.
 *
 * Tracks objects for cleanup and allows registration of
 * cleanup callbacks.
 */
export class SealedContext {
  public readonly executionId: string;
  public readonly startedAt: Date;
  private readonly sensitiveRefs: WeakRef<object>[] = [];
  private readonly cleanupCallbacks: Array<() => void> = [];

  constructor(options: SealedContextOptions = {}) {
    this.executionId = options.executionId ?? uuidv4();
    this.startedAt = new Date();
  }

  /**
   * Track an object for cleanup on context exit.
   *
   * @param obj - Object to track
   * @returns The same object for chaining
   */
  track<T extends object>(obj: T): T {
    try {
      this.sensitiveRefs.push(new WeakRef(obj));
    } catch {
      // Some objects cannot have weak references
    }
    return obj;
  }

  /**
   * Register a cleanup callback to run on context exit.
   *
   * @param callback - Function to call during cleanup
   */
  onCleanup(callback: () => void): void {
    this.cleanupCallbacks.push(callback);
  }

  /**
   * Internal: Run cleanup routines.
   */
  _cleanup(): void {
    // Run registered callbacks
    for (const callback of this.cleanupCallbacks) {
      try {
        callback();
      } catch {
        // Don't let cleanup errors propagate
      }
    }

    // Attempt to zero tracked objects
    for (const ref of this.sensitiveRefs) {
      const obj = ref.deref();
      if (obj !== undefined) {
        secureZeroMemory(obj);
      }
    }

    // Clear our own state
    this.sensitiveRefs.length = 0;
    this.cleanupCallbacks.length = 0;

    // Request garbage collection if available (V8 --expose-gc flag required)
    const g = global as typeof globalThis & { gc?: () => void };
    if (typeof g.gc === 'function') {
      g.gc();
    }
  }
}

/**
 * Options for SealedExecution.
 */
export interface SealedExecutionOptions {
  /** Generate destruction certificate on exit */
  attestation?: boolean;
  /** Custom attestation authority */
  authority?: AttestationAuthority;
  /** Additional metadata for the certificate */
  metadata?: Record<string, unknown>;
}

/**
 * Sealed execution manager that guarantees state destruction on exit.
 *
 * Can be used with the run() method for automatic cleanup:
 * ```typescript
 * const seal = new SealedExecution({ attestation: true });
 * const result = await seal.run((ctx) => {
 *   const sensitive = ctx.track({ ssn: '123-45-6789' });
 *   return processData(sensitive);
 * });
 * // All tracked state is now destroyed
 * // seal.certificate contains the destruction proof
 * ```
 */
export class SealedExecution {
  private static defaultAuthority: AttestationAuthority | null = null;

  public readonly attestation: boolean;
  public readonly authority: AttestationAuthority | null;
  public readonly metadata: Record<string, unknown>;
  public context: SealedContext | null = null;
  public certificate: DestructionCertificate | null = null;
  private chainOfCustody: ChainOfCustody | null = null;

  constructor(options: SealedExecutionOptions = {}) {
    this.attestation = options.attestation ?? false;
    this.metadata = options.metadata ?? {};

    if (this.attestation) {
      if (options.authority) {
        this.authority = options.authority;
      } else {
        if (!SealedExecution.defaultAuthority) {
          SealedExecution.defaultAuthority = new AttestationAuthority();
        }
        this.authority = SealedExecution.defaultAuthority;
      }
    } else {
      this.authority = options.authority ?? null;
    }
  }

  /**
   * Enter the sealed execution context.
   *
   * Use with try/finally or the run() method for automatic cleanup.
   *
   * @returns The sealed context for tracking objects
   */
  enter(): SealedContext {
    this.context = new SealedContext();

    if (this.attestation) {
      this.chainOfCustody = new ChainOfCustody(new Date(), 'sealed_execution');
      this.chainOfCustody.addAccess('sealed_execution', 'context_enter');
    }

    return this.context;
  }

  /**
   * Exit the sealed execution context and destroy all state.
   *
   * @param error - Optional error if exiting due to an exception
   */
  exit(error?: Error): void {
    if (!this.context) {
      return;
    }

    // Record exit in chain of custody
    if (this.chainOfCustody) {
      const action = error ? 'context_exit_error' : 'context_exit_normal';
      this.chainOfCustody.addAccess('sealed_execution', action);
    }

    // Perform cleanup
    this.context._cleanup();

    // Generate destruction certificate if requested
    if (this.attestation && this.authority) {
      const resource = new ResourceInfo(
        'sealed_compute',
        this.context.executionId,
        'TRANSIENT',
        {
          started_at: this.context.startedAt.toISOString(),
          duration_ms: Date.now() - this.context.startedAt.getTime(),
          error: error ? String(error) : null,
          ...this.metadata,
        }
      );

      const cert = DestructionCertificate.create(
        resource,
        DestructionMethod.MEMORY_ZERO,
        this.authority.authorityId,
        this.chainOfCustody
      );

      this.certificate = this.authority.signCertificate(cert);
    }

    // Clear context reference
    this.context = null;
  }

  /**
   * Run a function within the sealed context.
   *
   * Automatically handles enter/exit and cleanup.
   *
   * @param fn - Function to execute within the sealed context
   * @returns The function's return value
   */
  async run<T>(fn: (ctx: SealedContext) => T | Promise<T>): Promise<T> {
    const ctx = this.enter();
    try {
      const result = await fn(ctx);
      this.exit();
      return result;
    } catch (error) {
      this.exit(error as Error);
      throw error;
    }
  }
}

/**
 * Options for the sealed decorator.
 */
export interface SealedDecoratorOptions {
  /** Generate destruction certificate on exit */
  attestation?: boolean;
  /** Custom attestation authority */
  authority?: AttestationAuthority;
  /** Additional metadata for the certificate */
  metadata?: Record<string, unknown>;
}

/**
 * Higher-order function that wraps a function in a sealed execution context.
 *
 * All arguments are tracked for cleanup, and the function executes within
 * a sealed context that is destroyed on return.
 *
 * @example
 * ```typescript
 * const processPayment = sealed({ attestation: true })(
 *   async (cardNumber: string, amount: number) => {
 *     // All local state destroyed on return
 *     return { success: true, masked: `****${cardNumber.slice(-4)}` };
 *   }
 * );
 *
 * const result = await processPayment('4111-1111-1111-1234', 99.99);
 * // result._destruction_certificate contains the proof
 * ```
 *
 * @param options - Sealed execution options
 * @returns A function wrapper
 */
export function sealed<TArgs extends unknown[], TReturn>(
  options: SealedDecoratorOptions = {}
) {
  return function (
    fn: (...args: TArgs) => TReturn | Promise<TReturn>
  ): (...args: TArgs) => Promise<TReturn> {
    return async function (...args: TArgs): Promise<TReturn> {
      const seal = new SealedExecution({
        attestation: options.attestation,
        authority: options.authority,
        metadata: {
          function: fn.name || 'anonymous',
          ...options.metadata,
        },
      });

      const result = await seal.run(async (ctx) => {
        // Track arguments that are objects
        for (const arg of args) {
          if (arg && typeof arg === 'object') {
            ctx.track(arg as object);
          }
        }

        return fn(...args);
      });

      // Attach certificate to result if it's an object and attestation is enabled
      // Certificate is available after run() completes (exit() has been called)
      if (
        options.attestation &&
        seal.certificate &&
        result &&
        typeof result === 'object'
      ) {
        (result as Record<string, unknown>)['_destruction_certificate'] =
          seal.certificate.toDict();
      }

      return result;
    };
  };
}
