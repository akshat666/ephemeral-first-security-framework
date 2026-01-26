import { describe, it, expect } from 'vitest';
import {
  SealedContext,
  SealedExecution,
  sealed,
  secureZeroMemory,
} from '../src/sealed.js';

describe('secureZeroMemory', () => {
  it('should zero Buffer content', () => {
    const buffer = Buffer.from('sensitive data');
    secureZeroMemory(buffer);

    for (const byte of buffer) {
      expect(byte).toBe(0);
    }
  });

  it('should zero Uint8Array content', () => {
    const array = new Uint8Array([1, 2, 3, 4, 5]);
    secureZeroMemory(array);

    for (const byte of array) {
      expect(byte).toBe(0);
    }
  });

  it('should clear array', () => {
    const array = [1, 2, 3];
    secureZeroMemory(array);
    expect(array).toHaveLength(0);
  });

  it('should clear object properties', () => {
    const obj: Record<string, unknown> = { a: 1, b: 'secret', c: { nested: true } };
    secureZeroMemory(obj);
    expect(Object.keys(obj)).toHaveLength(0);
  });

  it('should handle primitives gracefully', () => {
    // Should not throw for primitives (even though they can't be zeroed)
    expect(() => secureZeroMemory('string')).not.toThrow();
    expect(() => secureZeroMemory(123)).not.toThrow();
    expect(() => secureZeroMemory(null)).not.toThrow();
    expect(() => secureZeroMemory(undefined)).not.toThrow();
  });
});

describe('SealedContext', () => {
  it('should create context with unique ID', () => {
    const ctx1 = new SealedContext();
    const ctx2 = new SealedContext();

    expect(ctx1.executionId).toBeDefined();
    expect(ctx2.executionId).toBeDefined();
    expect(ctx1.executionId).not.toBe(ctx2.executionId);
    expect(ctx1.startedAt).toBeInstanceOf(Date);
  });

  it('should accept custom execution ID', () => {
    const ctx = new SealedContext({ executionId: 'custom-id' });
    expect(ctx.executionId).toBe('custom-id');
  });

  it('should track objects', () => {
    const ctx = new SealedContext();
    const obj = { data: 'test' };

    const tracked = ctx.track(obj);
    expect(tracked).toBe(obj);
  });

  it('should run cleanup callbacks', () => {
    const ctx = new SealedContext();
    let cleanupCalled = false;

    ctx.onCleanup(() => {
      cleanupCalled = true;
    });

    ctx._cleanup();
    expect(cleanupCalled).toBe(true);
  });

  it('should zero tracked objects on cleanup', () => {
    const ctx = new SealedContext();
    const sensitiveData = Buffer.from('secret');

    ctx.track(sensitiveData);
    ctx._cleanup();

    // Check that buffer was zeroed
    for (const byte of sensitiveData) {
      expect(byte).toBe(0);
    }
  });
});

describe('SealedExecution', () => {
  it('should run function and cleanup', async () => {
    const seal = new SealedExecution();

    const result = await seal.run((ctx) => {
      ctx.track({ sensitive: 'data' });
      return 42;
    });

    expect(result).toBe(42);
    expect(seal.context).toBeNull();
  });

  it('should handle async functions', async () => {
    const seal = new SealedExecution();

    const result = await seal.run(async () => {
      await new Promise((resolve) => setTimeout(resolve, 10));
      return 'async result';
    });

    expect(result).toBe('async result');
  });

  it('should cleanup on error', async () => {
    const seal = new SealedExecution();
    const tracked = Buffer.from('sensitive');

    await expect(
      seal.run((ctx) => {
        ctx.track(tracked);
        throw new Error('Test error');
      })
    ).rejects.toThrow('Test error');

    expect(seal.context).toBeNull();

    // Check that buffer was zeroed
    for (const byte of tracked) {
      expect(byte).toBe(0);
    }
  });

  it('should generate certificate with attestation', async () => {
    const seal = new SealedExecution({ attestation: true });

    await seal.run(() => {
      return 'done';
    });

    expect(seal.certificate).not.toBeNull();
    expect(seal.certificate?.destructionMethod).toBe('memory_zero');
    expect(seal.certificate?.signature).toBeDefined();
  });

  it('should not generate certificate without attestation', async () => {
    const seal = new SealedExecution({ attestation: false });

    await seal.run(() => 'done');

    expect(seal.certificate).toBeNull();
  });

  it('should record error in certificate metadata', async () => {
    const seal = new SealedExecution({ attestation: true });

    await expect(
      seal.run(() => {
        throw new Error('Test failure');
      })
    ).rejects.toThrow();

    expect(seal.certificate?.resource.metadata.error).toBe('Error: Test failure');
  });

  it('should use manual enter/exit', () => {
    const seal = new SealedExecution({ attestation: true });

    const ctx = seal.enter();
    const tracked = ctx.track({ data: 'test' });

    seal.exit();

    expect(seal.context).toBeNull();
    expect(seal.certificate).not.toBeNull();
    expect(Object.keys(tracked)).toHaveLength(0); // Should be cleared
  });
});

describe('sealed decorator', () => {
  it('should wrap function in sealed context', async () => {
    const fn = sealed()(async (x: number) => x * 2);

    const result = await fn(21);
    expect(result).toBe(42);
  });

  it('should attach certificate to result object', async () => {
    const fn = sealed({ attestation: true })(async () => {
      return { success: true };
    });

    const result = await fn();
    expect(result.success).toBe(true);
    expect(result._destruction_certificate).toBeDefined();
  });

  it('should track arguments', async () => {
    const trackedArgs: object[] = [];

    const fn = sealed({ attestation: true })(async (data: { value: string }) => {
      trackedArgs.push(data);
      return { processed: true };
    });

    const input = { value: 'sensitive' };
    await fn(input);

    // The input object should have been tracked and cleared
    expect(Object.keys(input)).toHaveLength(0);
  });

  it('should include function name in metadata', async () => {
    async function namedFunction(): Promise<Record<string, unknown>> {
      return { done: true };
    }

    const fn = sealed({ attestation: true })(namedFunction);
    const result = await fn();

    const cert = result._destruction_certificate as Record<string, unknown>;
    const resource = cert.resource as Record<string, unknown>;
    const metadata = resource.metadata as Record<string, unknown>;

    expect(metadata.function).toBe('namedFunction');
  });
});
