package app.hideit.sealed;

import app.hideit.certificate.*;

import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.Callable;

/**
 * A sealed execution context that guarantees cleanup of all tracked state on exit.
 * Implements AutoCloseable for use with try-with-resources.
 *
 * <pre>
 * try (SealedExecution seal = SealedExecution.create()) {
 *     // Work with sensitive data
 *     SealedContext ctx = seal.getContext();
 *     byte[] sensitiveData = ctx.track(loadSensitiveData());
 *     // Process data...
 * } // All tracked objects cleaned up here
 * </pre>
 */
public final class SealedExecution implements AutoCloseable {

    private final String id;
    private final Instant startTime;
    private final SealedContext context;
    private final boolean generateCertificate;
    private final AttestationAuthority authority;

    private Instant endTime;
    private DestructionCertificate certificate;
    private boolean closed;

    private SealedExecution(Builder builder) {
        this.id = builder.id != null ? builder.id : UUID.randomUUID().toString();
        this.startTime = Instant.now();
        this.context = new SealedContext();
        this.generateCertificate = builder.generateCertificate;
        this.authority = builder.authority;
        this.closed = false;
    }

    /**
     * Creates a new sealed execution context.
     *
     * @return a new SealedExecution
     */
    public static SealedExecution create() {
        return new Builder().build();
    }

    /**
     * Creates a new sealed execution with certificate generation.
     *
     * @param authority the attestation authority for signing certificates
     * @return a new SealedExecution
     */
    public static SealedExecution withAttestation(AttestationAuthority authority) {
        return new Builder()
            .generateCertificate(true)
            .authority(authority)
            .build();
    }

    /**
     * Runs a function within a sealed execution context.
     *
     * @param fn the function to run
     * @param <T> the return type
     * @return the result of the function
     * @throws Exception if the function throws
     */
    public static <T> T run(SealedFunction<SealedContext, T> fn) throws Exception {
        try (SealedExecution seal = create()) {
            return fn.apply(seal.getContext());
        }
    }

    /**
     * Runs a function within a sealed execution context with certificate generation.
     *
     * @param authority the attestation authority
     * @param fn the function to run
     * @param <T> the return type
     * @return a result containing both the value and the certificate
     * @throws Exception if the function throws
     */
    public static <T> SealedResult<T> runWithAttestation(AttestationAuthority authority, SealedFunction<SealedContext, T> fn) throws Exception {
        SealedExecution seal = withAttestation(authority);
        T result;
        try {
            result = fn.apply(seal.getContext());
        } finally {
            seal.close();
        }
        return new SealedResult<>(result, seal.getCertificate());
    }

    public String getId() {
        return id;
    }

    public Instant getStartTime() {
        return startTime;
    }

    public Instant getEndTime() {
        return endTime;
    }

    public SealedContext getContext() {
        ensureNotClosed();
        return context;
    }

    public DestructionCertificate getCertificate() {
        return certificate;
    }

    public boolean isClosed() {
        return closed;
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }

        try {
            // Perform cleanup
            context.cleanup();
            endTime = Instant.now();

            // Generate certificate if requested
            if (generateCertificate) {
                certificate = generateCertificate();
            }
        } finally {
            closed = true;
        }
    }

    private DestructionCertificate generateCertificate() {
        ResourceInfo resource = new ResourceInfo(
            "sealed_execution",
            id,
            context.getTrackedCount()
        );

        ChainOfCustody chain = new ChainOfCustody()
            .addEntry("SEALED_EXECUTION_START", "efsf-java", "Started sealed execution")
            .addEntry("SEALED_EXECUTION_END", "efsf-java", "Completed sealed execution and cleaned up");

        DestructionCertificate cert = new DestructionCertificate.Builder()
            .resource(resource)
            .method(DestructionMethod.MEMORY_ZERO)
            .chainOfCustody(chain)
            .build();

        if (authority != null) {
            authority.sign(cert);
        }

        return cert;
    }

    private void ensureNotClosed() {
        if (closed) {
            throw new IllegalStateException("SealedExecution has been closed");
        }
    }

    /**
     * A function that can throw exceptions.
     */
    @FunctionalInterface
    public interface SealedFunction<T, R> {
        R apply(T t) throws Exception;
    }

    /**
     * A result from a sealed execution with optional certificate.
     */
    public static final class SealedResult<T> {
        private final T value;
        private final DestructionCertificate certificate;

        public SealedResult(T value, DestructionCertificate certificate) {
            this.value = value;
            this.certificate = certificate;
        }

        public T getValue() {
            return value;
        }

        public DestructionCertificate getCertificate() {
            return certificate;
        }
    }

    /**
     * Builder for SealedExecution.
     */
    public static class Builder {
        private String id;
        private boolean generateCertificate;
        private AttestationAuthority authority;

        public Builder id(String id) {
            this.id = id;
            return this;
        }

        public Builder generateCertificate(boolean generateCertificate) {
            this.generateCertificate = generateCertificate;
            return this;
        }

        public Builder authority(AttestationAuthority authority) {
            this.authority = authority;
            return this;
        }

        public SealedExecution build() {
            return new SealedExecution(this);
        }
    }
}
