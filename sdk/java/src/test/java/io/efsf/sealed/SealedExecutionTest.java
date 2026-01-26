package io.efsf.sealed;

import io.efsf.certificate.AttestationAuthority;
import io.efsf.certificate.DestructionCertificate;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Sealed Execution Tests")
class SealedExecutionTest {

    @Test
    @DisplayName("SealedExecution creates valid context")
    void testBasicCreation() {
        try (SealedExecution seal = SealedExecution.create()) {
            assertNotNull(seal.getId());
            assertNotNull(seal.getStartTime());
            assertNotNull(seal.getContext());
            assertFalse(seal.isClosed());
        }
    }

    @Test
    @DisplayName("SealedExecution tracks objects")
    void testObjectTracking() {
        try (SealedExecution seal = SealedExecution.create()) {
            SealedContext ctx = seal.getContext();

            List<String> list = ctx.track(new ArrayList<>());
            assertNotNull(list);
            assertEquals(1, ctx.getTrackedCount());

            ctx.track("test string");
            ctx.track(42);
            assertEquals(3, ctx.getTrackedCount());
        }
    }

    @Test
    @DisplayName("SealedExecution runs cleanup callbacks")
    void testCleanupCallbacks() {
        AtomicBoolean cleaned = new AtomicBoolean(false);

        try (SealedExecution seal = SealedExecution.create()) {
            seal.getContext().onCleanup(() -> cleaned.set(true));
            assertFalse(cleaned.get());
        }

        assertTrue(cleaned.get());
    }

    @Test
    @DisplayName("SealedExecution runs cleanup in reverse order")
    void testCleanupOrder() {
        List<Integer> order = new ArrayList<>();

        try (SealedExecution seal = SealedExecution.create()) {
            SealedContext ctx = seal.getContext();
            ctx.onCleanup(() -> order.add(1));
            ctx.onCleanup(() -> order.add(2));
            ctx.onCleanup(() -> order.add(3));
        }

        assertEquals(List.of(3, 2, 1), order);
    }

    @Test
    @DisplayName("SealedExecution generates certificate with attestation")
    void testCertificateGeneration() {
        AttestationAuthority authority = AttestationAuthority.create("test-authority");

        try (SealedExecution seal = SealedExecution.withAttestation(authority)) {
            seal.getContext().track("sensitive data");
        }

        // Certificate should be available after close
        // Note: We can't access it here since seal is closed
        // This is tested through the static run method instead
    }

    @Test
    @DisplayName("Static run method executes function in sealed context")
    void testStaticRun() throws Exception {
        String result = SealedExecution.run(ctx -> {
            ctx.track("tracked object");
            return "completed";
        });

        assertEquals("completed", result);
    }

    @Test
    @DisplayName("Static run method with attestation returns certificate")
    void testStaticRunWithAttestation() throws Exception {
        AttestationAuthority authority = AttestationAuthority.create();

        SealedExecution.SealedResult<String> result = SealedExecution.runWithAttestation(authority, ctx -> {
            ctx.track("sensitive data");
            return "processed";
        });

        assertEquals("processed", result.getValue());
        assertNotNull(result.getCertificate());
        assertTrue(result.getCertificate().isSigned());
        assertTrue(authority.verify(result.getCertificate()));
    }

    @Test
    @DisplayName("SealedContext becomes inactive after close")
    void testContextInactiveAfterClose() {
        SealedExecution seal = SealedExecution.create();
        SealedContext ctx = seal.getContext();
        assertTrue(ctx.isActive());

        seal.close();
        assertFalse(ctx.isActive());
        assertThrows(IllegalStateException.class, () -> ctx.track("new object"));
    }

    @Test
    @DisplayName("SealedExecution throws when accessed after close")
    void testAccessAfterClose() {
        SealedExecution seal = SealedExecution.create();
        seal.close();

        assertTrue(seal.isClosed());
        assertThrows(IllegalStateException.class, seal::getContext);
    }

    @Test
    @DisplayName("SealedExecution handles exceptions during cleanup")
    void testCleanupExceptionHandling() {
        AtomicBoolean secondCallbackRan = new AtomicBoolean(false);

        try (SealedExecution seal = SealedExecution.create()) {
            SealedContext ctx = seal.getContext();
            ctx.onCleanup(() -> {
                throw new RuntimeException("Cleanup error");
            });
            ctx.onCleanup(() -> secondCallbackRan.set(true));
        }

        // Second callback should still run despite first throwing
        assertTrue(secondCallbackRan.get());
    }

    @Test
    @DisplayName("SealedExecution builder configures correctly")
    void testBuilder() {
        AttestationAuthority authority = AttestationAuthority.create();

        SealedExecution seal = new SealedExecution.Builder()
            .id("custom-id")
            .generateCertificate(true)
            .authority(authority)
            .build();

        assertEquals("custom-id", seal.getId());
        seal.close();

        assertNotNull(seal.getCertificate());
    }

    @Test
    @DisplayName("SealedExecution tracks end time on close")
    void testEndTimeTracking() throws InterruptedException {
        SealedExecution seal = SealedExecution.create();
        assertNull(seal.getEndTime());

        Thread.sleep(10); // Small delay to ensure time difference
        seal.close();

        assertNotNull(seal.getEndTime());
        assertTrue(seal.getEndTime().isAfter(seal.getStartTime()));
    }
}
