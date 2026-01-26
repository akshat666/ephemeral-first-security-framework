package io.efsf.certificate;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Certificate Tests")
class CertificateTest {

    @Test
    @DisplayName("ResourceInfo stores resource metadata")
    void testResourceInfo() {
        ResourceInfo info = new ResourceInfo("ephemeral_record", "rec-123", 1024, "redis");

        assertEquals("ephemeral_record", info.getResourceType());
        assertEquals("rec-123", info.getResourceId());
        assertEquals(1024, info.getSizeBytes());
        assertEquals("redis", info.getLocation());
    }

    @Test
    @DisplayName("ResourceInfo serializes to/from Map")
    void testResourceInfoSerialization() {
        ResourceInfo original = new ResourceInfo("test", "id-123", 512, "memory");

        Map<String, Object> map = original.toMap();
        ResourceInfo restored = ResourceInfo.fromMap(map);

        assertEquals(original, restored);
    }

    @Test
    @DisplayName("ChainOfCustody maintains hash chain")
    void testChainOfCustody() {
        ChainOfCustody chain = new ChainOfCustody()
            .addEntry("CREATED", "system", "Record created")
            .addEntry("ACCESSED", "user-123", "Data retrieved")
            .addEntry("DESTROYED", "system", "Record destroyed");

        assertEquals(3, chain.getEntries().size());
        assertTrue(chain.verify());

        // Each entry should have a hash linking to previous
        assertNull(chain.getEntries().get(0).getPreviousHash());
        assertNotNull(chain.getEntries().get(1).getPreviousHash());
        assertEquals(
            chain.getEntries().get(0).getHash(),
            chain.getEntries().get(1).getPreviousHash()
        );
    }

    @Test
    @DisplayName("ChainOfCustody serializes to/from List")
    void testChainOfCustodySerialization() {
        ChainOfCustody original = new ChainOfCustody()
            .addEntry("ACTION1", "actor1")
            .addEntry("ACTION2", "actor2", "details");

        var list = original.toList();
        ChainOfCustody restored = ChainOfCustody.fromList(list);

        assertEquals(original.getEntries().size(), restored.getEntries().size());
        assertTrue(restored.verify());
    }

    @Test
    @DisplayName("DestructionCertificate generates with required fields")
    void testDestructionCertificate() {
        ResourceInfo resource = new ResourceInfo("record", "id-123", 256);

        DestructionCertificate cert = new DestructionCertificate.Builder()
            .resource(resource)
            .method(DestructionMethod.KEY_DESTRUCTION)
            .build();

        assertNotNull(cert.getId());
        assertNotNull(cert.getTimestamp());
        assertEquals(resource, cert.getResource());
        assertEquals(DestructionMethod.KEY_DESTRUCTION, cert.getMethod());
        assertFalse(cert.isSigned());
    }

    @Test
    @DisplayName("DestructionCertificate includes chain of custody")
    void testCertificateWithChain() {
        ChainOfCustody chain = new ChainOfCustody()
            .addEntry("STORED", "efsf")
            .addEntry("DESTROYED", "efsf");

        DestructionCertificate cert = new DestructionCertificate.Builder()
            .resource(new ResourceInfo("record", "id-123", 100))
            .method(DestructionMethod.MEMORY_ZERO)
            .chainOfCustody(chain)
            .build();

        assertNotNull(cert.getChainOfCustody());
        assertEquals(2, cert.getChainOfCustody().getEntries().size());
    }

    @Test
    @DisplayName("DestructionCertificate computes consistent hash")
    void testCertificateHash() {
        DestructionCertificate cert = new DestructionCertificate.Builder()
            .id("test-cert")
            .resource(new ResourceInfo("record", "id-123", 100))
            .method(DestructionMethod.KEY_DESTRUCTION)
            .build();

        String hash1 = cert.computeHash();
        String hash2 = cert.computeHash();

        assertEquals(hash1, hash2);
    }

    @Test
    @DisplayName("DestructionCertificate serializes to/from Map")
    void testCertificateSerialization() {
        DestructionCertificate original = new DestructionCertificate.Builder()
            .resource(new ResourceInfo("record", "id-123", 256))
            .method(DestructionMethod.SECURE_DELETE)
            .chainOfCustody(new ChainOfCustody().addEntry("TEST", "test-actor"))
            .build();

        Map<String, Object> map = original.toMap();
        DestructionCertificate restored = DestructionCertificate.fromMap(map);

        assertEquals(original.getId(), restored.getId());
        assertEquals(original.getMethod(), restored.getMethod());
    }

    @Test
    @DisplayName("AttestationAuthority generates Ed25519 keypair")
    void testAttestationAuthorityCreation() {
        AttestationAuthority authority = AttestationAuthority.create("test-authority");

        assertEquals("test-authority", authority.getId());
        assertEquals(32, authority.getPublicKeyBytes().length);
        assertEquals(32, authority.getPrivateKeyBytes().length);
    }

    @Test
    @DisplayName("AttestationAuthority signs and verifies")
    void testSignAndVerify() {
        AttestationAuthority authority = AttestationAuthority.create();
        byte[] data = "Test data to sign".getBytes();

        byte[] signature = authority.sign(data);
        assertTrue(authority.verify(data, signature));

        // Tampered data should not verify
        byte[] tampered = "Tampered data".getBytes();
        assertFalse(authority.verify(tampered, signature));
    }

    @Test
    @DisplayName("AttestationAuthority signs certificates")
    void testSignCertificate() {
        AttestationAuthority authority = AttestationAuthority.create("signer");

        DestructionCertificate cert = new DestructionCertificate.Builder()
            .resource(new ResourceInfo("record", "id-123", 100))
            .method(DestructionMethod.KEY_DESTRUCTION)
            .build();

        assertFalse(cert.isSigned());

        authority.sign(cert);

        assertTrue(cert.isSigned());
        assertNotNull(cert.getSignature());
        assertTrue(authority.verify(cert));
    }

    @Test
    @DisplayName("AttestationAuthority can be restored from private key")
    void testAuthorityRestoration() {
        AttestationAuthority original = AttestationAuthority.create("original");
        String privateKeyBase64 = original.getPrivateKeyBase64();

        AttestationAuthority restored = AttestationAuthority.fromBase64PrivateKey("restored", privateKeyBase64);

        // Both should produce the same signatures
        byte[] data = "test".getBytes();
        assertArrayEquals(original.sign(data), restored.sign(data));
    }

    @Test
    @DisplayName("Verifier can verify without private key")
    void testVerifierOnly() {
        AttestationAuthority authority = AttestationAuthority.create();
        byte[] data = "Test data".getBytes();
        byte[] signature = authority.sign(data);

        AttestationAuthority.Verifier verifier =
            AttestationAuthority.verifierFromPublicKey("verifier", authority.getPublicKeyBytes());

        assertTrue(verifier.verify(data, signature));
    }
}
