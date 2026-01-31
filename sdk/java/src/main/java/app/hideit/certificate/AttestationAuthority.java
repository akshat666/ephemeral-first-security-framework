package app.hideit.certificate;

import app.hideit.exception.CryptoException;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

/**
 * An authority that can sign destruction certificates using Ed25519.
 */
public final class AttestationAuthority {

    private final String id;
    private final Ed25519PrivateKeyParameters privateKey;
    private final Ed25519PublicKeyParameters publicKey;

    private AttestationAuthority(String id, Ed25519PrivateKeyParameters privateKey, Ed25519PublicKeyParameters publicKey) {
        this.id = id;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * Creates a new attestation authority with a generated key pair.
     *
     * @return a new AttestationAuthority
     */
    public static AttestationAuthority create() {
        return create(UUID.randomUUID().toString());
    }

    /**
     * Creates a new attestation authority with a generated key pair and specified ID.
     *
     * @param id the authority ID
     * @return a new AttestationAuthority
     */
    public static AttestationAuthority create(String id) {
        Ed25519KeyPairGenerator generator = new Ed25519KeyPairGenerator();
        generator.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();

        return new AttestationAuthority(
            id,
            (Ed25519PrivateKeyParameters) keyPair.getPrivate(),
            (Ed25519PublicKeyParameters) keyPair.getPublic()
        );
    }

    /**
     * Creates an attestation authority from existing key material.
     *
     * @param id the authority ID
     * @param privateKeyBytes the private key bytes (32 bytes)
     * @return a new AttestationAuthority
     */
    public static AttestationAuthority fromPrivateKey(String id, byte[] privateKeyBytes) {
        Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(privateKeyBytes, 0);
        Ed25519PublicKeyParameters publicKey = privateKey.generatePublicKey();
        return new AttestationAuthority(id, privateKey, publicKey);
    }

    /**
     * Creates an attestation authority from a Base64-encoded private key.
     *
     * @param id the authority ID
     * @param base64PrivateKey the Base64-encoded private key
     * @return a new AttestationAuthority
     */
    public static AttestationAuthority fromBase64PrivateKey(String id, String base64PrivateKey) {
        byte[] privateKeyBytes = Base64.getDecoder().decode(base64PrivateKey);
        return fromPrivateKey(id, privateKeyBytes);
    }

    public String getId() {
        return id;
    }

    /**
     * Gets the public key bytes.
     *
     * @return the public key bytes (32 bytes)
     */
    public byte[] getPublicKeyBytes() {
        return publicKey.getEncoded();
    }

    /**
     * Gets the public key as a Base64-encoded string.
     *
     * @return the Base64-encoded public key
     */
    public String getPublicKeyBase64() {
        return Base64.getEncoder().encodeToString(getPublicKeyBytes());
    }

    /**
     * Gets the private key bytes.
     *
     * @return the private key bytes (32 bytes)
     */
    public byte[] getPrivateKeyBytes() {
        return privateKey.getEncoded();
    }

    /**
     * Gets the private key as a Base64-encoded string.
     *
     * @return the Base64-encoded private key
     */
    public String getPrivateKeyBase64() {
        return Base64.getEncoder().encodeToString(getPrivateKeyBytes());
    }

    /**
     * Signs data using Ed25519.
     *
     * @param data the data to sign
     * @return the signature bytes
     */
    public byte[] sign(byte[] data) {
        try {
            Ed25519Signer signer = new Ed25519Signer();
            signer.init(true, privateKey);
            signer.update(data, 0, data.length);
            return signer.generateSignature();
        } catch (Exception e) {
            throw new CryptoException("Signing failed", e);
        }
    }

    /**
     * Signs a destruction certificate.
     *
     * @param certificate the certificate to sign
     * @return the signed certificate (same instance with signature added)
     */
    public DestructionCertificate sign(DestructionCertificate certificate) {
        byte[] signature = sign(certificate.getCanonicalBytes());
        String signatureBase64 = Base64.getEncoder().encodeToString(signature);
        certificate.setSignature(signatureBase64, id);
        return certificate;
    }

    /**
     * Verifies a signature using this authority's public key.
     *
     * @param data the data that was signed
     * @param signature the signature to verify
     * @return true if the signature is valid
     */
    public boolean verify(byte[] data, byte[] signature) {
        try {
            Ed25519Signer verifier = new Ed25519Signer();
            verifier.init(false, publicKey);
            verifier.update(data, 0, data.length);
            return verifier.verifySignature(signature);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Verifies a destruction certificate's signature.
     *
     * @param certificate the certificate to verify
     * @return true if the signature is valid
     */
    public boolean verify(DestructionCertificate certificate) {
        if (!certificate.isSigned()) {
            return false;
        }
        byte[] signature = Base64.getDecoder().decode(certificate.getSignature());
        return verify(certificate.getCanonicalBytes(), signature);
    }

    /**
     * Creates a verifier from a public key (cannot sign, only verify).
     *
     * @param id the authority ID
     * @param publicKeyBytes the public key bytes
     * @return an AttestationAuthority that can only verify
     */
    public static Verifier verifierFromPublicKey(String id, byte[] publicKeyBytes) {
        Ed25519PublicKeyParameters publicKey = new Ed25519PublicKeyParameters(publicKeyBytes, 0);
        return new Verifier(id, publicKey);
    }

    /**
     * A verifier that can only verify signatures, not create them.
     */
    public static final class Verifier {
        private final String id;
        private final Ed25519PublicKeyParameters publicKey;

        private Verifier(String id, Ed25519PublicKeyParameters publicKey) {
            this.id = id;
            this.publicKey = publicKey;
        }

        public String getId() {
            return id;
        }

        public byte[] getPublicKeyBytes() {
            return publicKey.getEncoded();
        }

        public boolean verify(byte[] data, byte[] signature) {
            try {
                Ed25519Signer verifier = new Ed25519Signer();
                verifier.init(false, publicKey);
                verifier.update(data, 0, data.length);
                return verifier.verifySignature(signature);
            } catch (Exception e) {
                return false;
            }
        }

        public boolean verify(DestructionCertificate certificate) {
            if (!certificate.isSigned()) {
                return false;
            }
            byte[] signature = Base64.getDecoder().decode(certificate.getSignature());
            return verify(certificate.getCanonicalBytes(), signature);
        }
    }

    @Override
    public String toString() {
        return "AttestationAuthority{" +
            "id='" + id + '\'' +
            '}';
    }
}
