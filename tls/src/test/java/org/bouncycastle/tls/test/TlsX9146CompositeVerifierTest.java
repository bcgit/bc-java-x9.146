package org.bouncycastle.tls.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import junit.framework.TestCase;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.crypto.Tls13Verifier;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCompositeSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsRawKeyCertificate;
import org.bouncycastle.util.Strings;

/**
 * X9.146 QTLS CKS 4 (Composite) crypto bridge: verifies that a genuine composite signature (ML-DSA-44 +
 * ECDSA P-256 / SHA-256, draft-reddy-tls-composite-mldsa codepoint 0x0907) is verified as a whole -- both
 * components -- through the TLS crypto abstraction ({@link JcaTlsRawKeyCertificate#createVerifier(int)} /
 * {@link Tls13Verifier}), using BC's JCA composite-signature provider. This exercises the real composite
 * verification path (not the interim single-component split of the lightweight crypto). Only the composite
 * public key (SubjectPublicKeyInfo) is needed for verification, so no certificate is built.
 */
public class TlsX9146CompositeVerifierTest
    extends TestCase
{
    private static final Provider BC = new BouncyCastleProvider();

    protected void setUp()
    {
        // BC's composite-signature SPI resolves its component algorithms by the "BC" provider name, so the
        // provider must be registered (not merely passed as an instance).
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(BC);
        }
    }

    public void testCompositeVerifierRoundTrip()
        throws Exception
    {
        ASN1ObjectIdentifier compositeOid = IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256;

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(compositeOid.getId(), BC);
        KeyPair keyPair = kpg.generateKeyPair();

        JcaTlsCrypto crypto = new JcaTlsCryptoProvider().setProvider(BC).create(new SecureRandom());
        // The public key's X.509 SubjectPublicKeyInfo is all that verification needs.
        JcaTlsRawKeyCertificate tlsCertificate =
            new JcaTlsRawKeyCertificate(crypto, keyPair.getPublic().getEncoded());

        byte[] message = Strings.toByteArray("X9.146 composite CertificateVerify transcript stand-in");

        // Produce a genuine composite signature over the message (both components) via raw JCA.
        Signature signer = Signature.getInstance(compositeOid.getId(), BC);
        signer.initSign(keyPair.getPrivate());
        signer.update(message);
        byte[] signature = signer.sign();

        // A correct composite signature verifies through the TLS Tls13Verifier obtained for CKS-4's codepoint.
        Tls13Verifier verifier = tlsCertificate.createVerifier(SignatureScheme.mldsa44_ecdsa_secp256r1_sha256);
        verifier.getOutputStream().write(message);
        assertTrue("composite signature should verify through the TLS crypto layer",
            verifier.verifySignature(signature));

        // A signature over different data must be rejected (proving the signature is actually checked, not
        // silently ignored, and that both components participate).
        Tls13Verifier verifier2 = tlsCertificate.createVerifier(SignatureScheme.mldsa44_ecdsa_secp256r1_sha256);
        verifier2.getOutputStream().write(Strings.toByteArray("a different transcript"));
        assertFalse("composite signature over different data must be rejected",
            verifier2.verifySignature(signature));
    }

    public void testCompositeSignAndVerifyThroughTlsLayer()
        throws Exception
    {
        ASN1ObjectIdentifier compositeOid = IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256;

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(compositeOid.getId(), BC);
        KeyPair keyPair = kpg.generateKeyPair();

        JcaTlsCrypto crypto = new JcaTlsCryptoProvider().setProvider(BC).create(new SecureRandom());

        byte[] message = Strings.toByteArray("X9.146 composite CertificateVerify transcript stand-in");
        SignatureAndHashAlgorithm algorithm =
            SignatureScheme.getSignatureAndHashAlgorithm(SignatureScheme.mldsa44_ecdsa_secp256r1_sha256);

        // Sign through the TLS composite signer (the credential's stream-signer path).
        JcaTlsCompositeSigner signer = new JcaTlsCompositeSigner(crypto, keyPair.getPrivate(),
            SignatureScheme.mldsa44_ecdsa_secp256r1_sha256);
        TlsStreamSigner streamSigner = signer.getStreamSigner(algorithm);
        streamSigner.getOutputStream().write(message);
        byte[] signature = streamSigner.getSignature();

        // Verify through the TLS composite verifier: the signer's output must be accepted end-to-end.
        JcaTlsRawKeyCertificate tlsCertificate =
            new JcaTlsRawKeyCertificate(crypto, keyPair.getPublic().getEncoded());
        Tls13Verifier verifier = tlsCertificate.createVerifier(SignatureScheme.mldsa44_ecdsa_secp256r1_sha256);
        verifier.getOutputStream().write(message);
        assertTrue("composite signature from the TLS signer should verify through the TLS verifier",
            verifier.verifySignature(signature));
    }
}
