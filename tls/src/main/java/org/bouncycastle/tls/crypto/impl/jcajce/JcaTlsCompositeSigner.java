package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.PrivateKey;

import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

/**
 * A {@link TlsSigner} for X9.146 QTLS CKS 4 composite signatures (draft-reddy-tls-composite-mldsa): it signs
 * with a single composite private key, producing one composite signature (both the ML-DSA and the classical
 * component), via Bouncy Castle's JCA composite-signature provider. The TLS composite {@link SignatureScheme}
 * codepoint maps to the draft-ounsworth composite algorithm OID that identifies the JCA {@code Signature}.
 * <p>
 * Only {@link SignatureScheme#mldsa44_ecdsa_secp256r1_sha256} (0x0907) is wired so far; its SHA-256 matches
 * BC's {@code id_MLDSA44_ECDSA_P256_SHA256} combination. The other composite codepoints need per-codepoint
 * OID mapping. TLS 1.3 always uses the stream signer, so {@link #generateRawSignature} is unsupported.
 */
public class JcaTlsCompositeSigner
    implements TlsSigner
{
    private final JcaTlsCrypto crypto;
    private final PrivateKey privateKey;
    private final int signatureScheme;

    public JcaTlsCompositeSigner(JcaTlsCrypto crypto, PrivateKey privateKey, int signatureScheme)
    {
        if (null == crypto)
        {
            throw new NullPointerException("crypto");
        }
        if (null == privateKey)
        {
            throw new NullPointerException("privateKey");
        }
        if (!SignatureScheme.isComposite(signatureScheme))
        {
            throw new IllegalArgumentException(
                "'signatureScheme' " + SignatureScheme.getText(signatureScheme) + " is not composite");
        }

        this.crypto = crypto;
        this.privateKey = privateKey;
        this.signatureScheme = signatureScheme;
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) throws IOException
    {
        if (algorithm == null || SignatureScheme.from(algorithm) != signatureScheme)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        return crypto.createStreamSigner(getCompositeAlgorithmName(signatureScheme), null, privateKey, true);
    }

    static String getCompositeAlgorithmName(int signatureScheme)
    {
        switch (signatureScheme)
        {
        case SignatureScheme.mldsa44_ecdsa_secp256r1_sha256:
            return IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256.getId();
        default:
            throw new IllegalArgumentException(
                "no composite algorithm mapping for " + SignatureScheme.getText(signatureScheme));
        }
    }
}
