package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.tls.crypto.impl.TlsImplUtils;

/**
 * Container class for generating signatures that carries the signature type, parameters, public key certificate and public key's associated signer object.
 */
public class DefaultTlsCredentialedSigner
    implements TlsCredentialedSigner
{
    protected TlsCryptoParameters cryptoParams;
    protected Certificate certificate;
    protected SignatureAndHashAlgorithm signatureAndHashAlgorithm;
    protected SignatureAndHashAlgorithm altSignatureAndHashAlgorithm;

    protected TlsSigner signer;
    protected TlsSigner altSigner;

    public DefaultTlsCredentialedSigner(TlsCryptoParameters cryptoParams, TlsSigner signer, Certificate certificate,
                                        SignatureAndHashAlgorithm signatureAndHashAlgorithm)
    {
        this(cryptoParams, signer, null, certificate, signatureAndHashAlgorithm, null);
    }
    public DefaultTlsCredentialedSigner(TlsCryptoParameters cryptoParams, TlsSigner signer, TlsSigner altSigner, Certificate certificate,
                                        SignatureAndHashAlgorithm signatureAndHashAlgorithm, SignatureAndHashAlgorithm altSignatureAndHashAlgorithm)
    {
        if (certificate == null)
        {
            throw new IllegalArgumentException("'certificate' cannot be null");
        }
        if (certificate.isEmpty())
        {
            throw new IllegalArgumentException("'certificate' cannot be empty");
        }
        if (signer == null)
        {
            throw new IllegalArgumentException("'signer' cannot be null");
        }
        this.signer = signer;
        this.altSigner = altSigner;

        this.cryptoParams = cryptoParams;
        this.certificate = certificate;
        this.signatureAndHashAlgorithm = signatureAndHashAlgorithm;
        this.altSignatureAndHashAlgorithm = altSignatureAndHashAlgorithm;
    }

    public Certificate getCertificate()
    {
        return certificate;
    }

    public byte[] generateRawSignature(byte[] hash)
        throws IOException
    {
        return signer.generateRawSignature(getEffectiveAlgorithm(), hash);
    }

    public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm()
    {
        return signatureAndHashAlgorithm;
    }
    public SignatureAndHashAlgorithm getAltSignatureAndHashAlgorithm()
    {
        return altSignatureAndHashAlgorithm;
    }

    public TlsStreamSigner getStreamSigner() throws IOException
    {
        return signer.getStreamSigner(getEffectiveAlgorithm());
    }
    public TlsStreamSigner getAltStreamSigner() throws IOException
    {
        return altSigner.getStreamSigner(getAltEffectiveAlgorithm());
    }

    protected SignatureAndHashAlgorithm getEffectiveAlgorithm()
    {
        SignatureAndHashAlgorithm algorithm = null;
        if (TlsImplUtils.isTLSv12(cryptoParams))
        {
            algorithm = getSignatureAndHashAlgorithm();
            if (algorithm == null)
            {
                throw new IllegalStateException("'signatureAndHashAlgorithm' cannot be null for (D)TLS 1.2+");
            }
        }
        return algorithm;
    }
    protected SignatureAndHashAlgorithm getAltEffectiveAlgorithm()
    {
        SignatureAndHashAlgorithm algorithm = null;
        if (TlsImplUtils.isTLSv12(cryptoParams))
        {
            algorithm = getAltSignatureAndHashAlgorithm();
            if (algorithm == null)
            {
                throw new IllegalStateException("'signatureAndHashAlgorithm' cannot be null for (D)TLS 1.2+");
            }
        }
        return algorithm;
    }
}
