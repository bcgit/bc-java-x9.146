package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.falcon.FalconSigner;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

import java.io.IOException;

final class BcTlsPQSigner extends BcTlsSigner
{
    private final int signatureScheme;

    public BcTlsPQSigner(BcTlsCrypto crypto, AsymmetricKeyParameter privateKey, int signatureScheme)
    {
        super(crypto, privateKey);

        if (!SignatureScheme.isPQ(signatureScheme))
        {
            throw new IllegalArgumentException("signatureScheme");
        }
        this.signatureScheme = signatureScheme;

    }

    @Override
    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        if (algorithm == null || SignatureScheme.from(algorithm) != signatureScheme)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        //TODO[x9.146]: do I need crypto hash algorithm?

        switch (signatureScheme)
        {
        case SignatureScheme.DRAFT_mldsa44:
        case SignatureScheme.DRAFT_mldsa65:
        case SignatureScheme.DRAFT_mldsa87:
        {
            Signer signer = new MLDSASigner();
            signer.init(true, privateKey);
            try
            {
                signer.update(hash, 0, hash.length);
                return signer.generateSignature();
            }
            catch (Exception e)
            {
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
            }
        }
        case SignatureScheme.X9146_falcon512:
        case SignatureScheme.X9146_falcon1024:
        {
            MessageSigner signer = new FalconSigner();
            signer.init(true, privateKey);
            return signer.generateSignature(hash);
        }
        default:
            throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }
        // Should message be attached to signature?

    }

    @Override
    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm)
    {
        switch (signatureScheme)
        {
            case SignatureScheme.DRAFT_mldsa44:
            case SignatureScheme.DRAFT_mldsa65:
            case SignatureScheme.DRAFT_mldsa87:
            {
                Signer signer = new MLDSASigner();
                signer.init(true, privateKey);
                return new BcTlsPQStreamSigner(signer);
            }
            case SignatureScheme.X9146_falcon512:
            case SignatureScheme.X9146_falcon1024:
            {
                MessageSigner signer = new FalconSigner();
                signer.init(true, privateKey);
                return new BcTlsPQStreamSigner(signer);
            }
            default:
                return null; //throw exp?
        }
    }


}
