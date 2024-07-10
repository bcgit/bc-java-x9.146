package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.io.SignerOutputStream;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner;
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconSigner;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.Tls13Verifier;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

import java.io.IOException;
import java.io.OutputStream;

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
        MessageSigner signer;

        switch (signatureScheme)
        {
        case SignatureScheme.dilithiumr3_2:
        case SignatureScheme.dilithiumr3_3:
        case SignatureScheme.dilithiumr3_5:
        case SignatureScheme.hybrid_p256_dilithiumr3_2:
        case SignatureScheme.hybrid_rsa3072_dilithiumr3_2:
        case SignatureScheme.hybrid_p384_dilithiumr3_3:
        case SignatureScheme.hybrid_p521_dilithiumr3_5:
        {
            signer = new DilithiumSigner();
            signer.init(true, privateKey);
            break;
        }
        case SignatureScheme.falcon_512:
        case SignatureScheme.falcon_1024:
        case SignatureScheme.hybrid_p256_falcon_512:
        case SignatureScheme.hybrid_rsa3072_falcon_512:
        case SignatureScheme.hybrid_p521_falcon_1024:
        {
            signer = new FalconSigner();
            signer.init(true, privateKey);
            break;
        }
        default:
            throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }
        // Should message be attached to signature?
        return signer.generateSignature(hash);

    }

    @Override
    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm)
    {
        MessageSigner signer;
        switch (signatureScheme)
        {
            case SignatureScheme.dilithiumr3_2:
            case SignatureScheme.dilithiumr3_3:
            case SignatureScheme.dilithiumr3_5:
            case SignatureScheme.hybrid_p256_dilithiumr3_2:
            case SignatureScheme.hybrid_rsa3072_dilithiumr3_2:
            case SignatureScheme.hybrid_p384_dilithiumr3_3:
            case SignatureScheme.hybrid_p521_dilithiumr3_5:
            {
                signer = new DilithiumSigner();
                signer.init(true, privateKey);
                break;
            }
            case SignatureScheme.falcon_512:
            case SignatureScheme.falcon_1024:
            case SignatureScheme.hybrid_p256_falcon_512:
            case SignatureScheme.hybrid_rsa3072_falcon_512:
            case SignatureScheme.hybrid_p521_falcon_1024:
            {
                signer = new FalconSigner();
                signer.init(true, privateKey);
                break;
            }
            default:
                return null; //throw exp?
        }
        return new BcTlsPQStreamSigner(signer);
    }


}
