package org.bouncycastle.pqc.crypto.crystals.dilithium;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.encoders.Hex;

public class DilithiumSigner
    implements MessageSigner
{
    private DilithiumPrivateKeyParameters privKey;
    private DilithiumPublicKeyParameters pubKey;

    private SecureRandom random;

    public DilithiumSigner()
    {
    }

    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            if (param instanceof ParametersWithRandom)
            {
                privKey = (DilithiumPrivateKeyParameters)((ParametersWithRandom)param).getParameters();
                random = ((ParametersWithRandom)param).getRandom();
            }
            else
            {
                privKey = (DilithiumPrivateKeyParameters)param;
                random = null;
            }
        }
        else
        {
            pubKey = (DilithiumPublicKeyParameters)param;
        }
    }

    public byte[] generateSignature(byte[] message)
    {
        DilithiumEngine engine = privKey.getParameters().getEngine(random);

        return engine.sign(message, message.length, privKey.rho, privKey.k, privKey.tr, privKey.t0, privKey.s1, privKey.s2);
    }
    public byte[] internalGenerateSignature(byte[] message, byte[] random)
    {
        DilithiumEngine engine = privKey.getParameters().getEngine(this.random);

        return engine.signSignatureInternal(message, message.length, privKey.rho, privKey.k, privKey.tr, privKey.t0, privKey.s1, privKey.s2, random);
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        System.out.println("msg: " + Hex.toHexString(message));
        System.out.println("sig: " + Hex.toHexString(signature));
        DilithiumEngine engine = pubKey.getParameters().getEngine(random);

        return engine.signOpen(message, signature, signature.length, pubKey.rho, pubKey.t1);
    }
}
