package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.io.SignerOutputStream;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.tls.crypto.Tls13Verifier;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class BcTls13PQVerifier
    implements Tls13Verifier
{

    private final ByteArrayOutputStream output;
    private final MessageSigner verifierBeta;
    private final Signer verifier;

    public BcTls13PQVerifier(Signer verifier)
    {
        if (verifier == null)
        {
            throw new NullPointerException("'verifier' cannot be null");
        }

        this.verifierBeta = null;
        this.verifier = verifier;
        this.output = new ByteArrayOutputStream();
    }
    public BcTls13PQVerifier(MessageSigner verifier)
    {
        if (verifier == null)
        {
            throw new NullPointerException("'verifier' cannot be null");
        }

        this.verifierBeta = verifier;
        this.verifier = null;
        this.output = new ByteArrayOutputStream();
    }

    public final OutputStream getOutputStream() throws IOException
    {
        return output;
    }

    public final boolean verifySignature(byte[] signature) throws IOException
    {
        if (verifierBeta != null)
        {
            return verifierBeta.verifySignature(output.toByteArray(), signature);
        }
        else
        {
            byte[] message = output.toByteArray();
            verifier.update(message, 0, message.length);
            return verifier.verifySignature(signature);
        }
    }
}
