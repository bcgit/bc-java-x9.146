package org.bouncycastle.tls.crypto.impl.bc;

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
    private final MessageSigner verifier;

    public BcTls13PQVerifier(MessageSigner verifier)
    {
        if (verifier == null)
        {
            throw new NullPointerException("'verifier' cannot be null");
        }

        this.verifier = verifier;
        this.output = new ByteArrayOutputStream();
    }

    public final OutputStream getOutputStream() throws IOException
    {
        return output;
    }

    public final boolean verifySignature(byte[] signature) throws IOException
    {
        return verifier.verifySignature(output.toByteArray(), signature);
    }
}
