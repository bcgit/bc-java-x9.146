package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.io.SignerOutputStream;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

class BcTlsPQStreamSigner
    implements TlsStreamSigner
{
    private final ByteArrayOutputStream output;
    private final MessageSigner signer;


    BcTlsPQStreamSigner(MessageSigner signer)
    {
        this.output = new ByteArrayOutputStream();

        this.signer = signer;
    }

    public OutputStream getOutputStream() throws IOException
    {
        return output;
    }

    public byte[] getSignature() throws IOException
    {
        try
        {
            return signer.generateSignature(output.toByteArray());
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}
