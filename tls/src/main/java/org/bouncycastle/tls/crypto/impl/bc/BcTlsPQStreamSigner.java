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
    private final MessageSigner signerBeta;
    private final Signer signer;


    BcTlsPQStreamSigner(MessageSigner signer)
    {
        this.output = new ByteArrayOutputStream();

        this.signerBeta = signer;
        this.signer = null;
    }
    BcTlsPQStreamSigner(Signer signer)
    {
        this.output = new ByteArrayOutputStream();

        this.signerBeta = null;
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
            if (signerBeta != null)
            {
                return signerBeta.generateSignature(output.toByteArray());
            }
            else
            {
                byte[] out = output.toByteArray();
                signer.update(out, 0, out.length);
                return signer.generateSignature();
            }
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}
