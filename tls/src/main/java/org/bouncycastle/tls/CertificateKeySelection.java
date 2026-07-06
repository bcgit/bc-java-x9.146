package org.bouncycastle.tls;

import java.util.Vector;

public class CertificateKeySelection
{

    private Vector<KeySelection> signatureIdentifier;

    public CertificateKeySelection(Vector<KeySelection> signatureIdentifier)
    {
        this.signatureIdentifier = signatureIdentifier;
    }

    public Vector<KeySelection> getSignatureIdentifier()
    {
        return signatureIdentifier;
    }

    public void setSignatureIdentifier(Vector<KeySelection> signatureIdentifier)
    {
        this.signatureIdentifier = signatureIdentifier;
    }

    @Override
    public String toString()
    {
        return "CertificateKeySelection{" +
            "signatureIdentifier=" + signatureIdentifier +
            '}';
    }
}