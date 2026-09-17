package org.bouncycastle.crypto.util;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * NOTE: jdk1.4 overlay. XMSS / XMSS^MT (org.bouncycastle.crypto.params.XMSS*,
 * org.bouncycastle.crypto.generators.XMSS*KeyPairGenerator and
 * org.bouncycastle.crypto.signers.xmss) is excluded from this distribution, so every method here
 * answers null - "not an XMSS key" - and the key factories in this package fall through to their
 * own unrecognised-algorithm handling, exactly as they did before XMSS was promoted into
 * org.bouncycastle.crypto. Keep the method set in step with the base copy: a new method there that
 * is not added here fails the build only when the jdk1.4 distribution is built.
 */
class XmssKeyUtil
{
    private XmssKeyUtil()
    {
    }

    static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey)
        throws IOException
    {
        return null;
    }

    static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey, ASN1Set attributes)
        throws IOException
    {
        return null;
    }

    static AsymmetricKeyParameter createPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        return null;
    }

    static AsymmetricKeyParameter createPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        return null;
    }
}
