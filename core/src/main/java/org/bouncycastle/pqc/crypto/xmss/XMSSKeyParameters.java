package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * @deprecated use {@link org.bouncycastle.crypto.params.XMSSKeyParameters} instead.
 */
@Deprecated
public class XMSSKeyParameters
    extends AsymmetricKeyParameter
{
    public static final String SHA_256 = "SHA-256";
    public static final String SHA_512 = "SHA-512";
    public static final String SHAKE128 = "SHAKE128";
    public static final String SHAKE256 = "SHAKE256";
    public static final String SHAKE256_LEN = "SHAKE256-LEN";

    private final String treeDigest;

    public XMSSKeyParameters(boolean isPrivateKey, String treeDigest)
    {
        super(isPrivateKey);
        this.treeDigest = treeDigest;
    }

    public String getTreeDigest()
    {
        return treeDigest;
    }
}
