package org.bouncycastle.crypto.signers.xmss;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * WOTS+ Parameters.
 */
final class WOTSPlusParameters
{
    /**
     * The message digest size.
     */
    private final int digestSize;
    /**
     * The number of n-byte string elements in a WOTS+ secret key, public key,
     * and signature.
     */
    private final int len;
    /**
     * len1.
     */
    private final int len1;
    /**
     * len2.
     */
    private final int len2;
    private final ASN1ObjectIdentifier treeDigest;

    /**
     * The Winternitz parameter, fixed at 16 by RFC 8391 sec. 5. It is a constant rather than a
     * field with a getter because no parameter set varies it: len1, len2 and the OID lookup below
     * are derived from it here, and WOTSPlus reads it directly for the chain lengths and the
     * base-w conversion.
     */
    static final int WINTERNITZ_PARAMETER = 16;

    /**
     * Constructor...
     *
     * @param treeDigest The digest used for WOTS+.
     */
    public WOTSPlusParameters(ASN1ObjectIdentifier treeDigest)
    {
        this(treeDigest, DigestUtil.getDigest(treeDigest).getDigestSize());
    }

    /**
     * Constructor with explicit digest size (security parameter n).
     *
     * @param treeDigest The digest used for WOTS+.
     * @param digestSize The security parameter n in bytes.
     */
    public WOTSPlusParameters(ASN1ObjectIdentifier treeDigest, int digestSize)
    {
        this.treeDigest = treeDigest;
        this.digestSize = digestSize;
        len1 = (int)Math.ceil((double)(8 * digestSize) / XMSSUtil.log2(WINTERNITZ_PARAMETER));
        len2 = (int)Math.floor(XMSSUtil.log2(len1 * (WINTERNITZ_PARAMETER - 1)) / XMSSUtil.log2(WINTERNITZ_PARAMETER)) + 1;
        len = len1 + len2;
        String algName = DigestUtil.getDigestName(treeDigest);
        // The identifier this answers with is not kept - nothing anywhere reads a WOTS+ parameter
        // set identifier - but whether there is one at all is the only thing that rejects a
        // security parameter no XMSS parameter set defines. n arrives unexamined through the
        // public XMSSParameters(height, tree digest OID, n) and XMSSMTParameters(height, layers,
        // tree digest OID, n) constructors, and len1, len2 and len above are computed from
        // whatever it is, so a SHA-256 asked for at n = 17, or truncated to 64, is stopped here
        // and nowhere else.
        if (WOTSPlusOid.lookup(algName, digestSize, WINTERNITZ_PARAMETER, len) == null)
        {
            throw new IllegalArgumentException("cannot find OID for digest algorithm: " + algName);
        }
    }

    /**
     * Getter digestSize.
     *
     * @return digestSize.
     */
    public int getTreeDigestSize()
    {
        return digestSize;
    }

    /**
     * Getter len.
     *
     * @return len.
     */
    public int getLen()
    {
        return len;
    }

    /**
     * Getter len1.
     *
     * @return len1.
     */
    public int getLen1()
    {
        return len1;
    }

    /**
     * Getter len2.
     *
     * @return len2.
     */
    public int getLen2()
    {
        return len2;
    }

    public ASN1ObjectIdentifier getTreeDigest()
    {
        return treeDigest;
    }
}
