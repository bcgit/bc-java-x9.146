package org.bouncycastle.crypto.signers.xmss;

import junit.framework.TestCase;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSMTPrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;

/**
 * An XMSS^MT private key of a non-standard parameter set is written through
 * XmssKeyUtil.xmssmtCreateKeyStructure, which reads the index back out of the key's own encoding.
 * The index is a long the whole way - the encoding carries ceil(h/8) bytes of it, XMSSMTPrivateKey
 * holds a long and XMSSEngine.isStoredIndexValid takes one - and a tree taller than 32 needs more
 * than four bytes for it.
 * <p>
 * Narrowing it to an int on the way through truncated silently, and did so ahead of the bounds
 * check, so the out-of-range value was not rejected but wrapped into an in-range one: the key was
 * exported claiming a position it had already signed past, and re-importing it reused every
 * one-time key in between (RFC 8391 sec. 1.1).
 * </p>
 */
public class LargeIndexEncodingTests
    extends TestCase
{
    /**
     * Total height 36 with 4 layers: 9 per layer, well inside the BDS limit, but not one of the
     * RFC 8391 sec. 5.4 registered sets - so it has no parameter-set OID and is encoded through
     * xmssmtCreateKeyStructure rather than the RFC 9802 raw form. ceil(36/8) = 5 index bytes.
     */
    private static final int HEIGHT = 36;
    private static final int LAYERS = 4;

    private static XMSSMTPrivateKeyParameters keyAtIndex(XMSSMTParameters params, long index)
    {
        int n = params.getTreeDigestSize();
        byte[] secretKeySeed = new byte[n];
        byte[] secretKeyPRF = new byte[n];
        byte[] publicSeed = new byte[n];
        byte[] root = new byte[n];

        for (int i = 0; i != n; i++)
        {
            secretKeySeed[i] = (byte)i;
            secretKeyPRF[i] = (byte)(i + 1);
            publicSeed[i] = (byte)(i + 2);
            root[i] = (byte)(i + 3);
        }

        return new XMSSMTPrivateKeyParameters.Builder(params)
            .withIndex(index)
            .withSecretKeySeed(secretKeySeed).withSecretKeyPRF(secretKeyPRF)
            .withPublicSeed(publicSeed).withRoot(root)
            .withBDSState(new BDSStateMap((1L << HEIGHT) - 1)).build();
    }

    public void testIndexBeyondIntRangeSurvivesEncoding()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(HEIGHT, LAYERS, NISTObjectIdentifiers.id_sha256);

        assertEquals("expected a non-standard parameter set", 0, params.getParameterSetOID());

        // just past what four bytes can hold: truncation reported this key as index 5
        long index = (1L << 32) + 5;

        XMSSMTPrivateKeyParameters privKey = keyAtIndex(params, index);
        PrivateKeyInfo info = PrivateKeyInfoFactory.createPrivateKeyInfo(privKey);
        XMSSMTPrivateKeyParameters decoded = (XMSSMTPrivateKeyParameters)PrivateKeyFactory.createKey(info);

        assertEquals("key rolled back by encoding", index, decoded.getIndex());
    }

    /**
     * The boundary itself, and the two indices either side of it: 2^32 - 1 is the largest value
     * four bytes hold, and the truncation showed up from 2^32 on.
     */
    public void testIndicesAroundTheFourByteBoundary()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(HEIGHT, LAYERS, NISTObjectIdentifiers.id_sha256);

        long[] indices = new long[]{
            0L,
            (1L << 31),
            (1L << 32) - 1,
            (1L << 32),
            (1L << 35),
            (1L << HEIGHT) - 1};

        for (int i = 0; i != indices.length; i++)
        {
            XMSSMTPrivateKeyParameters privKey = keyAtIndex(params, indices[i]);
            PrivateKeyInfo info = PrivateKeyInfoFactory.createPrivateKeyInfo(privKey);
            XMSSMTPrivateKeyParameters decoded = (XMSSMTPrivateKeyParameters)PrivateKeyFactory.createKey(info);

            assertEquals("index " + indices[i] + " did not survive encoding",
                indices[i], decoded.getIndex());
        }
    }
}
