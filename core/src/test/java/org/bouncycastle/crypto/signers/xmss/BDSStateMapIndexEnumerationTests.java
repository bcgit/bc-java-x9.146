package org.bouncycastle.crypto.signers.xmss;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.XMSSMTKeyPairGenerator;
import org.bouncycastle.crypto.params.XMSSMTKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSMTPrivateKeyParameters;

/**
 * BDSStateMap.validate(XMSSMTParameters, long) ties each layer's BDS traversal state to the
 * enclosing key's global index, and admits one specific carry-over at a leaf index of 0: a
 * layer's state may still show the previous subtree's final leaf, because updateState() does not
 * advance a layer's state on the last leaf of its subtree - the state is rebuilt from scratch the
 * next time that layer signs. The method's own comment claims that walking every index of five
 * parameter sets - h=4/d=2, h=6/d=2, h=6/d=3, h=9/d=3 and h=8/d=4 - turns up no other divergence.
 * That walk had never been captured as a test, so a future change to the boundary condition had
 * nothing to catch a regression; this is that walk.
 */
public class BDSStateMapIndexEnumerationTests
    extends TestCase
{
    /**
     * Every index a key of each cited parameter set can reach - 0 up to and including the
     * one-past-the-end exhausted index - is checked directly against
     * {@link BDSStateMap#validate(XMSSMTParameters, long)}, the method the boundary claim is
     * about. A boundary case the claim missed would surface here as an unexpected
     * IllegalStateException partway through.
     * <p>
     * This calls validate() directly rather than round-tripping through the private key's own
     * byte encoding: that outer encoding has a separate, pre-existing width limitation at the
     * exhausted-index placeholder for a total height that is an exact multiple of 8 (h=8 among
     * the parameter sets here), which is a different concern from the one this test is chartered
     * to cover and would otherwise mask what this test is actually checking.
     */
    public void testEveryIndexOfCitedParameterSetsValidates()
        throws Exception
    {
        walkEveryIndex(4, 2);
        walkEveryIndex(6, 2);
        walkEveryIndex(6, 3);
        walkEveryIndex(9, 3);
        walkEveryIndex(8, 4);
    }

    private void walkEveryIndex(int height, int layers)
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(height, layers, new SHA256Digest());
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));

        XMSSMTPrivateKeyParameters privKey = (XMSSMTPrivateKeyParameters)kpg.generateKeyPair().getPrivate();
        long maxIndex = privKey.getBDSState().getMaxIndex();
        String label = "h=" + height + "/d=" + layers;

        for (long expectedIndex = 0; expectedIndex <= maxIndex + 1; expectedIndex++)
        {
            assertEquals(label, expectedIndex, privKey.getIndex());

            privKey.getBDSState().validate(params, privKey.getIndex());

            if (expectedIndex < maxIndex + 1)
            {
                privKey.rollKey();
            }
        }
    }

    /**
     * The check has teeth, not just the absence of a false rejection: a global index rolled back
     * against traversal state that stayed advanced - a partial write, a restore from backup, a
     * buggy storage layer - is exactly the divergence RFC 8391 sec. 1.1 requires be refused, since
     * signing again there would reuse a one-time key and the resulting signature would still
     * verify.
     */
    public void testRolledBackIndexStillRejected()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(6, 3, new SHA256Digest());
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));

        XMSSMTPrivateKeyParameters privKey = (XMSSMTPrivateKeyParameters)kpg.generateKeyPair().getPrivate();

        for (int i = 0; i != 5; i++)
        {
            privKey.rollKey();
        }

        byte[] encoded = privKey.getEncoded();
        int indexSize = (params.getHeight() + 7) / 8;

        // roll the declared index back to 0 while leaving the traversal state - which has
        // genuinely advanced to index 5 - untouched
        for (int i = 0; i < indexSize; i++)
        {
            encoded[i] = 0;
        }

        try
        {
            new XMSSMTPrivateKeyParameters.Builder(params).withPrivateKey(encoded).build();
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            assertTrue(e.getMessage(), e.getMessage().startsWith("BDS state has wrong index for layer"));
        }
    }
}
