package org.bouncycastle.crypto.signers.xmss;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.XMSSKeyPairGenerator;
import org.bouncycastle.crypto.generators.XMSSMTKeyPairGenerator;
import org.bouncycastle.crypto.params.XMSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSMTPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSMTPublicKeyParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.params.XMSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSPublicKeyParameters;
import org.bouncycastle.crypto.signers.XMSSMTSigner;
import org.bouncycastle.crypto.signers.XMSSSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * The four XMSS / XMSS^MT key parameter builders. XMSS and XMSS^MT are separate class families
 * with the same contract, so the tests here are deliberately written in pairs - the two halves
 * had drifted apart, and a pair that must agree is the cheapest way to keep them together.
 */
public class KeyParametersBuilderTests
    extends TestCase
{
    private static final int HEIGHT = 4;
    private static final int LAYERS = 2;

    private XMSSParameters xmssParams()
    {
        return new XMSSParameters(HEIGHT, new SHA256Digest());
    }

    private XMSSMTParameters xmssMTParams()
    {
        return new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest());
    }

    /**
     * A null parameter set is rejected where it is passed, rather than dereferenced first and
     * caught by a check that can never run. All four builders share the wording.
     */
    public void testNullParametersRejectedByBuilder()
    {
        try
        {
            new XMSSPrivateKeyParameters.Builder(null);
            fail("no exception");
        }
        catch (NullPointerException e)
        {
            assertEquals("params == null", e.getMessage());
        }

        try
        {
            new XMSSPublicKeyParameters.Builder(null);
            fail("no exception");
        }
        catch (NullPointerException e)
        {
            assertEquals("params == null", e.getMessage());
        }

        try
        {
            new XMSSMTPrivateKeyParameters.Builder(null);
            fail("no exception");
        }
        catch (NullPointerException e)
        {
            assertEquals("params == null", e.getMessage());
        }

        try
        {
            new XMSSMTPublicKeyParameters.Builder(null);
            fail("no exception");
        }
        catch (NullPointerException e)
        {
            assertEquals("params == null", e.getMessage());
        }
    }

    /**
     * The two signature builders read an index out of the encoding and it can name a leaf the tree
     * does not have - the XMSS one reads four bytes as a signed int, so it can be negative too.
     * XMSS^MT refused that and XMSS did not, which had one scheme's two halves disagreeing about
     * whether an index outside the tree is a signature that will not decode or one that does not
     * verify.
     * <p>
     * A verifier saw the same answer either way, and still does - XMSSEngine.verifySignature
     * catches a RuntimeException from the decode and reports false - so this is asserted at the
     * builder, which is where the two differed and what a caller assembling a signature by hand
     * reaches. The false is asserted beside it, because that is the answer that must not change.
     * </p>
     */
    public void testSignatureIndexOutsideTheTreeRejectedByBuilder()
    {
        XMSSParameters params = xmssParams();
        // index(4) || random(n) || reduced signature, as XMSSSignature lays it down
        int size = 4 + params.getTreeDigestSize() + XMSSReducedSignature.sizeOf(params);
        int[] outside = new int[]{ 1 << HEIGHT, (1 << HEIGHT) + 1, Integer.MAX_VALUE, -1,
            Integer.MIN_VALUE };

        for (int i = 0; i != outside.length; i++)
        {
            byte[] encoded = new byte[size];

            Pack.intToBigEndian(outside[i], encoded, 0);

            try
            {
                new XMSSSignature.Builder(params).withSignature(encoded).build();
                fail("index " + outside[i] + " accepted");
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("index out of bounds", e.getMessage());
            }
            catch (IllegalStateException e)
            {
                // isIndexValid raises rather than returns for a negative index, and that is inside
                // the same catch the verifier reads the refusal through
                assertEquals("index must not be negative", e.getMessage());
                assertTrue("only the negative cases arrive this way", outside[i] < 0);
            }
        }

        // every index the tree does have still decodes, so the bound is where the tree ends
        for (int index = 0; index != (1 << HEIGHT); index++)
        {
            byte[] encoded = new byte[size];

            Pack.intToBigEndian(index, encoded, 0);

            assertEquals(index,
                new XMSSSignature.Builder(params).withSignature(encoded).build().getIndex());
        }
    }

    /**
     * All four key builders, and the two signature builders beside them, take the same optional
     * n-byte fields on the same terms, so a wrong-sized one has to be reported the same way. Each
     * carried its own copy of the check and they had drifted into two wordings.
     */
    public void testWrongSizedFieldRejectedByBuilder()
    {
        byte[] shortSeed = new byte[31];
        byte[] seed = new byte[32];

        try
        {
            new XMSSSignature.Builder(xmssParams()).withRandom(shortSeed).build();
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("size of random needs to be equal to size of digest", e.getMessage());
        }

        try
        {
            new XMSSMTSignature.Builder(xmssMTParams()).withRandom(shortSeed).build();
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("size of random needs to be equal to size of digest", e.getMessage());
        }

        try
        {
            new XMSSPublicKeyParameters.Builder(xmssParams()).withRoot(shortSeed)
                .withPublicSeed(seed).build();
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("size of root needs to be equal to size of digest", e.getMessage());
        }

        try
        {
            new XMSSMTPublicKeyParameters.Builder(xmssMTParams()).withRoot(seed)
                .withPublicSeed(shortSeed).build();
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("size of publicSeed needs to be equal to size of digest", e.getMessage());
        }

        try
        {
            new XMSSPrivateKeyParameters.Builder(xmssParams()).withSecretKeySeed(shortSeed)
                .withSecretKeyPRF(seed).withPublicSeed(seed).withRoot(seed).build();
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("size of secretKeySeed needs to be equal to size of digest", e.getMessage());
        }

        try
        {
            new XMSSMTPrivateKeyParameters.Builder(xmssMTParams()).withSecretKeySeed(seed)
                .withSecretKeyPRF(shortSeed).withPublicSeed(seed).withRoot(seed).build();
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("size of secretKeyPRF needs to be equal to size of digest", e.getMessage());
        }
    }

    /**
     * Neither private key builder will hand back a key whose seeds it had to invent. Without the
     * check the seeds default to all zeroes, which is a usable-looking key an application has no
     * way of telling apart from a generated one.
     */
    public void testPrivateKeyWithoutSeedsRejected()
    {
        try
        {
            new XMSSPrivateKeyParameters.Builder(xmssParams()).build();
            fail("no exception");
        }
        catch (IllegalStateException e)
        {
            assertEquals("publicSeed or secretKeySeed is null", e.getMessage());
        }

        try
        {
            new XMSSMTPrivateKeyParameters.Builder(xmssMTParams()).build();
            fail("no exception");
        }
        catch (IllegalStateException e)
        {
            assertEquals("publicSeed or secretKeySeed is null", e.getMessage());
        }
    }

    /**
     * The seed check is a disjunction - an imported private key carries its own seeds, so the
     * import path must stay open.
     */
    public void testPrivateKeyImportStillAccepted()
        throws Exception
    {
        XMSSPrivateKeyParameters xmss = (XMSSPrivateKeyParameters)generateXMSS().getPrivate();
        XMSSPrivateKeyParameters recovered = new XMSSPrivateKeyParameters.Builder(xmssParams())
            .withPrivateKey(xmss.getEncoded()).build();
        assertTrue(Arrays.areEqual(xmss.getEncoded(), recovered.getEncoded()));

        XMSSMTPrivateKeyParameters mt = (XMSSMTPrivateKeyParameters)generateXMSSMT().getPrivate();
        XMSSMTPrivateKeyParameters mtRecovered = new XMSSMTPrivateKeyParameters.Builder(xmssMTParams())
            .withPrivateKey(mt.getEncoded()).build();
        assertTrue(Arrays.areEqual(mt.getEncoded(), mtRecovered.getEncoded()));
    }

    /**
     * A generated key can be used 2^h times. The XMSS^MT generator used to obtain its empty BDS
     * state map by building a throwaway seedless private key, which produced a map with maxIndex
     * 0 that a fixup in withBDSState() then had to correct.
     */
    public void testGeneratedKeysReportFullUsageCount()
    {
        long expected = 1L << HEIGHT;

        XMSSPrivateKeyParameters xmss = (XMSSPrivateKeyParameters)generateXMSS().getPrivate();
        assertEquals(expected, xmss.getUsagesRemaining());
        assertEquals(expected - 1, xmss.getBDSState().getMaxIndex());

        XMSSMTPrivateKeyParameters mt = (XMSSMTPrivateKeyParameters)generateXMSSMT().getPrivate();
        assertEquals(expected, mt.getUsagesRemaining());
        assertEquals(expected - 1, mt.getBDSState().getMaxIndex());
    }

    /**
     * rollKey() past the last leaf installs the placeholder BDS documented on
     * BDS(XMSSParameters, int, int) - index deliberately one past maxIndex, so that
     * getUsagesRemaining() reports zero rather than the key silently wrapping round and reusing
     * a one-time signature.
     */
    public void testRollKeyPastLastLeafExhaustsTheKey()
    {
        XMSSPrivateKeyParameters key = (XMSSPrivateKeyParameters)generateXMSS().getPrivate();

        long maxIndex = key.getBDSState().getMaxIndex();
        for (int i = 0; i != (1 << HEIGHT); i++)
        {
            key = key.rollKey();
        }

        assertEquals(0, key.getUsagesRemaining());
        assertEquals(maxIndex + 1, key.getIndex());

        // and it stays exhausted rather than wrapping
        key = key.rollKey();
        assertEquals(0, key.getUsagesRemaining());
        assertEquals(maxIndex + 1, key.getIndex());
    }

    /**
     * A shard covers the range [index...index + usageCount), so the single use shard getNextKey()
     * takes from an unused key covers index 0 alone and carries maximum index 0. XMSS^MT read that
     * as the mark a state map written before it recorded a maximum index leaves in its place and
     * widened the shard to the whole key space - so the shard went on signing with the one-time
     * keys the key it came from was handing out at the same time, which is the one thing a
     * stateful signature scheme has to prevent.
     */
    public void testSingleUseShardCoversOneSignature()
        throws Exception
    {
        byte[] message = new byte[]{ 1, 2, 3 };

        XMSSPrivateKeyParameters xmss = (XMSSPrivateKeyParameters)generateXMSS().getPrivate();
        XMSSPrivateKeyParameters xmssShard = xmss.getNextKey();

        assertEquals(0, xmssShard.getIndex());
        assertEquals(0, xmssShard.getBDSState().getMaxIndex());
        assertEquals(1, xmssShard.getUsagesRemaining());
        assertEquals(1, xmss.getIndex());

        XMSSSigner signer = new XMSSSigner();

        signer.init(true, xmssShard);
        signer.update(message, 0, message.length);
        signer.generateSignature();

        signer.update(message, 0, message.length);

        try
        {
            signer.generateSignature();
            fail("no exception");
        }
        catch (ExhaustedPrivateKeyException e)
        {
            assertEquals("no usages of private key remaining", e.getMessage());
        }

        XMSSMTPrivateKeyParameters mt = (XMSSMTPrivateKeyParameters)generateXMSSMT().getPrivate();
        XMSSMTPrivateKeyParameters mtShard = mt.getNextKey();

        assertEquals(0, mtShard.getIndex());
        assertEquals(0, mtShard.getBDSState().getMaxIndex());
        assertEquals(1, mtShard.getUsagesRemaining());
        assertEquals(1, mt.getIndex());

        // maximum index 0 now means what it says, so it has to survive being written out and read
        // back: the encoding records a maximum index short of the tree's, where one covering the
        // whole tree is left to the reader to infer
        XMSSMTPrivateKeyParameters restored = (XMSSMTPrivateKeyParameters)PrivateKeyFactory.createKey(
            PrivateKeyInfoFactory.createPrivateKeyInfo(mtShard).getEncoded());

        assertEquals(0, restored.getIndex());
        assertEquals(1, restored.getUsagesRemaining());

        XMSSMTSigner mtSigner = new XMSSMTSigner();

        mtSigner.init(true, mtShard);
        mtSigner.update(message, 0, message.length);
        mtSigner.generateSignature();

        mtSigner.update(message, 0, message.length);

        try
        {
            mtSigner.generateSignature();
            fail("no exception");
        }
        catch (ExhaustedPrivateKeyException e)
        {
            assertEquals("no usages of private key remaining", e.getMessage());
        }
    }

    /**
     * The index a caller hands the builder decides how far the tree is walked to rebuild the lost
     * traversal state, one authentication path per leaf, so an index past the end of the tree has
     * to be refused before the walk. It used to be refused by the walk instead, once it ran out of
     * tree: the answer was the same but it cost a full tree of authentication paths to reach, which
     * at the RFC 8391 heights is minutes of work at h = 16 and hours at h = 20. The encoded-key
     * path has always made this check on the index it reads.
     */
    public void testRecoveryIndexCheckedBeforeTheTreeIsWalked()
    {
        XMSSParameters params = xmssParams();
        byte[] seed = new byte[params.getTreeDigestSize()];
        int[] outOfRange = new int[]{ -1, (1 << HEIGHT) + 1, Integer.MAX_VALUE };

        for (int i = 0; i != outOfRange.length; i++)
        {
            long started = System.currentTimeMillis();

            try
            {
                recoverXMSSAt(params, seed, outOfRange[i]);
                fail("index " + outOfRange[i] + " accepted");
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("index out of bounds", e.getMessage());
            }

            // a walk of the height-4 tree used to take roughly half a second here; the point of the
            // check is that no walk happens at all, so any sane bound catches a regression
            assertTrue("index " + outOfRange[i] + " was walked, not checked",
                System.currentTimeMillis() - started < 5000);
        }
    }

    /**
     * 2^h is the index of a key with every leaf spent. It is inside the range the encoded-key path
     * accepts and is what rollKey() leaves behind, but the builder used to walk the whole tree and
     * then report it as out of bounds - so a state the encoding can carry could not be rebuilt.
     */
    public void testRecoveryAtTheExhaustedIndex()
    {
        XMSSParameters params = xmssParams();
        byte[] seed = new byte[params.getTreeDigestSize()];

        XMSSPrivateKeyParameters spent = recoverXMSSAt(params, seed, 1 << HEIGHT);

        assertEquals(1 << HEIGHT, spent.getIndex());
        assertEquals(0, spent.getUsagesRemaining());

        XMSSSigner signer = new XMSSSigner();

        signer.init(true, spent);
        signer.update(new byte[]{ 1, 2, 3 }, 0, 3);

        try
        {
            signer.generateSignature();
            fail("spent key signed");
        }
        catch (ExhaustedPrivateKeyException e)
        {
            assertEquals("no usages of private key remaining", e.getMessage());
        }
    }

    /**
     * The XMSS^MT half of {@link #testRecoveryIndexCheckedBeforeTheTreeIsWalked()}, which this
     * family had no equivalent of at all. An index the hypertree cannot hold fell through to a
     * placeholder state map instead of being refused, and nothing downstream could tell: XMSS^MT
     * builds each layer's traversal state lazily, so a map with no layers in it is a legitimate
     * map, and both the structural check and the per-layer index check pass over one. The key came
     * out carrying an index past its last leaf, and reporting its usages remaining off a maximum
     * index of 0.
     */
    public void testMTRecoveryIndexCheckedBeforeTheTreeIsWalked()
    {
        XMSSMTParameters params = xmssMTParams();
        byte[] seed = new byte[params.getTreeDigestSize()];
        long[] outOfRange = new long[]{ -1L, (1L << HEIGHT) + 1, Long.MAX_VALUE };

        for (int i = 0; i != outOfRange.length; i++)
        {
            long started = System.currentTimeMillis();

            try
            {
                recoverXMSSMTAt(params, seed, outOfRange[i]);
                fail("index " + outOfRange[i] + " accepted");
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("index out of bounds", e.getMessage());
            }

            assertTrue("index " + outOfRange[i] + " was walked, not checked",
                System.currentTimeMillis() - started < 5000);
        }
    }

    /**
     * The XMSS^MT half of {@link #testRecoveryAtTheExhaustedIndex()}. 2^h is in range and is the
     * position rollKey() stops at, so it has to rebuild to the state rollKey() leaves behind - an
     * empty map whose maximum index is the last leaf - rather than to one whose maximum index is
     * wherever the placeholder happened to put it.
     */
    public void testMTRecoveryAtTheExhaustedIndex()
    {
        XMSSMTParameters params = xmssMTParams();
        byte[] seed = new byte[params.getTreeDigestSize()];

        XMSSMTPrivateKeyParameters spent = recoverXMSSMTAt(params, seed, 1L << HEIGHT);

        assertEquals(1L << HEIGHT, spent.getIndex());
        assertEquals(0, spent.getUsagesRemaining());

        XMSSMTSigner signer = new XMSSMTSigner();

        signer.init(true, spent);
        signer.update(new byte[]{ 1, 2, 3 }, 0, 3);

        try
        {
            signer.generateSignature();
            fail("spent key signed");
        }
        catch (ExhaustedPrivateKeyException e)
        {
            assertEquals("no usages of private key remaining", e.getMessage());
        }
    }

    private XMSSMTPrivateKeyParameters recoverXMSSMTAt(XMSSMTParameters params, byte[] seed, long index)
    {
        return new XMSSMTPrivateKeyParameters.Builder(params)
            .withSecretKeySeed(seed).withSecretKeyPRF(seed).withPublicSeed(seed).withRoot(seed)
            .withIndex(index).build();
    }

    private XMSSPrivateKeyParameters recoverXMSSAt(XMSSParameters params, byte[] seed, int index)
    {
        return new XMSSPrivateKeyParameters.Builder(params)
            .withSecretKeySeed(seed).withSecretKeyPRF(seed).withPublicSeed(seed).withRoot(seed)
            .withIndex(index).build();
    }

    private AsymmetricCipherKeyPair generateXMSS()
    {
        XMSSKeyPairGenerator gen = new XMSSKeyPairGenerator();
        gen.init(new XMSSKeyGenerationParameters(xmssParams(), new SecureRandom()));
        return gen.generateKeyPair();
    }

    private AsymmetricCipherKeyPair generateXMSSMT()
    {
        XMSSMTKeyPairGenerator gen = new XMSSMTKeyPairGenerator();
        gen.init(new XMSSMTKeyGenerationParameters(xmssMTParams(), new SecureRandom()));
        return gen.generateKeyPair();
    }
}
