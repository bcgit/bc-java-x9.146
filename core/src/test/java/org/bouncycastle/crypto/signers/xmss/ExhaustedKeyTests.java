package org.bouncycastle.crypto.signers.xmss;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.XMSSKeyPairGenerator;
import org.bouncycastle.crypto.generators.XMSSMTKeyPairGenerator;
import org.bouncycastle.crypto.params.XMSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSMTPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.params.XMSSPrivateKeyParameters;
import org.bouncycastle.crypto.signers.XMSSMTSigner;
import org.bouncycastle.crypto.signers.XMSSSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * A used-up XMSS / XMSS^MT private key has to survive being written out and read back. It is the
 * one state that most needs to persist - a key restored from an earlier saved state would sign
 * again with a one-time key it has already used - and it is the state the index bound is widest
 * for: an exhausted key carries the index one past its last leaf, which is the placeholder
 * traversal state BDS installs when the final one-time key is consumed.
 */
public class ExhaustedKeyTests
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

    private XMSSPrivateKeyParameters exhaustedXMSS(XMSSParameters params)
    {
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        XMSSPrivateKeyParameters privKey = (XMSSPrivateKeyParameters)kpg.generateKeyPair().getPrivate();

        for (int i = 0; i != (1 << HEIGHT); i++)
        {
            privKey.rollKey();
        }

        assertEquals(0, privKey.getUsagesRemaining());

        return privKey;
    }

    private XMSSMTPrivateKeyParameters exhaustedXMSSMT(XMSSMTParameters params)
    {
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));

        XMSSMTPrivateKeyParameters privKey = (XMSSMTPrivateKeyParameters)kpg.generateKeyPair().getPrivate();

        // the parameters' own height, not the constant: the byte-aligned-height case below uses
        // this helper at a height of its own
        for (int i = 0; i != (1 << params.getHeight()); i++)
        {
            privKey.rollKey();
        }

        assertEquals(0, privKey.getUsagesRemaining());

        return privKey;
    }

    /**
     * The encoding of a used-up key can be read back, and what comes back is still used up.
     */
    public void testExhaustedKeyRoundTripsAndStaysExhausted()
        throws Exception
    {
        XMSSParameters params = xmssParams();
        XMSSPrivateKeyParameters privKey = exhaustedXMSS(params);

        XMSSPrivateKeyParameters restored = new XMSSPrivateKeyParameters.Builder(params)
            .withPrivateKey(privKey.getEncoded()).build();

        assertEquals(0, restored.getUsagesRemaining());
        assertEquals(privKey.getIndex(), restored.getIndex());
        assertEquals((1 << HEIGHT) - 1, restored.getBDSState().getMaxIndex());
        assertTrue(Arrays.areEqual(privKey.getEncoded(), restored.getEncoded()));

        XMSSMTParameters mtParams = xmssMTParams();
        XMSSMTPrivateKeyParameters mtPrivKey = exhaustedXMSSMT(mtParams);

        XMSSMTPrivateKeyParameters mtRestored = new XMSSMTPrivateKeyParameters.Builder(mtParams)
            .withPrivateKey(mtPrivKey.getEncoded()).build();

        assertEquals(0, mtRestored.getUsagesRemaining());
        assertEquals(mtPrivKey.getIndex(), mtRestored.getIndex());
        assertTrue(Arrays.areEqual(mtPrivKey.getEncoded(), mtRestored.getEncoded()));
    }

    /**
     * The same through PKCS#8, which is the path a key takes into and out of a keystore.
     */
    public void testExhaustedKeyRoundTripsThroughPrivateKeyInfo()
        throws Exception
    {
        XMSSPrivateKeyParameters privKey = exhaustedXMSS(xmssParams());

        XMSSPrivateKeyParameters restored = (XMSSPrivateKeyParameters)PrivateKeyFactory.createKey(
            PrivateKeyInfoFactory.createPrivateKeyInfo(privKey).getEncoded());

        assertEquals(0, restored.getUsagesRemaining());
        assertEquals(privKey.getIndex(), restored.getIndex());

        XMSSMTPrivateKeyParameters mtPrivKey = exhaustedXMSSMT(xmssMTParams());

        XMSSMTPrivateKeyParameters mtRestored = (XMSSMTPrivateKeyParameters)PrivateKeyFactory.createKey(
            PrivateKeyInfoFactory.createPrivateKeyInfo(mtPrivKey).getEncoded());

        assertEquals(0, mtRestored.getUsagesRemaining());
        assertEquals(mtPrivKey.getIndex(), mtRestored.getIndex());
    }

    /**
     * An XMSS^MT height whose index does not fit the width the raw encoding writes it in. That
     * encoding gives the index ceil(height / 8) bytes, and the largest index a key can hold is
     * 2^height - the position an exhausted key sits at, one past its last leaf - so at every
     * height that is a multiple of eight the exhausted index is exactly one bit too wide. The
     * PKCS#8 structure carries the index as an integer of its own and has no such limit, but it
     * used to be built by encoding the whole key and reading the field back out of those bytes,
     * which did: an exhausted key was written out as a key at index 0 declaring a full tree of
     * unused one-time keys, and read back the same way. It could not sign - the traversal state it
     * carried was still the exhausted one, and the signer refuses that - but a stored key saying
     * the opposite of the truth about where a one-time key scheme has got to is the thing RFC 8391
     * sec. 1.1 is about.
     * <p>
     * Height 8 over 2 layers, so the index is written in one byte and the exhausted key sits at
     * 256. The standard sets this reaches are the XMSSMT_*_40/* ones, whose exhausted index needs
     * a sixth byte, and 2^40 signatures is not a number anyone arrives at - which is why nothing
     * had met it.
     * </p>
     */
    public void testExhaustedKeyAtAByteAlignedHeightRoundTripsThroughPrivateKeyInfo()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(8, 2, new SHA256Digest());
        XMSSMTPrivateKeyParameters privKey = exhaustedXMSSMT(params);

        assertEquals(1L << 8, privKey.getIndex());

        XMSSMTPrivateKeyParameters restored = (XMSSMTPrivateKeyParameters)PrivateKeyFactory.createKey(
            PrivateKeyInfoFactory.createPrivateKeyInfo(privKey).getEncoded());

        assertEquals("an exhausted key came back at a position it had signed from",
            privKey.getIndex(), restored.getIndex());
        assertEquals(0, restored.getUsagesRemaining());
    }

    /**
     * The raw encoding refuses an exhausted XMSS^MT index it cannot carry, rather than narrowing it.
     * <p>
     * The index field of the raw layout is ceil(h / 8) bytes, and the largest index a key can hold
     * is 2^h - the position it stops at when its last one-time key is spent - so at a height that
     * is a multiple of eight the field is one bit short. It used to be written narrowed, and read
     * back as zero: the key came back declaring a full tree of unused one-time keys. Nothing caught
     * it, because the index a key declares is checked against its per-layer states by decomposing
     * it into a leaf index per layer, and 2^h decomposes to the same leaf index as 0 does at every
     * layer.
     * </p><p>
     * Height 8 over 2 layers, so the field is one byte and the exhausted key sits at 256. The
     * standard sets this reaches are the XMSSMT_*_40/* ones, whose exhausted index would need a
     * sixth byte, and they reach it through the RFC 9802 form, which carries the raw encoding.
     * {@link #testExhaustedKeyAtAByteAlignedHeightRoundTripsThroughPrivateKeyInfo()} is the same
     * key on the legacy ASN.1 path, whose index field has no width of its own and holds it.
     * </p><p>
     * Every position below it still encodes, which is what the refusal must not cost: the loop
     * asks for the encoding at all 256 of them.
     * </p>
     */
    public void testExhaustedKeyAtAByteAlignedHeightRefusesTheRawEncoding()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(8, 2, new SHA256Digest());
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));

        XMSSMTPrivateKeyParameters privKey = (XMSSMTPrivateKeyParameters)kpg.generateKeyPair().getPrivate();

        for (int i = 0; i != (1 << 8); i++)
        {
            assertEquals(i, privKey.getIndex());
            assertTrue("a live key's position was refused", privKey.getEncoded().length > 0);
            privKey.rollKey();
        }

        assertEquals(1L << 8, privKey.getIndex());

        try
        {
            privKey.getEncoded();
            fail("an index the field cannot hold was written narrowed");
        }
        catch (IllegalStateException e)
        {
            assertEquals("index 256 does not fit the 1 byte index field of a stored private key",
                e.getMessage());
        }
    }

    /**
     * A restored exhausted key refuses to sign, in both families. Restoring one that could sign
     * again would reuse a one-time key, which is the failure RFC 8391 sec. 1.1 exists to prevent.
     */
    public void testRestoredExhaustedKeyRefusesToSign()
        throws Exception
    {
        XMSSParameters params = xmssParams();
        XMSSPrivateKeyParameters restored = new XMSSPrivateKeyParameters.Builder(params)
            .withPrivateKey(exhaustedXMSS(params).getEncoded()).build();

        XMSSSigner signer = new XMSSSigner();
        byte[] message = new byte[]{ 1, 2, 3 };

        signer.init(true, restored);
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

        XMSSMTParameters mtParams = xmssMTParams();
        XMSSMTPrivateKeyParameters mtRestored = new XMSSMTPrivateKeyParameters.Builder(mtParams)
            .withPrivateKey(exhaustedXMSSMT(mtParams).getEncoded()).build();

        XMSSMTSigner mtSigner = new XMSSMTSigner();

        mtSigner.init(true, mtRestored);
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
     * A key is also left at its one-past-the-end index by handing out its last usages as a shard,
     * rather than by rolling to the end, and the shard itself carries a maximum index short of the
     * tree's. Both encodings have to survive the round trip.
     */
    public void testKeyExhaustedByShardExtractionRoundTrips()
        throws Exception
    {
        XMSSParameters params = xmssParams();
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        XMSSPrivateKeyParameters privKey = (XMSSPrivateKeyParameters)kpg.generateKeyPair().getPrivate();

        XMSSPrivateKeyParameters shard = privKey.extractKeyShard((int)privKey.getUsagesRemaining());

        assertEquals(0, privKey.getUsagesRemaining());
        assertEquals(1 << HEIGHT, shard.getUsagesRemaining());

        XMSSPrivateKeyParameters restored = new XMSSPrivateKeyParameters.Builder(params)
            .withPrivateKey(privKey.getEncoded()).build();

        assertEquals(0, restored.getUsagesRemaining());

        // the shard covers the whole tree here, so take a smaller one to reach a maximum index
        // short of the tree's, exhaust that, and round trip it too
        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        XMSSPrivateKeyParameters parent = (XMSSPrivateKeyParameters)kpg.generateKeyPair().getPrivate();
        XMSSPrivateKeyParameters smallShard = parent.extractKeyShard(2);

        assertEquals(1, smallShard.getBDSState().getMaxIndex());

        smallShard.rollKey();
        smallShard.rollKey();

        assertEquals(0, smallShard.getUsagesRemaining());

        XMSSPrivateKeyParameters restoredShard = new XMSSPrivateKeyParameters.Builder(params)
            .withPrivateKey(smallShard.getEncoded()).build();

        assertEquals(0, restoredShard.getUsagesRemaining());
        assertEquals(smallShard.getIndex(), restoredShard.getIndex());
    }

    /**
     * The two ways a shard request is outside what the key can give: none at all, and more than
     * the key has left. Both families refuse both, and the message is how a caller catching
     * IllegalArgumentException tells them apart - the shard API has no other way of saying which
     * it was - so the message is the thing asserted, for both families, since the two used to
     * carry a copy of each string apiece.
     */
    public void testShardRequestsOutsideWhatTheKeyHasAreRefused()
        throws Exception
    {
        XMSSParameters params = xmssParams();
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        XMSSPrivateKeyParameters privKey = (XMSSPrivateKeyParameters)kpg.generateKeyPair().getPrivate();
        long usages = privKey.getUsagesRemaining();

        checkShardRefused(privKey, 0, "cannot ask for a shard with 0 keys");
        checkShardRefused(privKey, -1, "cannot ask for a shard with 0 keys");
        checkShardRefused(privKey, (int)usages + 1, "usageCount exceeds usages remaining");

        assertEquals("a refused shard must not move the key", usages, privKey.getUsagesRemaining());

        XMSSMTParameters mtParams = xmssMTParams();
        XMSSMTKeyPairGenerator mtKpg = new XMSSMTKeyPairGenerator();

        mtKpg.init(new XMSSMTKeyGenerationParameters(mtParams, new SecureRandom()));

        XMSSMTPrivateKeyParameters mtPrivKey =
            (XMSSMTPrivateKeyParameters)mtKpg.generateKeyPair().getPrivate();
        long mtUsages = mtPrivKey.getUsagesRemaining();

        checkShardRefused(mtPrivKey, 0, "cannot ask for a shard with 0 keys");
        checkShardRefused(mtPrivKey, -1, "cannot ask for a shard with 0 keys");
        checkShardRefused(mtPrivKey, (int)mtUsages + 1, "usageCount exceeds usages remaining");

        assertEquals("a refused shard must not move the key", mtUsages,
            mtPrivKey.getUsagesRemaining());
    }

    private void checkShardRefused(XMSSPrivateKeyParameters privKey, int usageCount, String message)
    {
        try
        {
            privKey.extractKeyShard(usageCount);
            fail("shard of " + usageCount + " was handed out");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals(message, e.getMessage());
        }
    }

    private void checkShardRefused(XMSSMTPrivateKeyParameters privKey, int usageCount, String message)
    {
        try
        {
            privKey.extractKeyShard(usageCount);
            fail("shard of " + usageCount + " was handed out");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals(message, e.getMessage());
        }
    }

    /**
     * The index bound is one leaf wider than the signing bound, not open: one past the exhausted
     * index is still out of bounds, so is a negative index, and an index that does not match the
     * traversal state it arrived with is still caught.
     */
    public void testIndexBeyondExhaustionStillRejected()
        throws Exception
    {
        XMSSParameters params = xmssParams();
        byte[] encoded = exhaustedXMSS(params).getEncoded();

        checkRejected(params, withIndex(encoded, (1 << HEIGHT) + 1), "index out of bounds");
        checkRejected(params, withIndex(encoded, -1), "index out of bounds");
        checkRejected(params, withIndex(encoded, Integer.MAX_VALUE), "index out of bounds");
        checkRejected(params, withIndex(encoded, 3), "BDS state has wrong index");
    }

    private byte[] withIndex(byte[] encoded, int index)
    {
        byte[] altered = Arrays.clone(encoded);

        Pack.intToBigEndian(index, altered, 0);

        return altered;
    }

    private void checkRejected(XMSSParameters params, byte[] encoded, String message)
    {
        try
        {
            new XMSSPrivateKeyParameters.Builder(params).withPrivateKey(encoded).build();
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals(message, e.getMessage());
        }
    }
}
