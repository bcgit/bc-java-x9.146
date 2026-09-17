package org.bouncycastle.crypto.signers.xmss;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
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
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Longs;
import org.bouncycastle.util.Pack;

/**
 * RFC 8391 sec. 1.1: each one-time key must be used exactly once. A WOTS+ key used twice discloses
 * enough of itself to forge, so two verifying signatures at the same index are a private key
 * compromise, not a merely surprising result.
 * <p>
 * XMSSEngine.generateSignature / generateMTSignature both read the key's index and roll the key
 * past it, which is only safe as one atomic sequence. They are public entry points reachable
 * without going through XMSSSigner / XMSSMTSigner, so they take the lock on the key themselves
 * rather than relying on the caller to hold it; these tests drive them directly, the way a caller
 * using the lightweight API would, and assert no index is ever spent twice.
 * </p>
 */
public class OneTimeKeyReuseTests
    extends TestCase
{
    private static final int HEIGHT = 4;
    private static final int LAYERS = 2;
    private static final int THREADS = 4;
    private static final int TRIALS = 8;

    /**
     * The signatures produced by a set of threads racing on one key, ignoring the threads that
     * failed - a signature that was never produced spends nothing.
     */
    private static List sign(final Object privKey, final boolean multiTree)
        throws InterruptedException
    {
        final List sigs = new ArrayList();
        final Object lock = new Object();
        Thread[] threads = new Thread[THREADS];

        for (int i = 0; i != THREADS; i++)
        {
            final byte[] message = new byte[]{(byte)i, 0x5a};

            threads[i] = new Thread()
            {
                public void run()
                {
                    byte[] sig;
                    try
                    {
                        sig = multiTree
                            ? XMSSEngine.generateMTSignature((XMSSMTPrivateKeyParameters)privKey, message)
                            : XMSSEngine.generateSignature((XMSSPrivateKeyParameters)privKey, message);
                    }
                    catch (RuntimeException e)
                    {
                        // key exhausted, or this thread lost the race: nothing was spent
                        return;
                    }

                    synchronized (lock)
                    {
                        sigs.add(new Object[]{message, sig});
                    }
                }
            };
        }

        for (int i = 0; i != THREADS; i++)
        {
            threads[i].start();
        }
        for (int i = 0; i != THREADS; i++)
        {
            threads[i].join();
        }

        return sigs;
    }

    public void testXMSSConcurrentSigningSpendsEachOneTimeKeyOnce()
        throws Exception
    {
        for (int trial = 0; trial != TRIALS; trial++)
        {
            XMSSParameters params = new XMSSParameters(HEIGHT, new SHA256Digest());
            XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

            kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

            AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
            XMSSPrivateKeyParameters privKey = (XMSSPrivateKeyParameters)kp.getPrivate();
            XMSSPublicKeyParameters pubKey = (XMSSPublicKeyParameters)kp.getPublic();

            List sigs = sign(privKey, false);
            Set seen = new HashSet();

            for (int i = 0; i != sigs.size(); i++)
            {
                Object[] pair = (Object[])sigs.get(i);
                byte[] message = (byte[])pair[0];
                byte[] sig = (byte[])pair[1];

                // only a signature that verifies represents a one-time key that was actually spent
                if (!XMSSEngine.verifySignature(pubKey, message, sig))
                {
                    continue;
                }

                // an XMSS signature leads with its 4-byte big-endian index (RFC 8391 sec. 4.1.8)
                Integer index = Integers.valueOf((int)Pack.bigEndianToLong_Low(sig, 0, 4));

                assertTrue("one-time key at index " + index + " signed twice", seen.add(index));
            }
        }
    }

    public void testXMSSMTConcurrentSigningSpendsEachOneTimeKeyOnce()
        throws Exception
    {
        int indexSize = (HEIGHT + 7) / 8;

        for (int trial = 0; trial != TRIALS; trial++)
        {
            XMSSMTParameters params = new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest());
            XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

            kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));

            AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
            XMSSMTPrivateKeyParameters privKey = (XMSSMTPrivateKeyParameters)kp.getPrivate();
            XMSSMTPublicKeyParameters pubKey = (XMSSMTPublicKeyParameters)kp.getPublic();

            List sigs = sign(privKey, true);
            Set seen = new HashSet();

            for (int i = 0; i != sigs.size(); i++)
            {
                Object[] pair = (Object[])sigs.get(i);
                byte[] message = (byte[])pair[0];
                byte[] sig = (byte[])pair[1];

                if (!XMSSEngine.verifyMTSignature(pubKey, message, sig))
                {
                    continue;
                }

                // an XMSS^MT signature leads with its ceil(h/8)-byte index (RFC 8391 sec. 4.2.5)
                Long index = Longs.valueOf(Pack.bigEndianToLong_Low(sig, 0, indexSize));

                assertTrue("one-time key at index " + index + " signed twice", seen.add(index));
            }
        }
    }

    /**
     * Both paths record on the traversal state that its one-time key has signed. The record is
     * only still there to see where the roll leaves that state in place, which is the last leaf
     * of a subtree: everywhere else the roll installs a fresh state, sitting on a leaf that has
     * not signed yet. The XMSS^MT path did not make the record at all, so its state said no leaf
     * had ever signed.
     */
    public void testSignatureMarksTheOneTimeKeyItSpent()
        throws Exception
    {
        XMSSMTParameters mtParams = new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest());
        XMSSMTKeyPairGenerator mtKpg = new XMSSMTKeyPairGenerator();

        mtKpg.init(new XMSSMTKeyGenerationParameters(mtParams, new SecureRandom()));

        XMSSMTPrivateKeyParameters mtKey =
            (XMSSMTPrivateKeyParameters)mtKpg.generateKeyPair().getPrivate();
        int leaves = 1 << mtParams.getXMSSParameters().getHeight();

        for (int i = 1; i <= leaves; i++)
        {
            XMSSEngine.generateMTSignature(mtKey, new byte[]{(byte)i});

            assertEquals("XMSS^MT layer zero after signature " + i, i == leaves,
                mtKey.getBDSState().get(0).isUsed());
        }

        // the XMSS twin, whose record this was mirrored from: its whole tree is the subtree, so
        // the state is left in place only on the very last leaf, where it is the exhausted key
        // placeholder
        XMSSParameters params = new XMSSParameters(HEIGHT, new SHA256Digest());
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        XMSSPrivateKeyParameters key = (XMSSPrivateKeyParameters)kpg.generateKeyPair().getPrivate();

        for (int i = 1; i <= (1 << HEIGHT); i++)
        {
            XMSSEngine.generateSignature(key, new byte[]{(byte)i});

            assertEquals("XMSS after signature " + i, i == (1 << HEIGHT),
                key.getBDSState().isUsed());
        }
    }

    /**
     * The XMSS counterpart of the copy above. Its state is a single BDS and no layer states are
     * installed into it, but a signature still marks the state it spent in place, so two keys
     * sharing one BDS share that record: the key signing marks the state of the key that is not,
     * and the one that has signed nothing is then refused as a key that has already signed.
     */
    public void testXMSSKeyBuilderCopiesTheTraversalStateItIsGiven()
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(HEIGHT, new SHA256Digest());
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        XMSSPrivateKeyParameters key = (XMSSPrivateKeyParameters)kpg.generateKeyPair().getPrivate();
        XMSSPrivateKeyParameters shard = new XMSSPrivateKeyParameters.Builder(params)
            .withSecretKeySeed(key.getSecretKeySeed()).withSecretKeyPRF(key.getSecretKeyPRF())
            .withPublicSeed(key.getPublicSeed()).withRoot(key.getRoot())
            .withBDSState(key.getBDSState()).build();

        assertNotSame("the builder must copy the state it is given, not adopt it",
            key.getBDSState(), shard.getBDSState());

        XMSSEngine.generateSignature(key, new byte[]{0x01});

        assertEquals("the other key's index moved", 1, key.getIndex());
        assertEquals("the shard's index did not", 0, shard.getIndex());
        assertFalse("nor may the other key's signature mark the shard's state",
            shard.getBDSState().isUsed());

        // which is the point: a shard that has signed nothing must still be able to
        XMSSEngine.generateSignature(shard, new byte[]{0x02});
        assertEquals(1, shard.getIndex());
    }

    /**
     * markUsed() had no read side. The record it leaves travels with the state - it is copied by
     * every BDS copy constructor and written into the encoding - so a key can arrive holding a
     * state that says it has already signed, and nothing looked. The way there is ordinary: take
     * the traversal state off a live key, let that key sign, and the object taken is the one the
     * signature marked, because a signature marks its state and then replaces it. Build a key back
     * around what was taken and it sits on the index the signature spent, which RFC 8391 sec. 1.1
     * makes a private key compromise rather than a surprising result - both signatures verify.
     */
    public void testSigningIsRefusedOnAStateThatHasAlreadySigned()
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(HEIGHT, new SHA256Digest());
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        XMSSPrivateKeyParameters key = (XMSSPrivateKeyParameters)kpg.generateKeyPair().getPrivate();
        BDS spent = key.getBDSState();

        XMSSEngine.generateSignature(key, new byte[]{0x01});

        assertTrue("the signature must mark the state it spent", spent.isUsed());
        assertEquals("and roll the key past it", 1, key.getIndex());

        XMSSPrivateKeyParameters rolledBack = new XMSSPrivateKeyParameters.Builder(params)
            .withSecretKeySeed(key.getSecretKeySeed()).withSecretKeyPRF(key.getSecretKeyPRF())
            .withPublicSeed(key.getPublicSeed()).withRoot(key.getRoot())
            .withBDSState(spent).build();

        assertEquals("the rebuilt key is back on the index that signature spent",
            0, rolledBack.getIndex());

        try
        {
            XMSSEngine.generateSignature(rolledBack, new byte[]{0x02});
            fail("a state that has already signed must not sign again");
        }
        catch (IllegalStateException e)
        {
            assertEquals("one time key at index 0 has already signed", e.getMessage());
        }
    }

    /**
     * The XMSS^MT counterpart, on the layer zero state - the one whose leaf signs the message.
     * <p>
     * The check has to make the allowance BDSStateMap.validate(params, globalIndex) makes: on the
     * first leaf of a subtree the signer builds layer zero fresh, so the marked state carried over
     * from the end of the previous subtree is legitimate at that one position. Signing every leaf
     * of a subtree and on into the next covers it.
     * </p>
     */
    public void testMTSigningIsRefusedOnALayerZeroStateThatHasAlreadySigned()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest());
        XMSSMTPrivateKeyParameters key = mtKey(params);

        // one signature, so layer zero exists and sits somewhere other than a subtree boundary
        XMSSEngine.generateMTSignature(key, new byte[]{0x01});

        BDSStateMap spent = key.getBDSState();

        XMSSEngine.generateMTSignature(key, new byte[]{0x02});

        assertTrue("the signature must mark the layer zero state it spent", spent.get(0).isUsed());

        XMSSMTPrivateKeyParameters rolledBack = new XMSSMTPrivateKeyParameters.Builder(params)
            .withSecretKeySeed(key.getSecretKeySeed()).withSecretKeyPRF(key.getSecretKeyPRF())
            .withPublicSeed(key.getPublicSeed()).withRoot(key.getRoot())
            .withIndex(1L).withBDSState(spent).build();

        try
        {
            XMSSEngine.generateMTSignature(rolledBack, new byte[]{0x03});
            fail("a layer zero state that has already signed must not sign again");
        }
        catch (IllegalStateException e)
        {
            assertEquals("one time key at index 1 has already signed", e.getMessage());
        }

        // and the allowance: a whole key signed through, across every subtree boundary in it
        XMSSMTPrivateKeyParameters walked = mtKey(params);

        for (long i = 0; i != (1L << HEIGHT); i++)
        {
            assertEquals(i, walked.getIndex());
            XMSSEngine.generateMTSignature(walked, new byte[]{(byte)i});
        }
    }

    private static XMSSMTPrivateKeyParameters mtKey(XMSSMTParameters params)
    {
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));

        return (XMSSMTPrivateKeyParameters)kpg.generateKeyPair().getPrivate();
    }

    /**
     * Rolling the key replaces its state map, but signing still installs subtree states into the
     * map as it descends the layers, so the builder has to copy one it is handed rather than adopt
     * it. Adopting it leaves two keys reading authentication paths out of one map while each sits
     * at its own index.
     * <p>
     * The XMSS side has no equivalent: its state is a single BDS the signer only reads.
     * </p>
     */
    public void testKeyBuilderCopiesTheTraversalStateItIsGiven()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest());
        XMSSMTPrivateKeyParameters key = mtKey(params);

        // sign once so layer zero is populated and its position is something to watch
        XMSSEngine.generateMTSignature(key, new byte[]{0x01});
        assertEquals(1L, key.getIndex());

        XMSSMTPrivateKeyParameters shard = new XMSSMTPrivateKeyParameters.Builder(params)
            .withSecretKeySeed(key.getSecretKeySeed()).withSecretKeyPRF(key.getSecretKeyPRF())
            .withPublicSeed(key.getPublicSeed()).withRoot(key.getRoot())
            .withIndex(key.getIndex())
            .withBDSState(key.getBDSState()).build();

        assertNotSame("the builder must copy the state map it is given, not adopt it",
            key.getBDSState(), shard.getBDSState());

        int before = shard.getBDSState().get(0).getIndex();

        XMSSEngine.generateMTSignature(key, new byte[]{0x02});

        assertEquals("the other key's index moved", 2L, key.getIndex());
        assertEquals("the shard's index did not", 1L, shard.getIndex());
        assertEquals("nor may its traversal state, or it would sign again under the key at index 1",
            before, shard.getBDSState().get(0).getIndex());
    }

    /**
     * XMSSEngine.getNextBDSStateMap has to be public - the key parameters class is in another
     * package - so a caller can reach it with a state map taken off a live key. It hands the
     * advanced state back rather than applying it to the map it was given, so what such a caller
     * gets is a state map of its own, and the key it took the state from is untouched.
     */
    public void testTakingTheNextStateOffAKeyLeavesTheKeyWhereItWas()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest());
        XMSSMTPrivateKeyParameters key = mtKey(params);

        XMSSEngine.generateMTSignature(key, new byte[]{0x01});

        BDSStateMap held = key.getBDSState();
        int before = held.get(0).getIndex();

        BDSStateMap next = XMSSEngine.getNextBDSStateMap(held, key.getParameters(), key.getIndex(),
            key.getPublicSeed(), key.getSecretKeySeed());

        assertNotSame("the advanced state has to be a new map", held, next);
        assertEquals("and it is the one that moved", before + 1, next.get(0).getIndex());

        assertSame("the key still holds the state it had", held, key.getBDSState());
        assertEquals("which has not moved", before, held.get(0).getIndex());
        assertEquals("nor has its index", 1L, key.getIndex());
    }

    /**
     * So a caller cannot part a key's index from its traversal state, which is what would let the
     * key sign again under a one-time key its state had already moved past. Taking the next state
     * off the map a holder got from the key changes nothing about the key: it signs on at the index
     * it was on, and the signature verifies.
     */
    public void testAHolderCannotMoveAKeysStateOutFromUnderIt()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest());
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        XMSSMTPrivateKeyParameters key = (XMSSMTPrivateKeyParameters)kp.getPrivate();
        XMSSMTPublicKeyParameters publicKey = (XMSSMTPublicKeyParameters)kp.getPublic();

        XMSSEngine.generateMTSignature(key, new byte[]{0x01});

        XMSSEngine.getNextBDSStateMap(key.getBDSState(), key.getParameters(), key.getIndex(),
            key.getPublicSeed(), key.getSecretKeySeed());

        byte[] message = new byte[]{0x02};
        byte[] signature = XMSSEngine.generateMTSignature(key, message);

        assertEquals("the key spent one index, the one it was on", 2L, key.getIndex());
        assertTrue("the signature taken after a holder advanced the state it was handed",
            XMSSEngine.verifyMTSignature(publicKey, message, signature));

        // and on, through the subtree boundary that advance would have skipped
        for (int i = 2; i != (1 << HEIGHT); i++)
        {
            message = new byte[]{(byte)i};

            assertTrue("signature at index " + i, XMSSEngine.verifyMTSignature(publicKey, message,
                XMSSEngine.generateMTSignature(key, message)));
        }
    }
}
