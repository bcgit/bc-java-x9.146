package org.bouncycastle.crypto.signers.xmss;

import java.security.SecureRandom;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
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
import org.bouncycastle.util.Pack;

/**
 * A signer's private key field is not the monitor to lock on, because the signer itself replaces
 * it: getUpdatedPrivateKey() installs the shard the signer keeps and init() installs a new key
 * outright. Both signers used to read that field into a local and only then synchronize on what
 * they had read, so a call that had read the old key and a call that had read the new one held two
 * different monitors and excluded each other from nothing.
 * <p>
 * What comes out of that is the failure a stateful scheme cannot have. getUpdatedPrivateKey() hands
 * the caller the key to persist, having rolled it past the index the signer will spend; a signature
 * that had already read the same object then spends the index the caller has just been told is
 * still unused. Storing that key and restoring it signs a second message under one WOTS+ one-time
 * key, and both signatures verify - RFC 8391 sec. 1.1.
 * </p>
 * <p>
 * So the invariant asserted here is a range one, not a timing one: whatever order the two calls
 * take, the key handed back for storage must sit strictly past every index the signer has spent.
 * Before the fix this failed on roughly a third of the trials below; it cannot fail by chance.
 * </p>
 */
public class SignerConcurrencyTests
    extends TestCase
{
    private static final int HEIGHT = 4;
    private static final int LAYERS = 2;
    private static final int TRIALS = 120;

    public void testStoredXMSSKeyNeverSitsOnASignedIndex()
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(HEIGHT, new SHA256Digest());
        SecureRandom random = new SecureRandom();

        for (int trial = 0; trial != TRIALS; trial++)
        {
            XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

            kpg.init(new XMSSKeyGenerationParameters(params, random));

            AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
            final XMSSSigner signer = new XMSSSigner();

            signer.init(true, kp.getPrivate());
            signer.update(new byte[]{1, 2, 3}, 0, 3);

            final long[] signed = {-1L};
            final long[] stored = {-1L};
            final CountDownLatch go = new CountDownLatch(1);

            Thread signing = new Thread()
            {
                public void run()
                {
                    try
                    {
                        go.await();
                        // a signature and a key encoding both open with the index, 4 bytes
                        // big-endian for XMSS (RFC 8391 sec. 4.1.8)
                        signed[0] = Pack.bigEndianToLong_Low(signer.generateSignature(), 0, 4);
                    }
                    catch (Exception e)
                    {
                        // a key already handed over is a legitimate outcome of the other ordering
                    }
                }
            };

            Thread collecting = new Thread()
            {
                public void run()
                {
                    try
                    {
                        go.await();

                        XMSSPrivateKeyParameters key =
                            (XMSSPrivateKeyParameters)signer.getUpdatedPrivateKey();

                        if (key != null)
                        {
                            // as a caller persisting it does. The encode takes the key's own
                            // monitor, so it lands either side of a signature but never inside one
                            stored[0] = Pack.bigEndianToLong_Low(key.getEncoded(), 0, 4);
                        }
                    }
                    catch (Exception e)
                    {
                    }
                }
            };

            run(signing, collecting, go);

            if (signed[0] >= 0 && stored[0] >= 0)
            {
                assertTrue("XMSS key stored at index " + stored[0] + " after index " + signed[0]
                    + " was signed", stored[0] > signed[0]);
            }
        }
    }

    public void testStoredXMSSMTKeyNeverSitsOnASignedIndex()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest());
        SecureRandom random = new SecureRandom();
        final int indexSize = (HEIGHT + 7) / 8;

        for (int trial = 0; trial != TRIALS; trial++)
        {
            XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

            kpg.init(new XMSSMTKeyGenerationParameters(params, random));

            AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
            final XMSSMTSigner signer = new XMSSMTSigner();

            signer.init(true, kp.getPrivate());
            signer.update(new byte[]{1, 2, 3}, 0, 3);

            final long[] signed = {-1L};
            final long[] stored = {-1L};
            final CountDownLatch go = new CountDownLatch(1);

            Thread signing = new Thread()
            {
                public void run()
                {
                    try
                    {
                        go.await();
                        // the same index, in the ceil(h / 8) bytes XMSS^MT gives it
                        // (RFC 8391 sec. 4.2.5)
                        signed[0] = Pack.bigEndianToLong_Low(signer.generateSignature(), 0, indexSize);
                    }
                    catch (Exception e)
                    {
                    }
                }
            };

            Thread collecting = new Thread()
            {
                public void run()
                {
                    try
                    {
                        go.await();

                        XMSSMTPrivateKeyParameters key =
                            (XMSSMTPrivateKeyParameters)signer.getUpdatedPrivateKey();

                        if (key != null)
                        {
                            stored[0] = Pack.bigEndianToLong_Low(key.getEncoded(), 0, indexSize);
                        }
                    }
                    catch (Exception e)
                    {
                    }
                }
            };

            run(signing, collecting, go);

            if (signed[0] >= 0 && stored[0] >= 0)
            {
                assertTrue("XMSS^MT key stored at index " + stored[0] + " after index " + signed[0]
                    + " was signed", stored[0] > signed[0]);
            }
        }
    }

    /**
     * XMSSMTPrivateKeyParameters.getBDSState() hands out the live state map, and the signer
     * installs subtree states into that same map with put() as it descends the layers. So copying
     * a state map off a key that is signing - which is what the builder does with what the getter
     * returned, the shape the suite's own testKeyBuilderCopiesTheTraversalStateItIsGiven uses -
     * walked a TreeMap while it was being restructured. That is a ConcurrentModificationException
     * where the walk notices, and a torn read of the tree where it does not: the copy comes back
     * with layers missing or with a null where a state should be, and a key built on it is
     * unusable in a way that only shows up when it next signs.
     */
    public void testStateMapCanBeCopiedWhileTheKeyIsSigning()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(6, 3, new SHA256Digest());
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));

        final XMSSMTPrivateKeyParameters key =
            (XMSSMTPrivateKeyParameters)kpg.generateKeyPair().getPrivate();
        final int signatures = 1 << 6;
        final Throwable[] failure = {null};
        final boolean[] done = {false};

        Thread copying = new Thread()
        {
            public void run()
            {
                try
                {
                    while (!done[0])
                    {
                        BDSStateMap live = key.getBDSState();
                        BDSStateMap copy = new BDSStateMap(live, live.getMaxIndex());

                        for (int layer = 0; layer != 3; layer++)
                        {
                            BDS state = copy.get(layer);

                            // a layer built lazily is legitimately absent; one present must be
                            // whole, which a copy taken out of a map mid-restructure is not
                            if (state != null)
                            {
                                state.validate(params.getXMSSParameters());
                            }
                        }
                    }
                }
                catch (Throwable t)
                {
                    failure[0] = t;
                }
            }
        };

        copying.start();

        try
        {
            for (int i = 0; i != signatures; i++)
            {
                XMSSEngine.generateMTSignature(key, new byte[]{(byte)i});
            }
        }
        finally
        {
            done[0] = true;
            copying.join();
        }

        if (failure[0] != null)
        {
            fail("copying the state map of a signing key: " + failure[0]);
        }
    }

    /**
     * validateRoot() was the one accessor on BDSStateMap that read the map without taking the
     * monitor the rest of them take. It is reached while a key is being built around a state map a
     * live key still holds - the constructor and the builder both call it - and the signer of that
     * key puts each lazily built layer into the same map as it descends, an insertion that
     * rebalances the TreeMap. A lookup racing one walks a tree that is part way through being
     * rearranged, and comes back with the top layer's state, a null, or a state belonging to
     * another layer: the first is right by luck, the second silently skips the check the method
     * exists to make, and the third fails a key whose root is exactly what it should be.
     * <p>
     * Asserted as the lock discipline rather than as an outcome, the way the provider keys'
     * testEqualsTakesTheTwoKeyMonitorsOneAtATime is: hold the map's monitor and the call must wait
     * for it. Without the synchronized block it returns in microseconds, so the second it is given
     * here is not a timing margin being trusted - it is the difference between waiting and not.
     * </p>
     */
    public void testValidatingTheRootWaitsForTheStateMapItReads()
        throws Exception
    {
        final XMSSMTParameters params = new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest());
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));

        XMSSMTPrivateKeyParameters key =
            (XMSSMTPrivateKeyParameters)kpg.generateKeyPair().getPrivate();

        final BDSStateMap stateMap = key.getBDSState();
        final byte[] root = key.getRoot();

        // the top layer is the one validateRoot looks at, and it is there from key generation - so
        // the call has real work to do inside the monitor rather than falling out of a null check
        assertNotNull("the top layer's state", stateMap.get(LAYERS - 1));

        final CountDownLatch held = new CountDownLatch(1);
        final CountDownLatch release = new CountDownLatch(1);
        final CountDownLatch validated = new CountDownLatch(1);
        final Throwable[] failure = {null};

        Thread holder = new Thread()
        {
            public void run()
            {
                synchronized (stateMap)
                {
                    held.countDown();

                    try
                    {
                        release.await();
                    }
                    catch (InterruptedException e)
                    {
                        failure[0] = e;
                    }
                }
            }
        };

        Thread validating = new Thread()
        {
            public void run()
            {
                try
                {
                    stateMap.validateRoot(params, root);
                }
                catch (Throwable t)
                {
                    failure[0] = t;
                }

                validated.countDown();
            }
        };

        holder.start();
        held.await();
        validating.start();

        try
        {
            assertFalse("validateRoot must take the monitor every other read of the map takes",
                validated.await(1, TimeUnit.SECONDS));
        }
        finally
        {
            release.countDown();
        }

        assertTrue("and complete once it is released", validated.await(10, TimeUnit.SECONDS));

        holder.join();
        validating.join();

        if (failure[0] != null)
        {
            fail("validating the root of a held state map: " + failure[0]);
        }
    }

    private static void run(Thread signing, Thread collecting, CountDownLatch go)
        throws InterruptedException
    {
        signing.start();
        collecting.start();
        go.countDown();
        signing.join();
        collecting.join();
    }
}
