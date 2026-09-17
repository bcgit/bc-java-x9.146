package org.bouncycastle.crypto.signers.xmss;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.XMSSKeyPairGenerator;
import org.bouncycastle.crypto.generators.XMSSMTKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
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

/**
 * getUpdatedPrivateKey() is how a caller collects the advanced state it is obliged to persist, so
 * it is reached in situations where there is no state to collect: a signer that was never
 * initialised for signing, one initialised only for verification, and one whose key a previous
 * call has already taken. All three report an absent key the same way, in both families.
 */
public class SignerStateHandoverTests
    extends TestCase
{
    private static final int HEIGHT = 4;
    private static final int LAYERS = 2;

    private AsymmetricCipherKeyPair xmssKeyPair(XMSSParameters params)
    {
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        return kpg.generateKeyPair();
    }

    private AsymmetricCipherKeyPair xmssMTKeyPair(XMSSMTParameters params)
    {
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));

        return kpg.generateKeyPair();
    }

    /**
     * Having signed, the first call hands the advanced key over and the second reports that there
     * is nothing left to hand over - rather than raising a NullPointerException on the way in.
     */
    public void testKeyCollectedOnlyOnceAfterSigning()
    {
        AsymmetricCipherKeyPair kp = xmssKeyPair(new XMSSParameters(HEIGHT, new SHA256Digest()));
        XMSSSigner signer = new XMSSSigner();

        signer.init(true, kp.getPrivate());
        signer.update(new byte[]{ 1, 2, 3 }, 0, 3);
        signer.generateSignature();

        assertSame(kp.getPrivate(), signer.getUpdatedPrivateKey());
        assertNull(signer.getUpdatedPrivateKey());

        AsymmetricCipherKeyPair mtKp = xmssMTKeyPair(new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest()));
        XMSSMTSigner mtSigner = new XMSSMTSigner();

        mtSigner.init(true, mtKp.getPrivate());
        mtSigner.update(new byte[]{ 1, 2, 3 }, 0, 3);
        mtSigner.generateSignature();

        assertSame(mtKp.getPrivate(), mtSigner.getUpdatedPrivateKey());
        assertNull(mtSigner.getUpdatedPrivateKey());
    }

    /**
     * A signer with no signing key to give back says so, whether it was never initialised at all
     * or initialised for verification.
     */
    public void testNoKeyToCollectReportedAsAbsent()
    {
        AsymmetricCipherKeyPair kp = xmssKeyPair(new XMSSParameters(HEIGHT, new SHA256Digest()));

        assertNull(new XMSSSigner().getUpdatedPrivateKey());

        XMSSSigner verifier = new XMSSSigner();

        verifier.init(false, kp.getPublic());
        assertNull(verifier.getUpdatedPrivateKey());

        AsymmetricCipherKeyPair mtKp = xmssMTKeyPair(new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest()));

        assertNull(new XMSSMTSigner().getUpdatedPrivateKey());

        XMSSMTSigner mtVerifier = new XMSSMTSigner();

        mtVerifier.init(false, mtKp.getPublic());
        assertNull(mtVerifier.getUpdatedPrivateKey());
    }

    /**
     * Initialised but not yet used, the key stays with the caller and the signer keeps the shard
     * covering the usage it has not spent - the "leave it in place" half of the contract.
     */
    public void testInitialisedButUnusedSignerHandsBackTheKeyItWasGiven()
    {
        AsymmetricCipherKeyPair kp = xmssKeyPair(new XMSSParameters(HEIGHT, new SHA256Digest()));
        XMSSPrivateKeyParameters privKey = (XMSSPrivateKeyParameters)kp.getPrivate();
        XMSSSigner signer = new XMSSSigner();

        signer.init(true, privKey);

        assertSame(privKey, signer.getUpdatedPrivateKey());
        assertEquals((1 << HEIGHT) - 1, privKey.getUsagesRemaining());
        assertEquals(1, signer.getUsagesRemaining());   // the shard covers the one unspent usage

        AsymmetricCipherKeyPair mtKp = xmssMTKeyPair(new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest()));
        XMSSMTPrivateKeyParameters mtPrivKey = (XMSSMTPrivateKeyParameters)mtKp.getPrivate();
        XMSSMTSigner mtSigner = new XMSSMTSigner();

        mtSigner.init(true, mtPrivKey);

        assertSame(mtPrivKey, mtSigner.getUpdatedPrivateKey());
        assertEquals((1 << HEIGHT) - 1, mtPrivKey.getUsagesRemaining());
        assertEquals(1, mtSigner.getUsagesRemaining());   // the shard covers the one unspent usage
    }

    /**
     * A signature the engine refuses must leave the signer where it was, because what
     * getUpdatedPrivateKey() does next turns on whether one was made. hasGenerated used to be set
     * before the engine was called rather than from what the call did to the key, and the engine
     * has a guard the signer does not repeat - a traversal state that has already signed at the
     * index it is sitting on - which throws ahead of the try whose finally rolls the key. So a
     * refused signature left the signer reporting a key it had never spent: the collection that
     * follows hands the key back and then empties the signer, and the caller that asks a second
     * time is told there is nothing left, of a key that is still at index 0 with every one of its
     * usages unspent.
     * <p>
     * The state that provokes it is the one OneTimeKeyReuseTests builds: a traversal state taken
     * off a live key before it signs is the object that signature marks, so a key rebuilt around it
     * sits on an index it has already used. Asserted against the never-signed path beside it -
     * after the refusal the signer must hand its key over and still hold one, exactly as
     * testInitialisedButUnusedSignerHandsBackTheKeyItWasGiven has it.
     * </p>
     */
    public void testRefusedSignatureLeavesTheSignerHoldingItsKey()
    {
        XMSSParameters params = new XMSSParameters(HEIGHT, new SHA256Digest());
        XMSSPrivateKeyParameters spender =
            (XMSSPrivateKeyParameters)xmssKeyPair(params).getPrivate();
        BDS spent = spender.getBDSState();

        XMSSEngine.generateSignature(spender, new byte[]{0x01});

        XMSSPrivateKeyParameters privKey = new XMSSPrivateKeyParameters.Builder(params)
            .withSecretKeySeed(spender.getSecretKeySeed()).withSecretKeyPRF(spender.getSecretKeyPRF())
            .withPublicSeed(spender.getPublicSeed()).withRoot(spender.getRoot())
            .withBDSState(spent).build();

        XMSSSigner signer = new XMSSSigner();

        signer.init(true, privKey);
        signer.update(new byte[]{0x02}, 0, 1);

        try
        {
            signer.generateSignature();
            fail("a state that has already signed must not sign again");
        }
        catch (IllegalStateException e)
        {
            assertEquals("one time key at index 0 has already signed", e.getMessage());
        }

        assertEquals("the refused signature must not have moved the key", 0, privKey.getIndex());
        assertSame(privKey, signer.getUpdatedPrivateKey());
        assertNotNull("the signer spent nothing, so it still holds a key",
            signer.getUpdatedPrivateKey());

        XMSSMTParameters mtParams = new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest());
        XMSSMTPrivateKeyParameters mtSpender =
            (XMSSMTPrivateKeyParameters)xmssMTKeyPair(mtParams).getPrivate();

        // twice, so layer zero exists and sits off the subtree boundary the check allows for
        XMSSEngine.generateMTSignature(mtSpender, new byte[]{0x01});

        BDSStateMap mtSpent = mtSpender.getBDSState();

        XMSSEngine.generateMTSignature(mtSpender, new byte[]{0x02});

        XMSSMTPrivateKeyParameters mtPrivKey = new XMSSMTPrivateKeyParameters.Builder(mtParams)
            .withSecretKeySeed(mtSpender.getSecretKeySeed()).withSecretKeyPRF(mtSpender.getSecretKeyPRF())
            .withPublicSeed(mtSpender.getPublicSeed()).withRoot(mtSpender.getRoot())
            .withIndex(1L).withBDSState(mtSpent).build();

        XMSSMTSigner mtSigner = new XMSSMTSigner();

        mtSigner.init(true, mtPrivKey);
        mtSigner.update(new byte[]{0x03}, 0, 1);

        try
        {
            mtSigner.generateSignature();
            fail("a layer zero state that has already signed must not sign again");
        }
        catch (IllegalStateException e)
        {
            assertEquals("one time key at index 1 has already signed", e.getMessage());
        }

        assertEquals("the refused signature must not have moved the key", 1L, mtPrivKey.getIndex());
        assertSame(mtPrivKey, mtSigner.getUpdatedPrivateKey());
        assertNotNull("the signer spent nothing, so it still holds a key",
            mtSigner.getUpdatedPrivateKey());
    }

    /**
     * Collected twice with no signature between, a signer hands back the same key both times. The
     * first call rolls the key past the one leaf the signer keeps for itself and returns the rest;
     * a second roll has only that one leaf left to divide, so it took it - marking the key it
     * returned as having nothing remaining while the usages handed over the first time survived
     * only in that first return value. Two collections is not an exotic sequence: a store that
     * failed and is retried, or one written in a finally beside the explicit one, both reach it,
     * and a caller that treats the latest collection as the state to persist then writes an empty
     * key over a live one. Nothing distinguishes what came back from a genuinely spent key.
     * <p>
     * Asserted as object identity rather than as a usage count, because the count alone is what a
     * fresh shard of the last leaf would also satisfy. The signer must still hold its own leaf
     * after both calls, and must still be able to spend it.
     * </p>
     */
    public void testCollectingTwiceWithNoSignatureBetweenHandsBackTheSameKey()
    {
        AsymmetricCipherKeyPair kp = xmssKeyPair(new XMSSParameters(HEIGHT, new SHA256Digest()));
        XMSSPrivateKeyParameters privKey = (XMSSPrivateKeyParameters)kp.getPrivate();
        XMSSSigner signer = new XMSSSigner();

        signer.init(true, privKey);

        assertSame(privKey, signer.getUpdatedPrivateKey());
        assertSame(privKey, signer.getUpdatedPrivateKey());
        assertSame(privKey, signer.getUpdatedPrivateKey());
        assertEquals("the collected key keeps every usage the signer is not holding",
            (1 << HEIGHT) - 1, privKey.getUsagesRemaining());
        assertEquals(1, signer.getUsagesRemaining());

        signer.update(new byte[]{ 1, 2, 3 }, 0, 3);
        assertNotNull("the leaf the signer kept is still there to spend", signer.generateSignature());

        AsymmetricCipherKeyPair mtKp = xmssMTKeyPair(new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest()));
        XMSSMTPrivateKeyParameters mtPrivKey = (XMSSMTPrivateKeyParameters)mtKp.getPrivate();
        XMSSMTSigner mtSigner = new XMSSMTSigner();

        mtSigner.init(true, mtPrivKey);

        assertSame(mtPrivKey, mtSigner.getUpdatedPrivateKey());
        assertSame(mtPrivKey, mtSigner.getUpdatedPrivateKey());
        assertSame(mtPrivKey, mtSigner.getUpdatedPrivateKey());
        assertEquals("the collected key keeps every usage the signer is not holding",
            (1 << HEIGHT) - 1, mtPrivKey.getUsagesRemaining());
        assertEquals(1, mtSigner.getUsagesRemaining());

        mtSigner.update(new byte[]{ 1, 2, 3 }, 0, 3);
        assertNotNull("the leaf the signer kept is still there to spend", mtSigner.generateSignature());
    }

    /**
     * Collecting and then signing leaves nothing further to collect. The collection handed the
     * caller every usage but the one the signer kept, the signature spent that one, and the spent
     * shard adds nothing to what the caller was already given - so the collection after the
     * signature reports an absent key rather than handing the shard over.
     * <p>
     * Handing it over is the shape that loses state: a caller collecting in a finally beside an
     * explicit collection - or retrying a failed write - would store a key reporting nothing
     * remaining over the one carrying the rest of the tree. Refusing is also what the JCE layer
     * did before the shard existed, {@code XMSSSignatureSpi.getUpdatedPrivateKey} turning the
     * absent key back into "signature object not in a signing state".
     * </p><p>
     * The signature that preceded no collection is the other half of this and is unchanged: see
     * {@link #testKeyCollectedOnlyOnceAfterSigning()}, where the advanced key is what comes back.
     * </p>
     */
    public void testCollectionAfterACollectionAndASignatureIsRefused()
    {
        AsymmetricCipherKeyPair kp = xmssKeyPair(new XMSSParameters(HEIGHT, new SHA256Digest()));
        XMSSPrivateKeyParameters privKey = (XMSSPrivateKeyParameters)kp.getPrivate();
        XMSSSigner signer = new XMSSSigner();

        signer.init(true, privKey);

        assertSame(privKey, signer.getUpdatedPrivateKey());
        assertEquals("the collection handed back everything but the usage the signer kept",
            (1 << HEIGHT) - 1, privKey.getUsagesRemaining());

        signer.update(new byte[]{ 1, 2, 3 }, 0, 3);
        signer.generateSignature();

        assertNull("the spent shard was handed over rather than refused", signer.getUpdatedPrivateKey());
        assertNull(signer.getUpdatedPrivateKey());
        assertEquals("the collected key is untouched by the signature the shard made",
            (1 << HEIGHT) - 1, privKey.getUsagesRemaining());

        AsymmetricCipherKeyPair mtKp = xmssMTKeyPair(new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest()));
        XMSSMTPrivateKeyParameters mtPrivKey = (XMSSMTPrivateKeyParameters)mtKp.getPrivate();
        XMSSMTSigner mtSigner = new XMSSMTSigner();

        mtSigner.init(true, mtPrivKey);

        assertSame(mtPrivKey, mtSigner.getUpdatedPrivateKey());
        assertEquals("the collection handed back everything but the usage the signer kept",
            (1 << HEIGHT) - 1, mtPrivKey.getUsagesRemaining());

        mtSigner.update(new byte[]{ 1, 2, 3 }, 0, 3);
        mtSigner.generateSignature();

        assertNull("the spent shard was handed over rather than refused", mtSigner.getUpdatedPrivateKey());
        assertNull(mtSigner.getUpdatedPrivateKey());
        assertEquals("the collected key is untouched by the signature the shard made",
            (1 << HEIGHT) - 1, mtPrivKey.getUsagesRemaining());
    }

    /**
     * A signer given a key with nothing left to spend still has state its caller has to store, and
     * asking for it used to report the shard API's own "usageCount exceeds usages remaining" to a
     * caller that never asked for a shard. There is no next usage to leave behind, so the spent key
     * itself is what comes back - twice over, since nothing was consumed handing it over.
     */
    public void testSpentKeyHandedBackRatherThanShardedAgain()
    {
        AsymmetricCipherKeyPair kp = xmssKeyPair(new XMSSParameters(HEIGHT, new SHA256Digest()));
        XMSSPrivateKeyParameters privKey = (XMSSPrivateKeyParameters)kp.getPrivate();

        privKey.extractKeyShard(1 << HEIGHT);          // takes every usage the key had

        assertEquals(0, privKey.getUsagesRemaining());

        XMSSSigner signer = new XMSSSigner();

        signer.init(true, privKey);

        assertSame(privKey, signer.getUpdatedPrivateKey());
        assertSame(privKey, signer.getUpdatedPrivateKey());
        assertEquals(0, privKey.getUsagesRemaining());

        AsymmetricCipherKeyPair mtKp = xmssMTKeyPair(new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest()));
        XMSSMTPrivateKeyParameters mtPrivKey = (XMSSMTPrivateKeyParameters)mtKp.getPrivate();

        mtPrivKey.extractKeyShard(1 << HEIGHT);

        assertEquals(0, mtPrivKey.getUsagesRemaining());

        XMSSMTSigner mtSigner = new XMSSMTSigner();

        mtSigner.init(true, mtPrivKey);

        assertSame(mtPrivKey, mtSigner.getUpdatedPrivateKey());
        assertSame(mtPrivKey, mtSigner.getUpdatedPrivateKey());
        assertEquals(0, mtPrivKey.getUsagesRemaining());
    }

    /**
     * An argument that was never supplied is the caller's mistake, not a signature that failed to
     * verify - bytes that will not decode are reported as false, but there are no bytes here. The
     * XMSS signer used to answer a null signature with false; XMSS^MT has always named it. The
     * message is streamed in through update() and so cannot be absent, only empty.
     * <p>
     * The check sits on XMSSEngine rather than on the two signers, so the engine is asserted here
     * as well: it is the package's one public class, and a caller reaching it directly used to get
     * neither of the two answers a verify is allowed to give.
     * </p>
     */
    public void testVerifyNamesAnAbsentArgument()
    {
        AsymmetricCipherKeyPair kp = xmssKeyPair(new XMSSParameters(HEIGHT, new SHA256Digest()));
        XMSSSigner signer = new XMSSSigner();

        signer.init(true, kp.getPrivate());

        byte[] message = new byte[]{ 1, 2, 3 };

        signer.update(message, 0, message.length);

        byte[] signature = signer.generateSignature();
        XMSSSigner verifier = new XMSSSigner();

        verifier.init(false, kp.getPublic());
        verifier.update(message, 0, message.length);

        assertTrue(verifier.verifySignature(signature));
        checkAbsentSignature(verifier, message);

        AsymmetricCipherKeyPair mtKp = xmssMTKeyPair(new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest()));
        XMSSMTSigner mtSigner = new XMSSMTSigner();

        mtSigner.init(true, mtKp.getPrivate());

        mtSigner.update(message, 0, message.length);

        byte[] mtSignature = mtSigner.generateSignature();
        XMSSMTSigner mtVerifier = new XMSSMTSigner();

        mtVerifier.init(false, mtKp.getPublic());
        mtVerifier.update(message, 0, message.length);

        assertTrue(mtVerifier.verifySignature(mtSignature));
        checkAbsentSignature(mtVerifier, message);

        // a signature that is present but will not decode is still an answer, not an error
        verifier.update(message, 0, message.length);
        assertFalse(verifier.verifySignature(new byte[0]));

        mtVerifier.update(message, 0, message.length);
        assertFalse(mtVerifier.verifySignature(new byte[0]));

        // straight at the engine, which is where the check lives. XMSS reported an absent
        // signature as one that failed to verify, because the decode dereferences the array to check
        // its length and the catch that turns a malformed signature into false cannot tell that
        // NullPointerException from a bad encoding; XMSS^MT did not reach that catch at all, since
        // its builder reads a null as a request to set the fields rather than to decode and hands
        // back a signature carrying no reduced signatures, which surfaced at the layer-0 lookup
        // past that catch as an IndexOutOfBoundsException
        checkAbsentSignature((XMSSPublicKeyParameters)kp.getPublic(), message);
        checkAbsentSignature((XMSSMTPublicKeyParameters)mtKp.getPublic(), message);

        assertFalse(XMSSEngine.verifySignature((XMSSPublicKeyParameters)kp.getPublic(), message, new byte[0]));
        assertFalse(XMSSEngine.verifyMTSignature((XMSSMTPublicKeyParameters)mtKp.getPublic(), message, new byte[0]));
    }

    private void checkAbsentSignature(XMSSPublicKeyParameters publicKey, byte[] message)
    {
        try
        {
            XMSSEngine.verifySignature(publicKey, message, null);
            fail("absent signature accepted");
        }
        catch (NullPointerException e)
        {
            assertEquals("signature == null", e.getMessage());
        }
    }

    private void checkAbsentSignature(XMSSMTPublicKeyParameters publicKey, byte[] message)
    {
        try
        {
            XMSSEngine.verifyMTSignature(publicKey, message, null);
            fail("absent signature accepted");
        }
        catch (NullPointerException e)
        {
            assertEquals("signature == null", e.getMessage());
        }
    }

    private void checkAbsentSignature(XMSSSigner verifier, byte[] message)
    {
        verifier.update(message, 0, message.length);

        try
        {
            verifier.verifySignature(null);
            fail("absent signature accepted");
        }
        catch (NullPointerException e)
        {
            assertEquals("signature == null", e.getMessage());
        }
    }

    private void checkAbsentSignature(XMSSMTSigner verifier, byte[] message)
    {
        verifier.update(message, 0, message.length);

        try
        {
            verifier.verifySignature(null);
            fail("absent signature accepted");
        }
        catch (NullPointerException e)
        {
            assertEquals("signature == null", e.getMessage());
        }
    }

    /**
     * getUsagesRemaining() answers for the key the signer is holding, so the three states that
     * leave it holding none - never initialised, initialised for verification, and key already
     * collected - all report zero signatures left rather than raising on the absent key.
     */
    public void testUsagesRemainingReportedAsZeroWhenNoKeyHeld()
    {
        AsymmetricCipherKeyPair kp = xmssKeyPair(new XMSSParameters(HEIGHT, new SHA256Digest()));

        assertEquals(0, new XMSSSigner().getUsagesRemaining());

        XMSSSigner verifier = new XMSSSigner();

        verifier.init(false, kp.getPublic());
        assertEquals(0, verifier.getUsagesRemaining());

        XMSSSigner signer = new XMSSSigner();

        signer.init(true, kp.getPrivate());

        // the positive control: while the signer holds the key it reports the key's own count,
        // which for a freshly generated key is one signature per leaf of the tree
        assertEquals(1 << HEIGHT, signer.getUsagesRemaining());

        signer.update(new byte[]{ 1, 2, 3 }, 0, 3);
        signer.generateSignature();
        signer.getUpdatedPrivateKey();

        assertEquals(0, signer.getUsagesRemaining());

        AsymmetricCipherKeyPair mtKp = xmssMTKeyPair(new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest()));

        assertEquals(0, new XMSSMTSigner().getUsagesRemaining());

        XMSSMTSigner mtVerifier = new XMSSMTSigner();

        mtVerifier.init(false, mtKp.getPublic());
        assertEquals(0, mtVerifier.getUsagesRemaining());

        XMSSMTSigner mtSigner = new XMSSMTSigner();

        mtSigner.init(true, mtKp.getPrivate());

        assertEquals(1 << HEIGHT, mtSigner.getUsagesRemaining());

        mtSigner.update(new byte[]{ 1, 2, 3 }, 0, 3);
        mtSigner.generateSignature();
        mtSigner.getUpdatedPrivateKey();

        assertEquals(0, mtSigner.getUsagesRemaining());
    }
}
