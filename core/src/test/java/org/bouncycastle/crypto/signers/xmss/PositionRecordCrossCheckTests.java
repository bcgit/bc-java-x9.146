package org.bouncycastle.crypto.signers.xmss;

import java.security.SecureRandom;

import junit.framework.TestCase;
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
import org.bouncycastle.crypto.signers.XMSSMTSigner;

/**
 * An XMSS^MT private key records where it has got to twice - in its own index field, and in the
 * per-layer BDS traversal states beside it - and the two are advanced by separate statements, so
 * only the author of those statements holds them together. The constructor compares them, which
 * catches a key arriving desynchronised; nothing was comparing them again while the key was held,
 * so a roll that advanced one record and not the other would have gone unnoticed until the key was
 * next read back, and a key that has been rolled back in one record but not the other signs a
 * second message under a one-time key it has already used (RFC 8391 sec. 1.1).
 * <p>
 * These exercise the two ends of that: that a desynchronised pair is now refused where it moves and
 * where it is written out, and - the half that matters more - that a key going about its business
 * across every index it can reach is not.
 * </p>
 */
public class PositionRecordCrossCheckTests
    extends TestCase
{
    private static final int HEIGHT = 6;
    private static final int LAYERS = 3;

    /**
     * The compatibility half. Walk a key across every index it has, encoding at each one, and
     * confirm the encoding still decodes to a key that signs verifiably. A cross-check that is too
     * strict rejects legitimate keys, which is worse than the divergence it is there to find - the
     * boundary at a leaf index of 0, where a layer legitimately still shows the previous subtree's
     * last leaf, is the case that makes that a real risk here.
     */
    public void testEveryIndexOfAKeyStillEncodesAndSigns()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest());
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));

        org.bouncycastle.crypto.AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        XMSSMTPrivateKeyParameters privKey = (XMSSMTPrivateKeyParameters)kp.getPrivate();
        XMSSMTPublicKeyParameters pubKey = (XMSSMTPublicKeyParameters)kp.getPublic();

        long maxIndex = privKey.getBDSState().getMaxIndex();

        for (long index = 0; index <= maxIndex; index++)
        {
            assertEquals("key is not where the walk expects it", index, privKey.getIndex());

            byte[] encoded = privKey.getEncoded();
            XMSSMTPrivateKeyParameters decoded = new XMSSMTPrivateKeyParameters.Builder(params)
                .withPrivateKey(encoded).build();

            assertEquals("decoded key sits at a different index", index, decoded.getIndex());

            byte[] message = new byte[]{(byte)index, (byte)(index >>> 8)};

            XMSSMTSigner signer = new XMSSMTSigner();
            signer.init(true, decoded);
            signer.update(message, 0, message.length);
            byte[] signature = signer.generateSignature();

            XMSSMTSigner verifier = new XMSSMTSigner();
            verifier.init(false, pubKey);
            verifier.update(message, 0, message.length);
            assertTrue("signature at index " + index + " does not verify",
                verifier.verifySignature(signature));

            privKey.rollKey();
        }

        // and the exhausted key past the end, whose state map is empty and so has no layer to
        // disagree with anything
        assertEquals(maxIndex + 1, privKey.getIndex());
        assertEquals(0, privKey.getUsagesRemaining());
    }

    /**
     * A layer zero state left behind where the index has moved on - what a partial write or a
     * storage layer that restored half a key produces - must not be written out as a key, because
     * decoding it back is refused and because the position it describes is one the key has already
     * signed at.
     */
    public void testEncodingRefusesAStateThatLagsTheIndex()
        throws Exception
    {
        XMSSMTPrivateKeyParameters privKey = desynchronised();

        try
        {
            privKey.getEncoded();
            fail("a key whose two records of its position disagree was encoded");
        }
        catch (IllegalStateException e)
        {
            assertTrue("wrong message: " + e.getMessage(),
                e.getMessage().startsWith("BDS state has wrong index for layer 0"));
        }
    }

    /**
     * The same pair, refused where it next moves rather than where it is written: a roll carries a
     * lagging state forward rather than repairing it, so the key would go on signing at positions
     * its state says it has already been to.
     */
    public void testRollRefusesAStateThatLagsTheIndex()
        throws Exception
    {
        XMSSMTPrivateKeyParameters privKey = desynchronised();

        try
        {
            privKey.rollKey();
            fail("a key whose two records of its position disagree was rolled");
        }
        catch (IllegalStateException e)
        {
            assertTrue("wrong message: " + e.getMessage(),
                e.getMessage().startsWith("BDS state has wrong index for layer 0"));
        }
    }

    /**
     * The same pair again, refused where it would be spent. Encoding and rolling are where a
     * desynchronised key is written down or moved on; signing is where it consumes a one-time key,
     * and that is the step RFC 8391 sec. 1.1 is about.
     * <p>
     * Refusing it here rather than leaving the roll to catch it is not just an earlier message. The
     * roll runs from the finally the signature is built inside, so the one-time key is spent and
     * the key advanced before the exception the caller sees is raised: what that caller then knows
     * is that something went wrong, not that its key has moved. The assertion on the index is
     * therefore the one that matters - measured against the engine without the check, the key
     * comes back one position further on than it went in.
     * </p>
     */
    public void testSigningRefusesAStateThatLagsTheIndex()
        throws Exception
    {
        XMSSMTPrivateKeyParameters privKey = desynchronised();

        long index = privKey.getIndex();

        XMSSMTSigner signer = new XMSSMTSigner();

        signer.init(true, privKey);
        signer.update(new byte[]{0x01}, 0, 1);

        try
        {
            signer.generateSignature();
            fail("a key whose two records of its position disagree signed");
        }
        catch (IllegalStateException e)
        {
            assertTrue("wrong message: " + e.getMessage(),
                e.getMessage().startsWith("BDS state has wrong index for layer 0"));
        }

        assertEquals("a refused signature must not move the key", index, privKey.getIndex());
    }

    /**
     * The index is not the only thing a stateful key records twice. It also carries the tree root in
     * two places - its own root field, and the root node inside the BDS traversal state - and
     * validateRoot() is what compares them (github #2414). Nothing exercised it: it is reached from
     * four call sites in the two key classes, and no test anywhere named the message it raises, so
     * the whole of this half of the cross-check could have been deleted with every suite still green.
     * <p>
     * A root that disagrees is a key built around a traversal state describing a different tree.
     * Signatures made from it carry authentication paths to that other root, so they do not verify
     * under the public key the caller believes it holds - a signing key that quietly stopped working,
     * with each attempt spending a one-time key it can never get back.
     * </p>
     */
    public void testARootThatDisagreesWithTheStateIsRefused()
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(HEIGHT, new SHA256Digest());
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        XMSSPrivateKeyParameters privKey =
            (XMSSPrivateKeyParameters)kpg.generateKeyPair().getPrivate();

        // through the builder, where a restored state meets a root supplied beside it
        byte[] wrongRoot = org.bouncycastle.util.Arrays.clone(privKey.getRoot());

        wrongRoot[0] ^= 0x01;

        try
        {
            new XMSSPrivateKeyParameters.Builder(params)
                .withSecretKeySeed(privKey.getSecretKeySeed()).withSecretKeyPRF(privKey.getSecretKeyPRF())
                .withPublicSeed(privKey.getPublicSeed()).withRoot(wrongRoot)
                .withBDSState(privKey.getBDSState()).build();
            fail("a key whose root disagrees with its traversal state was built");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("BDS state root does not match the private key root", e.getMessage());
        }

        // and through the encoded-key path, where the two arrive in one byte string: every byte of
        // the root field, so the comparison cannot be of a prefix
        byte[] encoded = privKey.getEncoded();
        int n = params.getTreeDigestSize();
        int rootOffset = 4 + 3 * n;

        for (int b = 0; b != n; b++)
        {
            byte[] corrupt = org.bouncycastle.util.Arrays.clone(encoded);

            corrupt[rootOffset + b] ^= 0x01;

            try
            {
                new XMSSPrivateKeyParameters.Builder(params).withPrivateKey(corrupt).build();
                fail("corrupt root byte " + b + " accepted");
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("byte " + b, "BDS state root does not match the private key root",
                    e.getMessage());
            }
        }

        // the harness: the encoding these were made from is accepted and carries the same root
        XMSSPrivateKeyParameters decoded =
            new XMSSPrivateKeyParameters.Builder(params).withPrivateKey(encoded).build();

        assertTrue(org.bouncycastle.util.Arrays.areEqual(privKey.getRoot(), decoded.getRoot()));
    }

    /**
     * The XMSS^MT half, which reaches the same comparison through the state map. Only the top layer
     * is compared - the top tree's root is the public root, and the layers below describe subtrees
     * whose roots are not it - so this is also where a check applied to the wrong layer would show.
     */
    public void testATopLayerRootThatDisagreesIsRefused()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest());
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));

        XMSSMTPrivateKeyParameters privKey =
            (XMSSMTPrivateKeyParameters)kpg.generateKeyPair().getPrivate();

        assertNotNull("no top layer state to compare against",
            privKey.getBDSState().get(LAYERS - 1));

        byte[] encoded = privKey.getEncoded();
        int n = params.getTreeDigestSize();
        int rootOffset = (params.getHeight() + 7) / 8 + 3 * n;

        for (int b = 0; b != n; b++)
        {
            byte[] corrupt = org.bouncycastle.util.Arrays.clone(encoded);

            corrupt[rootOffset + b] ^= 0x01;

            try
            {
                new XMSSMTPrivateKeyParameters.Builder(params).withPrivateKey(corrupt).build();
                fail("corrupt root byte " + b + " accepted");
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("byte " + b, "BDS state root does not match the private key root",
                    e.getMessage());
            }
        }

        XMSSMTPrivateKeyParameters decoded =
            new XMSSMTPrivateKeyParameters.Builder(params).withPrivateKey(encoded).build();

        assertTrue(org.bouncycastle.util.Arrays.areEqual(privKey.getRoot(), decoded.getRoot()));
    }

    /**
     * The compatibility half, and the reason the check cannot simply require a root to be there. A
     * state carries no root until it has one - a freshly built key's state is computed from the
     * seeds rather than restored, and the layers below the top of an XMSS^MT key describe subtrees
     * whose root is not the public one - so validateRoot() compares only when both sides have a
     * value. A version that refused the absent case would refuse key generation itself.
     */
    public void testAnAbsentRootOnEitherSideIsNotAMismatch()
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(HEIGHT, new SHA256Digest());
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        XMSSPrivateKeyParameters privKey =
            (XMSSPrivateKeyParameters)kpg.generateKeyPair().getPrivate();
        BDS state = privKey.getBDSState();

        // a state with a real root, asked about a key that declares none
        state.validateRoot(null);

        // the key that declares none, which is what a key built without a root carries: zeros
        // rather than a value, and comparing them would refuse it
        assertNotNull(new XMSSPrivateKeyParameters.Builder(params)
            .withSecretKeySeed(privKey.getSecretKeySeed()).withSecretKeyPRF(privKey.getSecretKeyPRF())
            .withPublicSeed(privKey.getPublicSeed())
            .withBDSState(state).build());

        // the other side absent: an XMSS^MT layer is built lazily, so a map whose top layer is not
        // there yet has nothing to compare and must not be refused for it
        XMSSMTParameters mtParams = new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest());

        new BDSStateMap(1L << HEIGHT).validateRoot(mtParams, privKey.getRoot());
    }

    /**
     * A key sitting at an index its own layer zero state does not agree with, built the way the
     * failure actually arises: the state map handed out by getBDSState() is the live one, so a
     * layer zero state kept from before a roll can be put back into it afterwards, which is what
     * a half-restored key looks like from the inside.
     */
    private XMSSMTPrivateKeyParameters desynchronised()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest());
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));

        XMSSMTPrivateKeyParameters privKey =
            (XMSSMTPrivateKeyParameters)kpg.generateKeyPair().getPrivate();

        // sign twice so layer zero exists and is off the subtree boundary the cross-check allows
        XMSSMTSigner signer = new XMSSMTSigner();
        signer.init(true, privKey);
        for (int i = 0; i != 2; i++)
        {
            signer.update(new byte[]{(byte)i}, 0, 1);
            signer.generateSignature();
        }

        BDS stale = privKey.getBDSState().get(0);
        assertNotNull("no layer zero state to keep", stale);

        privKey.rollKey();
        assertTrue("layer zero already agrees with the index after the roll",
            stale.getIndex() != XMSSUtil.getLeafIndex(privKey.getIndex(), HEIGHT / LAYERS));

        privKey.getBDSState().put(0, stale);

        return privKey;
    }
}
