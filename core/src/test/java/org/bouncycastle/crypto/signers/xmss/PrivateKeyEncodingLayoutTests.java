package org.bouncycastle.crypto.signers.xmss;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
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
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Where each field of a stored private key sits, and which bytes its trailing checksum covers.
 * <p>
 * Everything else about this encoding is tested through a round trip, and a round trip cannot see
 * any of it: encode and decode are the same implementation read in two directions, so a change that
 * moves a field, or that alters what the checksum is taken over, moves both halves together and the
 * key still comes back. Measured - a build that hashes one byte less into the checksum on both
 * sides passed 134 of the 135 XMSS tests there were before this class. What is asserted here is therefore only the part an
 * agreeing pair of directions cannot establish: the offsets as
 * <code>docs/formats/xmss-private-key.md</code> gives them, taken from this file rather than from
 * the codec's own constants, and the checksum recomputed here from the digest the document names.
 */
public class PrivateKeyEncodingLayoutTests
    extends TestCase
{
    private static final int BDS_STATE_MAGIC = 0x42445300;
    private static final int BDS_STATE_MAP_MAGIC = 0x42444d00;
    private static final int STATE_VERSION = 1;
    private static final int CHECKSUM_SIZE = 32;

    /**
     * index(4) || secretKeySeed(n) || secretKeyPRF(n) || publicSeed(n) || root(n) || BDS state.
     */
    public void testXmssKeyEncodingLayout()
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(4, new SHA256Digest());
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        XMSSSigner signer = new XMSSSigner();

        signer.init(true, kp.getPrivate());

        // three indices: the state stored at index 1 holds far fewer nodes than one further in
        for (int index = 0; index != 3; index++)
        {
            signer.update((byte)index);
            signer.generateSignature();

            // the key to store, which is the one after the index just spent
            XMSSPrivateKeyParameters privKey = (XMSSPrivateKeyParameters)signer.getUpdatedPrivateKey();
            int n = params.getTreeDigestSize();
            byte[] encoding = privKey.getEncoded();

            assertEquals(index + 1, Pack.bigEndianToInt(encoding, 0));
            checkFields(encoding, 4, n, privKey.getSecretKeySeed(), privKey.getSecretKeyPRF(),
                privKey.getPublicSeed(), privKey.getRoot());
            checkState(encoding, 4 + 4 * n, BDS_STATE_MAGIC, privKey.getPublicSeed());

            // the asserted bytes are also what the key they decode to encodes back to, so this is
            // the layout of a stored key however it was arrived at, not only of a freshly rolled one
            XMSSPrivateKeyParameters rebuilt = new XMSSPrivateKeyParameters.Builder(params)
                .withPrivateKey(encoding).build();

            assertTrue("re-encoded", Arrays.areEqual(encoding, rebuilt.getEncoded()));

            // getUpdatedPrivateKey() took the key with it, so the signer needs it back to go on
            signer.init(true, privKey);
        }
    }

    /**
     * As above, with the index sized by the total height and the state a map of one BDS per layer.
     */
    public void testXmssMtKeyEncodingLayout()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(4, 2, new SHA256Digest());
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        XMSSMTSigner signer = new XMSSMTSigner();

        signer.init(true, kp.getPrivate());

        for (int index = 0; index != 3; index++)
        {
            signer.update((byte)index);
            signer.generateSignature();

            XMSSMTPrivateKeyParameters privKey = (XMSSMTPrivateKeyParameters)signer.getUpdatedPrivateKey();
            int n = params.getTreeDigestSize();
            int indexSize = (params.getHeight() + 7) / 8;
            byte[] encoding = privKey.getEncoded();

            assertEquals(1, indexSize);
            assertEquals(index + 1, encoding[0] & 0xff);
            checkFields(encoding, indexSize, n, privKey.getSecretKeySeed(), privKey.getSecretKeyPRF(),
                privKey.getPublicSeed(), privKey.getRoot());
            checkState(encoding, indexSize + 4 * n, BDS_STATE_MAP_MAGIC, privKey.getPublicSeed());

            XMSSMTPrivateKeyParameters rebuilt = new XMSSMTPrivateKeyParameters.Builder(params)
                .withPrivateKey(encoding).build();

            assertTrue("re-encoded", Arrays.areEqual(encoding, rebuilt.getEncoded()));

            signer.init(true, privKey);
        }
    }

    private void checkFields(byte[] encoding, int offset, int n, byte[] secretKeySeed, byte[] secretKeyPRF,
        byte[] publicSeed, byte[] root)
    {
        assertTrue("secretKeySeed", Arrays.areEqual(secretKeySeed,
            Arrays.copyOfRange(encoding, offset, offset + n)));
        assertTrue("secretKeyPRF", Arrays.areEqual(secretKeyPRF,
            Arrays.copyOfRange(encoding, offset + n, offset + 2 * n)));
        assertTrue("publicSeed", Arrays.areEqual(publicSeed,
            Arrays.copyOfRange(encoding, offset + 2 * n, offset + 3 * n)));
        assertTrue("root", Arrays.areEqual(root,
            Arrays.copyOfRange(encoding, offset + 3 * n, offset + 4 * n)));
    }

    /**
     * The state's header where the fixed fields end, and the checksum over everything from there to
     * the last 32 bytes - SHA-256 whatever the tree digest is, with the key's public seed in front.
     */
    private void checkState(byte[] encoding, int stateOffset, int magic, byte[] publicSeed)
    {
        int bodyLength = encoding.length - CHECKSUM_SIZE - stateOffset;

        assertTrue("state too short", bodyLength > 8);
        assertEquals("state magic", magic, Pack.bigEndianToInt(encoding, stateOffset));
        assertEquals("state version", STATE_VERSION, Pack.bigEndianToInt(encoding, stateOffset + 4));

        Digest digest = new SHA256Digest();

        digest.update(publicSeed, 0, publicSeed.length);
        digest.update(encoding, stateOffset, bodyLength);

        byte[] expected = new byte[digest.getDigestSize()];

        digest.doFinal(expected, 0);

        assertTrue("state checksum", Arrays.areEqual(expected,
            Arrays.copyOfRange(encoding, encoding.length - CHECKSUM_SIZE, encoding.length)));
    }
}
