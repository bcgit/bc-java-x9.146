package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.FixedSecureRandom;

/**
 * The XMSS / XMSS^MT implementation under org.bouncycastle.crypto is a copy of the deprecated
 * org.bouncycastle.pqc.crypto.xmss one, so the two must agree byte for byte on every encoding and
 * each must verify what the other signed. This test pins that down over the parameter-set matrix,
 * and is the guard against the copy drifting from the original while both ship.
 */
public class XMSSPromotionCompatibilityTest
    extends TestCase
{
    private static final byte[] MESSAGE = Strings.toByteArray("the quick brown fox jumped over the lazy dog");

    /**
     * The same seed drives both implementations, so a matching pair of keys must come out with
     * identical X.509 / PKCS#8 encodings, and each side must verify the other's signature. The
     * tree height is kept small: it does not change any encoding rule, only how long the tree
     * takes to build.
     */
    public void testXMSSKeysAndSignaturesMatchAcrossImplementations()
        throws Exception
    {
        for (int i = 0; i != 4; i++)
        {
            checkXMSS("h4/" + i, newXmssParams(4, i), oldXmssParams(4, i), seedFor(i));
        }

        // The matrix stops at the four RFC 8391 tree digests with their natural n. A tree height
        // outside the standard sets has no parameter-set OID, so its key is written in the legacy
        // PQCObjectIdentifiers.xmss form, whose XMSSKeyParams carries the height and the tree
        // digest OID but not n - neither implementation can express an SP 800-208 n that way, and
        // both have always failed on it. Those sets are all standard heights and are covered by
        // testStandardParameterSetEncodingMatches below, which exercises the RFC 9802 branch.
    }

    /**
     * A standard RFC 8391 parameter set, which is encoded in the RFC 9802 form (id-alg-xmss-hashsig
     * with the 4-octet parameter-set OID ahead of the raw key) rather than the legacy
     * XMSSKeyParams one - a different branch of both key factories.
     * <p>
     * It is also the only branch that carries the raw private key layout, the legacy one building
     * its ASN.1 structure out of the key's own fields instead, so this is where that layout is
     * compared byte for byte against the deprecated copy - and it therefore has to reach both
     * families. The XMSS^MT cases elsewhere in this class are non-standard heights and take the
     * legacy branch, so before XMSSMT-SHA2_20/2_256 was added here nothing in the tree compared an
     * XMSS^MT raw encoding at all: a build whose XMSS^MT index field was one byte wider than it
     * should be passed every case of this class. That set was left out as too slow, which its key
     * is not - a height 10 tree per side, the same shape as the XMSS cases above it - so what it
     * skips is the signing and cross-verification half of checkXMSSMT, whose first signature at
     * this height costs as much again as the key does and which the h=4/d=2 sets of
     * {@link #testXMSSMTKeysAndSignaturesMatchAcrossImplementations()} already cover.
     * </p>
     */
    public void testStandardParameterSetEncodingMatches()
        throws Exception
    {
        checkXMSS("XMSS-SHA2_10_256",
            new org.bouncycastle.crypto.params.XMSSParameters(10, new SHA256Digest()),
            new org.bouncycastle.pqc.crypto.xmss.XMSSParameters(10, new SHA256Digest()),
            seedFor(10));

        // XMSS_SHAKE256_10_192, an SP 800-208 set: SHAKE256 truncated to n = 24, named by
        // id-shake256-len rather than by one of the four RFC 8391 tree digests
        checkXMSS("XMSS-SHAKE256_10_192",
            new org.bouncycastle.crypto.params.XMSSParameters(10, NISTObjectIdentifiers.id_shake256_len, 24),
            new org.bouncycastle.pqc.crypto.xmss.XMSSParameters(10, NISTObjectIdentifiers.id_shake256_len, 24),
            seedFor(11));

        // XMSS_SHA2_10_192, the other SP 800-208 way of getting to n = 24, and the only set in
        // this class that reaches the truncating branch of KeyedHashFunctions.coreDigest - a
        // digest that is not an Xof and whose output is longer than n, so every F, H, H_msg and
        // PRF result is the first 24 bytes of a 32-byte digest. The other five sets here run at
        // their digest's natural n, and SHAKE256/192 is an Xof, which is squeezed to length
        // instead. Nothing pinned which 24 bytes those are: making that branch copy from offset 1
        // passes all six cases of this class, the 83 of crypto.signers.xmss.AllTests and the 54
        // of the provider's XMSSTest and XMSSMTTest, because a round trip agrees with itself
        // whichever bytes it keeps. This case is what disagrees.
        checkXMSS("XMSS-SHA2_10_192",
            new org.bouncycastle.crypto.params.XMSSParameters(10, NISTObjectIdentifiers.id_sha256, 24),
            new org.bouncycastle.pqc.crypto.xmss.XMSSParameters(10, NISTObjectIdentifiers.id_sha256, 24),
            seedFor(12));

        // XMSSMT_SHA2_20/2_256, the smallest standard XMSS^MT set, and the only place an XMSS^MT
        // raw private key encoding is compared against the deprecated copy at all
        compareEncodings("XMSSMT-SHA2_20/2_256",
            newXmssMtKey(new org.bouncycastle.crypto.params.XMSSMTParameters(20, 2, new SHA256Digest()),
                seedFor(13)),
            oldXmssMtKey(new org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters(20, 2, new SHA256Digest()),
                seedFor(13)));
    }

    public void testXMSSMTKeysAndSignaturesMatchAcrossImplementations()
        throws Exception
    {
        for (int i = 0; i != 4; i++)
        {
            checkXMSSMT("h4d2/" + i, newXmssMtParams(4, 2, i), oldXmssMtParams(4, 2, i), seedFor(20 + i));
        }
    }

    /**
     * Every index a key can reach, not only its first.
     * <p>
     * The two implementations agreeing at index 0 says nothing about the idx_sig field of the
     * H_msg key - r || root || toByte(idx_sig, n) of RFC 8391 sec. 4.1.9 and 4.2.7 - because at
     * index 0 that field is all zeros whatever is done with it, and every other case above signs
     * exactly once. Where those bytes sit, and how many of them there are, shows only once the
     * index is non-zero, and a sign-then-verify round trip cannot show it either: both directions
     * of one implementation build the key the same way, so they agree with each other while
     * disagreeing with the other implementation. Comparing the two at every index is what pins it,
     * and it walks the BDS traversal state through every shape it takes on the way.
     */
    public void testSignaturesMatchAtEveryIndexOfAKey()
        throws Exception
    {
        org.bouncycastle.crypto.signers.XMSSSigner newSigner = new org.bouncycastle.crypto.signers.XMSSSigner();
        newSigner.init(true, newXmssKey(newXmssParams(4, 0), seedFor(30)).getPrivate());

        org.bouncycastle.pqc.crypto.xmss.XMSSSigner oldSigner = new org.bouncycastle.pqc.crypto.xmss.XMSSSigner();
        oldSigner.init(true, oldXmssKey(oldXmssParams(4, 0), seedFor(30)).getPrivate());

        for (int i = 0; i != 1 << 4; i++)
        {
            newSigner.update(MESSAGE, 0, MESSAGE.length);
            assertTrue("XMSS: signatures differ at index " + i,
                Arrays.areEqual(newSigner.generateSignature(), oldSigner.generateSignature(MESSAGE)));
        }

        org.bouncycastle.crypto.signers.XMSSMTSigner newMtSigner = new org.bouncycastle.crypto.signers.XMSSMTSigner();
        newMtSigner.init(true, newXmssMtKey(newXmssMtParams(4, 2, 0), seedFor(31)).getPrivate());

        org.bouncycastle.pqc.crypto.xmss.XMSSMTSigner oldMtSigner = new org.bouncycastle.pqc.crypto.xmss.XMSSMTSigner();
        oldMtSigner.init(true, oldXmssMtKey(oldXmssMtParams(4, 2, 0), seedFor(31)).getPrivate());

        for (int i = 0; i != 1 << 4; i++)
        {
            newMtSigner.update(MESSAGE, 0, MESSAGE.length);
            assertTrue("XMSS^MT: signatures differ at index " + i,
                Arrays.areEqual(newMtSigner.generateSignature(), oldMtSigner.generateSignature(MESSAGE)));
        }
    }

    /**
     * The promoted signers implement org.bouncycastle.crypto.Signer rather than the pqc
     * StateAwareMessageSigner, so a message streamed in through update() must sign and verify, and
     * the buffer must be consumed by each operation rather than carried into the next. That the
     * streamed signature is byte-identical to the deprecated signer's one-shot output is asserted
     * by checkXMSS / checkXMSSMT below.
     */
    public void testStreamingRoundTrip()
        throws Exception
    {
        org.bouncycastle.crypto.params.XMSSParameters params =
            new org.bouncycastle.crypto.params.XMSSParameters(4, new SHA256Digest());

        org.bouncycastle.crypto.generators.XMSSKeyPairGenerator gen =
            new org.bouncycastle.crypto.generators.XMSSKeyPairGenerator();
        gen.init(new org.bouncycastle.crypto.params.XMSSKeyGenerationParameters(params, fixedRandom(seedFor(7))));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        org.bouncycastle.crypto.signers.XMSSSigner signer = new org.bouncycastle.crypto.signers.XMSSSigner();
        signer.init(true, kp.getPrivate());
        signer.update(MESSAGE, 0, MESSAGE.length);
        byte[] streamed = signer.generateSignature();

        org.bouncycastle.crypto.signers.XMSSSigner verifier = new org.bouncycastle.crypto.signers.XMSSSigner();
        verifier.init(false, kp.getPublic());
        verifier.update(MESSAGE, 0, MESSAGE.length);
        assertTrue("streamed signature did not verify through the streaming path",
            verifier.verifySignature(streamed));

        // verifySignature() consumed the buffer, so feeding the same message again verifies the
        // message alone and not the message twice
        verifier.init(false, kp.getPublic());
        verifier.update(MESSAGE, 0, MESSAGE.length);
        assertTrue("second streamed verification failed", verifier.verifySignature(streamed));
    }

    /**
     * The JCA layer wraps the private key in a ParametersWithRandom whenever a SecureRandom is
     * supplied - XMSSSignatureSpi.engineInitSign(PrivateKey, SecureRandom) does - so all four
     * signers have to accept the wrapper. XMSS derives its randomizer from the key
     * (r = PRF(SK_PRF, toByte(idx, 32)), RFC 8391 sec. 4.1.9 / 4.2.7), so the supplied random has
     * nothing to drive: the signature must come out byte-identical to the one signed without the
     * wrapper, which is what says the random was discarded rather than mixed in.
     */
    public void testParametersWithRandomAcceptedForSigning()
        throws Exception
    {
        // a random that would be impossible to miss had any of it reached the signature
        SecureRandom random = new FixedSecureRandom(
            new FixedSecureRandom.Source[]{ new FixedSecureRandom.Data(new byte[256]) });

        org.bouncycastle.crypto.params.XMSSParameters newParams = newXmssParams(4, 0);
        org.bouncycastle.crypto.params.XMSSMTParameters newMtParams = newXmssMtParams(4, 2, 0);
        org.bouncycastle.pqc.crypto.xmss.XMSSParameters oldParams = oldXmssParams(4, 0);
        org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters oldMtParams = oldXmssMtParams(4, 2, 0);

        byte[] seed = seedFor(31);

        org.bouncycastle.crypto.signers.XMSSSigner newSigner = new org.bouncycastle.crypto.signers.XMSSSigner();
        newSigner.init(true, new ParametersWithRandom(newXmssKey(newParams, seed).getPrivate(), random));
        newSigner.update(MESSAGE, 0, MESSAGE.length);
        byte[] wrapped = newSigner.generateSignature();

        org.bouncycastle.crypto.signers.XMSSSigner plainSigner = new org.bouncycastle.crypto.signers.XMSSSigner();
        plainSigner.init(true, newXmssKey(newParams, seed).getPrivate());
        plainSigner.update(MESSAGE, 0, MESSAGE.length);
        assertTrue("XMSS: ParametersWithRandom changed the signature",
            Arrays.areEqual(wrapped, plainSigner.generateSignature()));

        org.bouncycastle.pqc.crypto.xmss.XMSSSigner oldSigner = new org.bouncycastle.pqc.crypto.xmss.XMSSSigner();
        oldSigner.init(true, new ParametersWithRandom(oldXmssKey(oldParams, seed).getPrivate(), random));
        assertTrue("XMSS: deprecated signer disagreed under ParametersWithRandom",
            Arrays.areEqual(wrapped, oldSigner.generateSignature(MESSAGE)));

        byte[] mtSeed = seedFor(32);

        org.bouncycastle.crypto.signers.XMSSMTSigner newMtSigner = new org.bouncycastle.crypto.signers.XMSSMTSigner();
        newMtSigner.init(true, new ParametersWithRandom(newXmssMtKey(newMtParams, mtSeed).getPrivate(), random));
        newMtSigner.update(MESSAGE, 0, MESSAGE.length);
        byte[] mtWrapped = newMtSigner.generateSignature();

        org.bouncycastle.crypto.signers.XMSSMTSigner plainMtSigner = new org.bouncycastle.crypto.signers.XMSSMTSigner();
        plainMtSigner.init(true, newXmssMtKey(newMtParams, mtSeed).getPrivate());
        plainMtSigner.update(MESSAGE, 0, MESSAGE.length);
        assertTrue("XMSS^MT: ParametersWithRandom changed the signature",
            Arrays.areEqual(mtWrapped, plainMtSigner.generateSignature()));

        org.bouncycastle.pqc.crypto.xmss.XMSSMTSigner oldMtSigner = new org.bouncycastle.pqc.crypto.xmss.XMSSMTSigner();
        oldMtSigner.init(true, new ParametersWithRandom(oldXmssMtKey(oldMtParams, mtSeed).getPrivate(), random));
        assertTrue("XMSS^MT: deprecated signer disagreed under ParametersWithRandom",
            Arrays.areEqual(mtWrapped, oldMtSigner.generateSignature(MESSAGE)));
    }

    private static AsymmetricCipherKeyPair newXmssKey(org.bouncycastle.crypto.params.XMSSParameters params, byte[] seed)
    {
        org.bouncycastle.crypto.generators.XMSSKeyPairGenerator gen =
            new org.bouncycastle.crypto.generators.XMSSKeyPairGenerator();
        gen.init(new org.bouncycastle.crypto.params.XMSSKeyGenerationParameters(params, fixedRandom(seed)));
        return gen.generateKeyPair();
    }

    private static AsymmetricCipherKeyPair oldXmssKey(org.bouncycastle.pqc.crypto.xmss.XMSSParameters params, byte[] seed)
    {
        org.bouncycastle.pqc.crypto.xmss.XMSSKeyPairGenerator gen =
            new org.bouncycastle.pqc.crypto.xmss.XMSSKeyPairGenerator();
        gen.init(new org.bouncycastle.pqc.crypto.xmss.XMSSKeyGenerationParameters(params, fixedRandom(seed)));
        return gen.generateKeyPair();
    }

    private static AsymmetricCipherKeyPair newXmssMtKey(org.bouncycastle.crypto.params.XMSSMTParameters params, byte[] seed)
    {
        org.bouncycastle.crypto.generators.XMSSMTKeyPairGenerator gen =
            new org.bouncycastle.crypto.generators.XMSSMTKeyPairGenerator();
        gen.init(new org.bouncycastle.crypto.params.XMSSMTKeyGenerationParameters(params, fixedRandom(seed)));
        return gen.generateKeyPair();
    }

    private static AsymmetricCipherKeyPair oldXmssMtKey(org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters params, byte[] seed)
    {
        org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyPairGenerator gen =
            new org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyPairGenerator();
        gen.init(new org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyGenerationParameters(params, fixedRandom(seed)));
        return gen.generateKeyPair();
    }

    private void checkXMSS(String label,
                           org.bouncycastle.crypto.params.XMSSParameters newParams,
                           org.bouncycastle.pqc.crypto.xmss.XMSSParameters oldParams,
                           byte[] seed)
        throws Exception
    {
        org.bouncycastle.crypto.generators.XMSSKeyPairGenerator newGen =
            new org.bouncycastle.crypto.generators.XMSSKeyPairGenerator();
        newGen.init(new org.bouncycastle.crypto.params.XMSSKeyGenerationParameters(newParams, fixedRandom(seed)));
        AsymmetricCipherKeyPair newKp = newGen.generateKeyPair();

        org.bouncycastle.pqc.crypto.xmss.XMSSKeyPairGenerator oldGen =
            new org.bouncycastle.pqc.crypto.xmss.XMSSKeyPairGenerator();
        oldGen.init(new org.bouncycastle.pqc.crypto.xmss.XMSSKeyGenerationParameters(oldParams, fixedRandom(seed)));
        AsymmetricCipherKeyPair oldKp = oldGen.generateKeyPair();

        compareEncodings(label, newKp, oldKp);

        org.bouncycastle.crypto.signers.XMSSSigner newSigner = new org.bouncycastle.crypto.signers.XMSSSigner();
        newSigner.init(true, newKp.getPrivate());
        newSigner.update(MESSAGE, 0, MESSAGE.length);
        byte[] newSig = newSigner.generateSignature();

        org.bouncycastle.pqc.crypto.xmss.XMSSSigner oldSigner = new org.bouncycastle.pqc.crypto.xmss.XMSSSigner();
        oldSigner.init(true, oldKp.getPrivate());
        byte[] oldSig = oldSigner.generateSignature(MESSAGE);

        assertTrue(label + ": signatures differ", Arrays.areEqual(newSig, oldSig));

        org.bouncycastle.crypto.signers.XMSSSigner newVerifier = new org.bouncycastle.crypto.signers.XMSSSigner();
        newVerifier.init(false, newKp.getPublic());
        newVerifier.update(MESSAGE, 0, MESSAGE.length);
        assertTrue(label + ": promoted verifier rejected the deprecated signature",
            newVerifier.verifySignature(oldSig));

        org.bouncycastle.pqc.crypto.xmss.XMSSSigner oldVerifier = new org.bouncycastle.pqc.crypto.xmss.XMSSSigner();
        oldVerifier.init(false, oldKp.getPublic());
        assertTrue(label + ": deprecated verifier rejected the promoted signature",
            oldVerifier.verifySignature(MESSAGE, newSig));
    }

    private void checkXMSSMT(String label,
                             org.bouncycastle.crypto.params.XMSSMTParameters newParams,
                             org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters oldParams,
                             byte[] seed)
        throws Exception
    {
        org.bouncycastle.crypto.generators.XMSSMTKeyPairGenerator newGen =
            new org.bouncycastle.crypto.generators.XMSSMTKeyPairGenerator();
        newGen.init(new org.bouncycastle.crypto.params.XMSSMTKeyGenerationParameters(newParams, fixedRandom(seed)));
        AsymmetricCipherKeyPair newKp = newGen.generateKeyPair();

        org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyPairGenerator oldGen =
            new org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyPairGenerator();
        oldGen.init(new org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyGenerationParameters(oldParams, fixedRandom(seed)));
        AsymmetricCipherKeyPair oldKp = oldGen.generateKeyPair();

        compareEncodings(label, newKp, oldKp);

        org.bouncycastle.crypto.signers.XMSSMTSigner newSigner = new org.bouncycastle.crypto.signers.XMSSMTSigner();
        newSigner.init(true, newKp.getPrivate());
        newSigner.update(MESSAGE, 0, MESSAGE.length);
        byte[] newSig = newSigner.generateSignature();

        org.bouncycastle.pqc.crypto.xmss.XMSSMTSigner oldSigner = new org.bouncycastle.pqc.crypto.xmss.XMSSMTSigner();
        oldSigner.init(true, oldKp.getPrivate());
        byte[] oldSig = oldSigner.generateSignature(MESSAGE);

        assertTrue(label + ": signatures differ", Arrays.areEqual(newSig, oldSig));

        org.bouncycastle.crypto.signers.XMSSMTSigner newVerifier = new org.bouncycastle.crypto.signers.XMSSMTSigner();
        newVerifier.init(false, newKp.getPublic());
        newVerifier.update(MESSAGE, 0, MESSAGE.length);
        assertTrue(label + ": promoted verifier rejected the deprecated signature",
            newVerifier.verifySignature(oldSig));

        org.bouncycastle.pqc.crypto.xmss.XMSSMTSigner oldVerifier = new org.bouncycastle.pqc.crypto.xmss.XMSSMTSigner();
        oldVerifier.init(false, oldKp.getPublic());
        assertTrue(label + ": deprecated verifier rejected the promoted signature",
            oldVerifier.verifySignature(MESSAGE, newSig));
    }

    private void compareEncodings(String label, AsymmetricCipherKeyPair newKp, AsymmetricCipherKeyPair oldKp)
        throws Exception
    {
        byte[] newPub = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(newKp.getPublic()).getEncoded();
        byte[] oldPub = org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory
            .createSubjectPublicKeyInfo(oldKp.getPublic()).getEncoded();
        assertTrue(label + ": public key encodings differ", Arrays.areEqual(newPub, oldPub));

        byte[] newPriv = PrivateKeyInfoFactory.createPrivateKeyInfo(newKp.getPrivate()).getEncoded();
        byte[] oldPriv = org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory
            .createPrivateKeyInfo(oldKp.getPrivate()).getEncoded();
        assertTrue(label + ": private key encodings differ", Arrays.areEqual(newPriv, oldPriv));

        // each side's key factory must accept the other side's encoding
        assertNotNull(label + ": promoted factory rejected the deprecated public key",
            PublicKeyFactory.createKey(oldPub));
        assertNotNull(label + ": promoted factory rejected the deprecated private key",
            PrivateKeyFactory.createKey(oldPriv));
        assertNotNull(label + ": deprecated factory rejected the promoted public key",
            org.bouncycastle.pqc.crypto.util.PublicKeyFactory.createKey(newPub));
        assertNotNull(label + ": deprecated factory rejected the promoted private key",
            org.bouncycastle.pqc.crypto.util.PrivateKeyFactory.createKey(newPriv));
    }

    private static org.bouncycastle.crypto.params.XMSSParameters newXmssParams(int height, int digest)
    {
        return new org.bouncycastle.crypto.params.XMSSParameters(height, digest(digest));
    }

    private static org.bouncycastle.pqc.crypto.xmss.XMSSParameters oldXmssParams(int height, int digest)
    {
        return new org.bouncycastle.pqc.crypto.xmss.XMSSParameters(height, digest(digest));
    }

    private static org.bouncycastle.crypto.params.XMSSMTParameters newXmssMtParams(int height, int layers, int digest)
    {
        return new org.bouncycastle.crypto.params.XMSSMTParameters(height, layers, digest(digest));
    }

    private static org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters oldXmssMtParams(int height, int layers, int digest)
    {
        return new org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters(height, layers, digest(digest));
    }

    private static Digest digest(int n)
    {
        switch (n)
        {
        case 0:
            return new SHA256Digest();
        case 1:
            return new SHAKEDigest(128);
        case 2:
            return new SHA512Digest();
        default:
            return new SHAKEDigest(256);
        }
    }

    private static byte[] seedFor(int n)
    {
        byte[] seed = new byte[64];
        for (int i = 0; i != seed.length; i++)
        {
            seed[i] = (byte)(n * 31 + i);
        }
        return seed;
    }

    private static SecureRandom fixedRandom(byte[] seed)
    {
        // key generation reads three tree-digest-sized blocks (3 * 64 at the largest parameter set)
        byte[] material = new byte[6 * seed.length];
        for (int i = 0; i != 6; i++)
        {
            System.arraycopy(seed, 0, material, i * seed.length, seed.length);
        }

        return new FixedSecureRandom(new FixedSecureRandom.Source[]{ new FixedSecureRandom.Data(material) });
    }
}
