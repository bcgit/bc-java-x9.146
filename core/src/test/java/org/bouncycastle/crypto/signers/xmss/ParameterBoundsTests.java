package org.bouncycastle.crypto.signers.xmss;

import java.io.IOException;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.generators.XMSSKeyPairGenerator;
import org.bouncycastle.crypto.params.XMSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.XMSSKeyParams;
import org.bouncycastle.pqc.asn1.XMSSMTKeyParams;
import org.bouncycastle.pqc.asn1.XMSSPrivateKey;
import org.bouncycastle.pqc.asn1.XMSSPublicKey;

/**
 * A tree height is only meaningful up to the point where an int index can still count the tree's
 * leaves, and the parameter classes take one from whoever asks - including, through the ASN.1 key
 * parameters, from a key that arrived from somewhere else.
 */
public class ParameterBoundsTests
    extends TestCase
{
    /**
     * DigestUtil's two lookups are how a tree digest OID is turned into something usable, and they
     * are the pair this package refuses an unknown OID through. An absent one is the same mistake
     * and they answered it differently: getDigestName looks the OID up in a map, which takes a null
     * key and reports it by name, while getDigest compared the argument against each constant in
     * turn and so raised a NullPointerException on the first comparison. Since the removal of the
     * null check WOTSPlusParameters used to carry, this pair is the whole of what an absent OID
     * meets.
     */
    public void testAnAbsentTreeDigestOidIsRefusedByName()
    {
        try
        {
            DigestUtil.getDigest(null);
            fail("a null tree digest OID produced a digest");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("unrecognized digest OID: null", e.getMessage());
        }

        try
        {
            DigestUtil.getDigestName(null);
            fail("a null tree digest OID produced a name");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("unrecognized digest oid: null", e.getMessage());
        }
    }

    public void testHeightAboveMaximumRefused()
    {
        // 31 above a multiple of 32 wraps (1 << height) to a negative, which left key generation
        // with no leaves to build from; the rest wrap to a small positive, which built a shorter
        // tree than the one asked for
        int[] heights = new int[]{31, 32, 33, 62, 63, 64, 95, 96, Integer.MAX_VALUE};

        for (int i = 0; i != heights.length; i++)
        {
            try
            {
                new XMSSParameters(heights[i], NISTObjectIdentifiers.id_sha256);
                fail("height " + heights[i] + " accepted");
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("height must be <= 30", e.getMessage());
            }
        }
    }

    /**
     * The security parameter n is the caller's on both public constructors that take one, and
     * nothing derived from it is bounded - len1, len2 and len are computed from whatever arrives.
     * What refuses one that no registered parameter set defines is the WOTS+ parameter set lookup
     * in WOTSPlusParameters, whose answer is otherwise unread, so this is what says that lookup is
     * still doing something.
     */
    public void testSecurityParameterOutsideRegisteredSetsRefused()
    {
        // 32 and 24 are SHA-256's two, being RFC 8391 XMSS-SHA2_*_256 and SP 800-208
        // XMSS-SHA2_*_192; 64 is SHA-512's n asked for of SHA-256, which is neither. Zero and
        // below are not here because they are not sizes at all to these constructors - n > 0 is
        // what asks for an explicit one, and anything else means take the digest's own.
        int[] sizes = new int[]{1, 16, 17, 20, 31, 33, 48, 64, 128};

        for (int i = 0; i != sizes.length; i++)
        {
            try
            {
                new XMSSParameters(10, NISTObjectIdentifiers.id_sha256, sizes[i]);
                fail("n = " + sizes[i] + " accepted for XMSS");
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("cannot find OID for digest algorithm: SHA-256", e.getMessage());
            }

            try
            {
                new XMSSMTParameters(20, 2, NISTObjectIdentifiers.id_sha256, sizes[i]);
                fail("n = " + sizes[i] + " accepted for XMSS^MT");
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("cannot find OID for digest algorithm: SHA-256", e.getMessage());
            }
        }

        assertEquals(67, new XMSSParameters(10, NISTObjectIdentifiers.id_sha256, 32).getLen());
        assertEquals(51, new XMSSParameters(10, NISTObjectIdentifiers.id_sha256, 24).getLen());
    }

    public void testHeightBelowMinimumRefused()
    {
        int[] heights = new int[]{Integer.MIN_VALUE, -1, 0, 1};

        for (int i = 0; i != heights.length; i++)
        {
            try
            {
                new XMSSParameters(heights[i], NISTObjectIdentifiers.id_sha256);
                fail("height " + heights[i] + " accepted");
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("height must be >= 2", e.getMessage());
            }
        }
    }

    /**
     * The height in an XMSSKeyParams is whatever the encoded key said it was, so it reaches the
     * parameter set straight off the wire and has to be reported the way the rest of a malformed
     * key is - as an IOException out of the factory, not as an unchecked exception through it.
     */
    public void testHeightFromEncodedKeyReported()
        throws Exception
    {
        AlgorithmIdentifier treeDigest = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        AlgorithmIdentifier algId = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss,
            new XMSSKeyParams(31, treeDigest));

        try
        {
            PublicKeyFactory.createKey(new SubjectPublicKeyInfo(algId,
                new XMSSPublicKey(new byte[32], new byte[32])));
            fail("height 31 in public key parameters accepted");
        }
        catch (IOException e)
        {
            assertEquals("malformed XMSS public key: height must be <= 30", e.getMessage());
        }

        try
        {
            PrivateKeyFactory.createKey(new PrivateKeyInfo(algId,
                new XMSSPrivateKey(0, new byte[32], new byte[32], new byte[32], new byte[32], null)));
            fail("height 31 in private key parameters accepted");
        }
        catch (IOException e)
        {
            assertEquals("malformed XMSS private key: height must be <= 30", e.getMessage());
        }
    }

    public void testLayerCountRefused()
    {
        // zero divided into the total height, and a negative that divides into it cleanly
        int[][] cases = new int[][]{{4, 0}, {2, 0}, {4, -1}, {4, -2}, {60, Integer.MIN_VALUE}};

        for (int i = 0; i != cases.length; i++)
        {
            try
            {
                new XMSSMTParameters(cases[i][0], cases[i][1], NISTObjectIdentifiers.id_sha256);
                fail("layers " + cases[i][1] + " accepted");
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("layers must be >= 1", e.getMessage());
            }
        }
    }

    /**
     * As for the XMSS height, the layer count reaches the parameter set straight off the wire.
     */
    public void testLayerCountFromEncodedKeyReported()
        throws Exception
    {
        AlgorithmIdentifier treeDigest = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        AlgorithmIdentifier algId = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss_mt,
            new XMSSMTKeyParams(4, 0, treeDigest));

        try
        {
            PublicKeyFactory.createKey(new SubjectPublicKeyInfo(algId,
                new XMSSPublicKey(new byte[32], new byte[32])));
            fail("zero layers in public key parameters accepted");
        }
        catch (IOException e)
        {
            assertEquals("malformed XMSS^MT public key: layers must be >= 1", e.getMessage());
        }
    }

    public void testTotalHeightAboveMaximumRefused()
    {
        // a total height of 63 leaves every index reading as invalid, and 64 wraps the maximum
        // index to 0 - both silent, so neither shows up as a failure to build the key
        int[][] cases = new int[][]{{63, 3}, {64, 4}, {640, 64}, {1200, 120}};

        for (int i = 0; i != cases.length; i++)
        {
            try
            {
                new XMSSMTParameters(cases[i][0], cases[i][1], NISTObjectIdentifiers.id_sha256);
                fail("total height " + cases[i][0] + " accepted");
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("totalHeight must be <= 62", e.getMessage());
            }
        }
    }

    /**
     * Every parameter set RFC 8391 sec. 5.3 registers has to remain constructible - the bounds
     * are on what the arithmetic can carry, not a narrowing of the registered sets.
     */
    public void testRegisteredHypertreeSetsStillConstruct()
    {
        int[][] cases = new int[][]{{20, 2}, {20, 4}, {40, 2}, {40, 4}, {40, 8}, {60, 3}, {60, 6},
            {60, 12}};

        for (int i = 0; i != cases.length; i++)
        {
            XMSSMTParameters params = new XMSSMTParameters(cases[i][0], cases[i][1],
                NISTObjectIdentifiers.id_sha256);

            assertEquals(cases[i][0], params.getHeight());
            assertEquals(cases[i][1], params.getLayers());
        }
    }

    /**
     * The bound is the tallest tree the traversal state will validate, not something narrower:
     * a height BDS accepts has to remain constructible.
     */
    public void testMaximumHeightStillConstructs()
    {
        XMSSParameters params = new XMSSParameters(XMSSParameters.MAX_HEIGHT,
            NISTObjectIdentifiers.id_sha256);

        assertEquals(30, params.getHeight());

        // and the smallest tree, generated through to a usable key pair
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(
            new XMSSParameters(2, NISTObjectIdentifiers.id_sha256), new SecureRandom()));

        assertNotNull(kpg.generateKeyPair().getPrivate());
    }
}
