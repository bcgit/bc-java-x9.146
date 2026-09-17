package org.bouncycastle.jcajce.provider.test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Optional;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

/**
 * The JDK 11+ XEC key specs against the multi-release jar: a BC X25519 / X448 key must go out
 * through java.security.spec.XECPublicKeySpec / XECPrivateKeySpec and come back in again, which
 * is what lets a caller move a key between BC and another provider by coordinates rather than by
 * encoding. Only the jdk1.11 XDHKeys twin implements this, so a test in the base tree would never
 * see it - the base copy returns null and the SPI falls through to "key spec not recognized".
 */
public class XDHKeySpecMRTest
    extends TestCase
{
    private static final String BC = "BC";
    private static final String SUN = "SunEC";

    private static final BigInteger X25519_P =
        BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger X448_P =
        BigInteger.ONE.shiftLeft(448).subtract(BigInteger.ONE.shiftLeft(224)).subtract(BigInteger.ONE);

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

    public void testPublicKeySpecRoundTrip()
        throws Exception
    {
        checkPublicRoundTrip("X25519");
        checkPublicRoundTrip("X448");
    }

    private void checkPublicRoundTrip(String algorithm)
        throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance(algorithm, BC).generateKeyPair();
        KeyFactory kf = KeyFactory.getInstance(algorithm, BC);

        XECPublicKeySpec spec = (XECPublicKeySpec)kf.getKeySpec(kp.getPublic(), XECPublicKeySpec.class);

        assertEquals(algorithm, ((NamedParameterSpec)spec.getParams()).getName());
        assertEquals(algorithm, ((XECPublicKey)kp.getPublic()).getU(), spec.getU());

        PublicKey back = kf.generatePublic(spec);

        assertEquals(algorithm, kp.getPublic(), back);
        assertTrue(algorithm, Arrays.areEqual(kp.getPublic().getEncoded(), back.getEncoded()));
    }

    public void testPrivateKeySpecRoundTrip()
        throws Exception
    {
        checkPrivateRoundTrip("X25519");
        checkPrivateRoundTrip("X448");
    }

    private void checkPrivateRoundTrip(String algorithm)
        throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance(algorithm, BC).generateKeyPair();
        KeyFactory kf = KeyFactory.getInstance(algorithm, BC);

        XECPrivateKeySpec spec = (XECPrivateKeySpec)kf.getKeySpec(kp.getPrivate(), XECPrivateKeySpec.class);

        assertEquals(algorithm, algorithm, ((NamedParameterSpec)spec.getParams()).getName());

        Optional<byte[]> scalar = ((XECPrivateKey)kp.getPrivate()).getScalar();
        assertTrue(algorithm, scalar.isPresent());
        assertTrue(algorithm, Arrays.areEqual(scalar.get(), spec.getScalar()));

        PrivateKey back = kf.generatePrivate(spec);

        assertEquals(algorithm, kp.getPrivate(), back);
        assertTrue(algorithm, Arrays.areEqual(kp.getPrivate().getEncoded(), back.getEncoded()));
    }

    /**
     * RFC 7748 sec. 5: a u at or past the field prime must be accepted and processed as though it
     * had been reduced, so the non-canonical value has to produce the same key as the canonical one
     * rather than a distinct key or a rejection.
     */
    public void testNonCanonicalUIsReduced()
        throws Exception
    {
        checkNonCanonical("X25519", X25519_P, BigInteger.valueOf(9));
        checkNonCanonical("X448", X448_P, BigInteger.valueOf(5));
    }

    private void checkNonCanonical(String algorithm, BigInteger p, BigInteger u)
        throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance(algorithm, BC);
        NamedParameterSpec np = new NamedParameterSpec(algorithm);

        PublicKey canonical = kf.generatePublic(new XECPublicKeySpec(np, u));
        PublicKey nonCanonical = kf.generatePublic(new XECPublicKeySpec(np, p.add(u)));

        assertEquals(algorithm, canonical, nonCanonical);
        assertTrue(algorithm, Arrays.areEqual(canonical.getEncoded(), nonCanonical.getEncoded()));

        // and a value past the octet width the wire format allows reduces the same way
        PublicKey wide = kf.generatePublic(new XECPublicKeySpec(np, p.multiply(BigInteger.valueOf(3)).add(u)));

        assertEquals(algorithm, canonical, wide);
    }

    /**
     * The parity case the request came from: BC and the JDK's own provider must agree on the key a
     * shared XECPublicKeySpec describes, including for a non-canonical u.
     * <p>
     * The comparison is on the u-coordinate, not on getEncoded(): SunEC on JDK 11 emits the
     * SubjectPublicKeyInfo with an explicit NULL in the AlgorithmIdentifier parameters, where RFC
     * 8410 sec. 3 says "For all of the OIDs, the parameters MUST be absent" - as BC does, and as
     * later JDKs came to do. Asserting on the whole encoding would therefore assert BC shares that
     * defect. What this change controls is the coordinate conversion, which is what is compared.
     */
    public void testAgreesWithSunEC()
        throws Exception
    {
        if (Security.getProvider(SUN) == null)
        {
            return;
        }

        checkAgainstSunEC("X25519", X25519_P, BigInteger.valueOf(9));
        checkAgainstSunEC("X448", X448_P, BigInteger.valueOf(5));
    }

    private void checkAgainstSunEC(String algorithm, BigInteger p, BigInteger u)
        throws Exception
    {
        KeyFactory bcFact = KeyFactory.getInstance(algorithm, BC);
        KeyFactory sunFact = KeyFactory.getInstance(algorithm, SUN);
        NamedParameterSpec np = new NamedParameterSpec(algorithm);

        BigInteger[] values = new BigInteger[]{ u, p.add(u), p.subtract(BigInteger.ONE), BigInteger.ZERO };

        for (int i = 0; i != values.length; i++)
        {
            XECPublicKeySpec spec = new XECPublicKeySpec(np, values[i]);

            BigInteger fromBC = ((XECPublicKey)bcFact.generatePublic(spec)).getU();
            BigInteger fromSun = ((XECPublicKey)sunFact.generatePublic(spec)).getU();

            assertEquals(algorithm + " u=" + values[i], fromSun, fromBC);
        }

        // a key made by the JDK provider translates into a BC key through the shared spec
        KeyPair sunPair = KeyPairGenerator.getInstance(algorithm, SUN).generateKeyPair();
        XECPublicKeySpec sunSpec = (XECPublicKeySpec)sunFact.getKeySpec(sunPair.getPublic(), XECPublicKeySpec.class);

        assertEquals(algorithm, ((XECPublicKey)sunPair.getPublic()).getU(),
            ((XECPublicKey)bcFact.generatePublic(sunSpec)).getU());
    }

    public void testUnrecognizedParameters()
        throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("X25519", BC);

        try
        {
            kf.generatePublic(new XECPublicKeySpec(new NamedParameterSpec("Ed25519"), BigInteger.valueOf(9)));
            fail("no exception");
        }
        catch (InvalidKeySpecException e)
        {
            assertEquals("unrecognized named parameters: Ed25519", e.getMessage());
        }

        try
        {
            kf.generatePrivate(new XECPrivateKeySpec(new NamedParameterSpec("Ed25519"), new byte[32]));
            fail("no exception");
        }
        catch (InvalidKeySpecException e)
        {
            assertEquals("unrecognized named parameters: Ed25519", e.getMessage());
        }
    }

    public void testMalformedSpecs()
        throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("X25519", BC);
        NamedParameterSpec np = NamedParameterSpec.X25519;

        // a scalar of the wrong width is not padded or truncated into shape
        try
        {
            kf.generatePrivate(new XECPrivateKeySpec(np, new byte[31]));
            fail("no exception");
        }
        catch (InvalidKeySpecException e)
        {
            assertEquals("cannot use XEC private key (X25519) with scalar of incorrect length", e.getMessage());
        }

        // BC rejects a negative u rather than reading it as its representative modulo p, matching
        // the check already applied to an incoming JDK XECPublicKey object
        try
        {
            kf.generatePublic(new XECPublicKeySpec(np, BigInteger.valueOf(-1)));
            fail("no exception");
        }
        catch (InvalidKeySpecException e)
        {
            assertEquals("cannot use XEC public key with negative U value", e.getMessage());
        }
    }

    /**
     * A spec class the XDH factory does not bridge must still reach the base handling rather than
     * being swallowed by the new fall-through.
     */
    public void testUnrelatedSpecStillRejected()
        throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("X25519", BC);

        try
        {
            kf.generatePublic(new java.security.spec.EncodedKeySpec(new byte[10])
            {
                public String getFormat()
                {
                    return "not-a-format";
                }
            });
            fail("no exception");
        }
        catch (InvalidKeySpecException e)
        {
            // expected - the base BaseKeyFactorySpi handling
        }
    }
}
