package org.bouncycastle.jcajce.provider.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.security.auth.Destroyable;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

/**
 * Verifies that the NIST/ISO PQC private keys honour the JCA {@link javax.security.auth.Destroyable}
 * contract: {@code destroy()} zeroizes the held key material, {@code isDestroyed()} flips, and the
 * secret-bearing accessors throw afterwards. See github #2366.
 */
public class PQCKeyDestructionTest
    extends TestCase
{
    private static final String[] ALGORITHMS = { "ML-DSA", "ML-KEM", "SLH-DSA", "FRODOKEM", "CMCE" };

    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testDestroyErasesPrivateKey()
        throws Exception
    {
        for (int i = 0; i != ALGORITHMS.length; i++)
        {
            checkDestroy(ALGORITHMS[i]);
        }
    }

    private void checkDestroy(String algorithm)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        KeyPair kp = kpg.generateKeyPair();

        final PrivateKey priv = kp.getPrivate();

        byte[] enc = priv.getEncoded();
        assertNotNull(algorithm + ": no encoding", enc);
        assertFalse(algorithm + ": encoding should not be all-zero", isAllZero(enc));

        // through the interface rather than off PrivateKey: PrivateKey extends Destroyable only
        // from Java 8, and this suite is compiled by the genuine 1.5 javac of the jdk15to18 build
        final Destroyable dPriv = (Destroyable)priv;

        assertFalse(algorithm + ": key reported destroyed before destroy()", dPriv.isDestroyed());

        PrivateKey copy = KeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME)
            .generatePrivate(new PKCS8EncodedKeySpec(enc));
        assertEquals(algorithm + ": copy should equal original before destroy()", priv, copy);

        // must succeed without throwing DestroyFailedException
        dPriv.destroy();

        assertTrue(algorithm + ": key not reported destroyed after destroy()", dPriv.isDestroyed());

        try
        {
            priv.getEncoded();
            fail(algorithm + ": getEncoded() should throw once destroyed");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }

        // a destroyed key no longer exposes its value, so equality collapses to identity
        assertTrue(algorithm + ": destroyed key should still equal itself", priv.equals(priv));
        assertFalse(algorithm + ": destroyed key should not equal a live copy", priv.equals(copy));
        assertFalse(algorithm + ": live copy should not equal a destroyed key", copy.equals(priv));

        // serializing a destroyed key must fail with IOException, not a leaked IllegalStateException
        try
        {
            ObjectOutputStream oOut = new ObjectOutputStream(new ByteArrayOutputStream());
            oOut.writeObject(priv);
            oOut.close();
            fail(algorithm + ": serialization should throw once destroyed");
        }
        catch (IOException e)
        {
            // expected
        }

        // destroy() is idempotent - a second call must not throw
        dPriv.destroy();
        assertTrue(dPriv.isDestroyed());
    }

    private static boolean isAllZero(byte[] data)
    {
        return Arrays.areEqual(data, new byte[data.length]);
    }
}
