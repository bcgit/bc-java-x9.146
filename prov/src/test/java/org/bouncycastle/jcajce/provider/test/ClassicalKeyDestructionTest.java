package org.bouncycastle.jcajce.provider.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;
import javax.security.auth.Destroyable;

import junit.framework.TestCase;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.crypto.agreement.DHStandardGroups;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.bouncycastle.crypto.params.GOST3410Parameters;
import org.bouncycastle.crypto.params.GOST3410PrivateKeyParameters;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.bouncycastle.jce.interfaces.GOST3410PrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.GOST3410ParameterSpec;
import org.bouncycastle.jce.spec.GOST3410PublicKeyParameterSetSpec;

/**
 * Verifies that the remaining BigInteger-backed classical private keys honour the JCA
 * {@link javax.security.auth.Destroyable} contract, extending {@link ECRSAKeyDestructionTest} to
 * DSA, DH, ElGamal, GOST R 34.10-94, ECGOST R 34.10-2001, ECGOST R 34.10-2012 and DSTU 4145:
 * {@code destroy()} drops the held private value, {@code isDestroyed()} flips, the secret-bearing
 * accessors throw afterwards while the domain parameters survive, {@code hashCode()} is stable,
 * equality collapses to identity, and a destroyed key cannot be serialized (IOException, not an
 * escaping IllegalStateException). The lightweight parameter objects underneath are covered too.
 * See github #2432.
 */
public class ClassicalKeyDestructionTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    // FIPS 186-3 2048/256 domain parameters, so the DSA key pair does not need parameter generation
    private static final DSAParameterSpec DSA_PARAMS = new DSAParameterSpec(
        new BigInteger(
                    "F56C2A7D366E3EBDEAA1891FD2A0D099" +
                    "436438A673FED4D75F594959CFFEBCA7BE0FC72E4FE67D91" +
                    "D801CBA0693AC4ED9E411B41D19E2FD1699C4390AD27D94C" +
                    "69C0B143F1DC88932CFE2310C886412047BD9B1C7A67F8A2" +
                    "5909132627F51A0C866877E672E555342BDF9355347DBD43" +
                    "B47156B2C20BAD9D2B071BC2FDCF9757F75C168C5D9FC431" +
                    "31BE162A0756D1BDEC2CA0EB0E3B018A8B38D3EF2487782A" +
                    "EB9FBF99D8B30499C55E4F61E5C7DCEE2A2BB55BD7F75FCD" +
                    "F00E48F2E8356BDB59D86114028F67B8E07B127744778AFF" +
                    "1CF1399A4D679D92FDE7D941C5C85C5D7BFF91BA69F9489D" +
                    "531D1EBFA727CFDA651390F8021719FA9F7216CEB177BD75", 16),
        new BigInteger("C24ED361870B61E0D367F008F99F8A1F75525889C89DB1B673C45AF5867CB467", 16),
        new BigInteger(
                    "8DC6CC814CAE4A1C05A3E186A6FE27EA" +
                    "BA8CDB133FDCE14A963A92E809790CBA096EAA26140550C1" +
                    "29FA2B98C16E84236AA33BF919CD6F587E048C52666576DB" +
                    "6E925C6CBE9B9EC5C16020F9A44C9F1C8F7A8E611C1F6EC2" +
                    "513EA6AA0B8D0F72FED73CA37DF240DB57BBB27431D61869" +
                    "7B9E771B0B301D5DF05955425061A30DC6D33BB6D2A32BD0" +
                    "A75A0A71D2184F506372ABF84A56AEEEA8EB693BF29A6403" +
                    "45FA1298A16E85421B2208D00068A5A42915F82CF0B858C8" +
                    "FA39D43D704B6927E0B2F916304E86FB6A1B487F07D8139E" +
                    "428BB096C6D67A76EC0B8D4EF274B8A2CF556D279AD267CC" +
                    "EF5AF477AFED029F485B5597739F5D0240F67C2D948A6279", 16));

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testDestroyErasesDSAPrivateKey()
        throws Exception
    {
        final DSAPrivateKey priv = (DSAPrivateKey)generate("DSA", DSA_PARAMS).getPrivate();
        BigInteger x = priv.getX();

        checkDestroy("DSA", priv);

        checkThrowsDestroyed("DSA: getX()", new Callable()
        {
            public Object call()
            {
                return priv.getX();
            }
        });
        assertNotNull("DSA: parameters should survive destroy()", priv.getParams());

        // the lightweight parameters underneath
        final DSAPrivateKeyParameters params = new DSAPrivateKeyParameters(x,
            new DSAParameters(DSA_PARAMS.getP(), DSA_PARAMS.getQ(), DSA_PARAMS.getG()));

        checkLightweightDestroy("DSA", params);

        checkThrowsDestroyed("DSA params: getX()", new Callable()
        {
            public Object call()
            {
                return params.getX();
            }
        });
        assertNotNull("DSA params: parameters should survive destroy()", params.getParameters());
    }

    public void testDestroyErasesDHPrivateKey()
        throws Exception
    {
        DHParameters group = DHStandardGroups.rfc3526_2048;
        final DHPrivateKey priv = (DHPrivateKey)generate("DH", new DHParameterSpec(group.getP(), group.getG())).getPrivate();
        BigInteger x = priv.getX();

        final PrivateKey copy = checkDestroy("DH", priv);

        checkThrowsDestroyed("DH: getX()", new Callable()
        {
            public Object call()
            {
                return priv.getX();
            }
        });
        assertNotNull("DH: parameters should survive destroy()", priv.getParams());

        // a key decoded from PKCS#8 keeps the PrivateKeyInfo it was decoded from and encodes
        // from that - destroy() has to drop it too.
        ((Destroyable)copy).destroy();
        checkThrowsDestroyed("DH: decoded key getEncoded()", new Callable()
        {
            public Object call()
            {
                return copy.getEncoded();
            }
        });

        // the lightweight parameters underneath - these carry their own hashCode/equals
        final DHPrivateKeyParameters params = new DHPrivateKeyParameters(x, group);
        DHPrivateKeyParameters twin = new DHPrivateKeyParameters(x, group);
        int preHashCode = params.hashCode();

        assertEquals("DH params: twin should be equal before destroy()", params, twin);

        checkLightweightDestroy("DH", params);

        checkThrowsDestroyed("DH params: getX()", new Callable()
        {
            public Object call()
            {
                return params.getX();
            }
        });
        assertNotNull("DH params: parameters should survive destroy()", params.getParameters());
        assertEquals("DH params: hashCode should be stable across destroy()", preHashCode, params.hashCode());
        assertTrue("DH params: destroyed key should still equal itself", params.equals(params));
        assertFalse("DH params: destroyed key should not equal a live twin", params.equals(twin));
        assertFalse("DH params: live twin should not equal a destroyed key", twin.equals(params));
    }

    public void testDestroyErasesElGamalPrivateKey()
        throws Exception
    {
        DHParameters group = DHStandardGroups.rfc3526_2048;
        final ElGamalPrivateKey priv = (ElGamalPrivateKey)generate("ElGamal", new DHParameterSpec(group.getP(), group.getG())).getPrivate();
        BigInteger x = priv.getX();

        checkDestroy("ElGamal", priv);

        checkThrowsDestroyed("ElGamal: getX()", new Callable()
        {
            public Object call()
            {
                return priv.getX();
            }
        });
        assertNotNull("ElGamal: parameters should survive destroy()", priv.getParameters());

        // the lightweight parameters underneath - these carry their own hashCode/equals
        ElGamalParameters elParams = new ElGamalParameters(group.getP(), group.getG());
        final ElGamalPrivateKeyParameters params = new ElGamalPrivateKeyParameters(x, elParams);
        ElGamalPrivateKeyParameters twin = new ElGamalPrivateKeyParameters(x, elParams);
        int preHashCode = params.hashCode();

        assertEquals("ElGamal params: twin should be equal before destroy()", params, twin);

        checkLightweightDestroy("ElGamal", params);

        checkThrowsDestroyed("ElGamal params: getX()", new Callable()
        {
            public Object call()
            {
                return params.getX();
            }
        });
        assertNotNull("ElGamal params: parameters should survive destroy()", params.getParameters());
        assertEquals("ElGamal params: hashCode should be stable across destroy()", preHashCode, params.hashCode());
        assertTrue("ElGamal params: destroyed key should still equal itself", params.equals(params));
        assertFalse("ElGamal params: destroyed key should not equal a live twin", params.equals(twin));
        assertFalse("ElGamal params: live twin should not equal a destroyed key", twin.equals(params));
    }

    public void testDestroyErasesGOST3410PrivateKey()
        throws Exception
    {
        final GOST3410PrivateKey priv = (GOST3410PrivateKey)generate("GOST3410",
            new GOST3410ParameterSpec(CryptoProObjectIdentifiers.gostR3410_94_CryptoPro_A.getId())).getPrivate();
        BigInteger x = priv.getX();
        GOST3410PublicKeyParameterSetSpec setSpec = priv.getParameters().getPublicKeyParameters();

        checkDestroy("GOST3410", priv);

        checkThrowsDestroyed("GOST3410: getX()", new Callable()
        {
            public Object call()
            {
                return priv.getX();
            }
        });
        assertNotNull("GOST3410: parameters should survive destroy()", priv.getParameters());

        // the lightweight parameters underneath
        final GOST3410PrivateKeyParameters params = new GOST3410PrivateKeyParameters(x,
            new GOST3410Parameters(setSpec.getP(), setSpec.getQ(), setSpec.getA()));

        checkLightweightDestroy("GOST3410", params);

        checkThrowsDestroyed("GOST3410 params: getX()", new Callable()
        {
            public Object call()
            {
                return params.getX();
            }
        });
        assertNotNull("GOST3410 params: parameters should survive destroy()", params.getParameters());
    }

    public void testDestroyErasesECGOST3410PrivateKey()
        throws Exception
    {
        checkECStyleKey("ECGOST3410", new ECGenParameterSpec("GostR3410-2001-CryptoPro-A"));
    }

    public void testDestroyErasesECGOST3410_2012PrivateKey()
        throws Exception
    {
        checkECStyleKey("ECGOST3410-2012", new ECGenParameterSpec("Tc26-Gost-3410-12-256-paramSetA"));
        checkECStyleKey("ECGOST3410-2012", new ECGenParameterSpec("Tc26-Gost-3410-12-512-paramSetA"));
    }

    public void testDestroyErasesDSTU4145PrivateKey()
        throws Exception
    {
        checkECStyleKey("DSTU4145", new ECGenParameterSpec("1.2.804.2.1.1.1.1.3.1.1.2.0"));
    }

    /**
     * The three EC-based keys expose the private value as both the JCA getS() and the BC getD().
     */
    private void checkECStyleKey(String algorithm, AlgorithmParameterSpec spec)
        throws Exception
    {
        final PrivateKey priv = generate(algorithm, spec).getPrivate();
        final ECPrivateKey ecPriv = (ECPrivateKey)priv;
        final org.bouncycastle.jce.interfaces.ECPrivateKey bcPriv = (org.bouncycastle.jce.interfaces.ECPrivateKey)priv;

        assertNotNull(ecPriv.getS());
        assertEquals(ecPriv.getS(), bcPriv.getD());

        checkDestroy(algorithm, priv);

        checkThrowsDestroyed(algorithm + ": getS()", new Callable()
        {
            public Object call()
            {
                return ecPriv.getS();
            }
        });
        checkThrowsDestroyed(algorithm + ": getD()", new Callable()
        {
            public Object call()
            {
                return bcPriv.getD();
            }
        });
        assertNotNull(algorithm + ": domain parameters should survive destroy()", ecPriv.getParams());
        assertNotNull(algorithm + ": BC domain parameters should survive destroy()", bcPriv.getParameters());
    }

    private KeyPair generate(String algorithm, AlgorithmParameterSpec spec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, BC);

        kpg.initialize(spec);

        return kpg.generateKeyPair();
    }

    /**
     * The contract common to every key: destroyable, destroy() succeeds and is idempotent,
     * isDestroyed() flips, getEncoded() throws, hashCode() is stable, equality collapses to
     * identity, toString() still works and serialization fails cleanly.
     *
     * @return a live copy of the key, decoded from its PKCS#8 encoding before destruction.
     */
    private PrivateKey checkDestroy(String algorithm, final PrivateKey priv)
        throws Exception
    {
        byte[] enc = priv.getEncoded();
        assertNotNull(algorithm + ": no encoding", enc);
        assertTrue(algorithm + ": key must be destroyable", priv instanceof Destroyable);

        Destroyable dPriv = (Destroyable)priv;
        assertFalse(algorithm + ": key reported destroyed before destroy()", dPriv.isDestroyed());

        int preHashCode = priv.hashCode();

        PrivateKey copy = KeyFactory.getInstance(algorithm, BC).generatePrivate(new PKCS8EncodedKeySpec(enc));
        assertEquals(algorithm + ": copy should equal original before destroy()", priv, copy);
        assertEquals(algorithm + ": copy should hash as original before destroy()", preHashCode, copy.hashCode());

        // must succeed without throwing DestroyFailedException
        dPriv.destroy();

        assertTrue(algorithm + ": key not reported destroyed after destroy()", dPriv.isDestroyed());

        checkThrowsDestroyed(algorithm + ": getEncoded()", new Callable()
        {
            public Object call()
            {
                return priv.getEncoded();
            }
        });

        // hashCode is stable, and equality collapses to identity
        assertEquals(algorithm + ": hashCode should be stable across destroy()", preHashCode, priv.hashCode());
        assertTrue(algorithm + ": destroyed key should still equal itself", priv.equals(priv));
        assertFalse(algorithm + ": destroyed key should not equal a live copy", priv.equals(copy));
        assertFalse(algorithm + ": live copy should not equal a destroyed key", copy.equals(priv));
        assertNotNull(algorithm + ": toString() should not throw once destroyed", priv.toString());
        assertEquals(algorithm + ": algorithm name should survive destroy()", priv.getAlgorithm(), copy.getAlgorithm());

        checkSerializationFails(algorithm, priv);

        // destroy() is idempotent - a second call must not throw
        dPriv.destroy();
        assertTrue(dPriv.isDestroyed());

        return copy;
    }

    private void checkLightweightDestroy(String algorithm, Object params)
        throws Exception
    {
        assertTrue(algorithm + " params: must be destroyable", params instanceof Destroyable);

        Destroyable dParams = (Destroyable)params;
        assertFalse(algorithm + " params: reported destroyed before destroy()", dParams.isDestroyed());

        dParams.destroy();

        assertTrue(algorithm + " params: not reported destroyed after destroy()", dParams.isDestroyed());

        // idempotent
        dParams.destroy();
        assertTrue(dParams.isDestroyed());
    }

    private void checkThrowsDestroyed(String what, Callable call)
    {
        try
        {
            call.call();
            fail(what + " should throw once destroyed");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }
    }

    private void checkSerializationFails(String algorithm, PrivateKey priv)
        throws Exception
    {
        ObjectOutputStream oOut = new ObjectOutputStream(new ByteArrayOutputStream());
        try
        {
            oOut.writeObject(priv);
            fail(algorithm + ": serialization should throw once destroyed");
        }
        catch (IOException e)
        {
            // expected - the declared exception, carrying the destroyed message
            assertEquals("key destroyed", e.getMessage());
        }
        catch (IllegalStateException e)
        {
            fail(algorithm + ": IllegalStateException must not escape writeObject");
        }
    }

    private interface Callable
    {
        Object call();
    }
}
