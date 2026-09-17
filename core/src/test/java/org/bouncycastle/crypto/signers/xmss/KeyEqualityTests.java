package org.bouncycastle.crypto.signers.xmss;

import java.security.SecureRandom;

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

/**
 * What a stateful private key's equals() and hashCode() answer.
 * <p>
 * Both live on the key parameters, where the fields and the monitor a signature is taken under
 * are, and the two provider keys are one delegating line each - the shape
 * {@code HSSPrivateKeyParameters} and {@code BCLMSPrivateKey} have for the other stateful family.
 * Neither method existed on either class before that, so nothing here was covered: the provider
 * suites assert two keys are equal, which reaches equals(), and nothing at all reached hashCode().
 * </p><p>
 * The property those two have to hold together is the one a stateful key is unusual for. Two keys
 * of a key pair differ in where they have got to and in nothing else, so equals() has to answer on
 * the index while hashCode() must not - it is over the fields that do not move as the key signs,
 * so keys from one key pair share a bucket of a Set or a Map and are told apart inside it. A
 * hashCode() that moved with the index would lose a key that had signed since it was put in.
 * </p>
 */
public class KeyEqualityTests
    extends TestCase
{
    private static final int HEIGHT = 4;
    private static final int LAYERS = 2;

    private static byte[] filled(byte b, int n)
    {
        byte[] rv = new byte[n];

        for (int i = 0; i != n; i++)
        {
            rv[i] = b;
        }

        return rv;
    }

    private static XMSSPrivateKeyParameters newXmssKey()
    {
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(
            new XMSSParameters(HEIGHT, new SHA256Digest()), new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

        return (XMSSPrivateKeyParameters)kp.getPrivate();
    }

    private static XMSSMTPrivateKeyParameters newXmssMtKey()
    {
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(
            new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest()), new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

        return (XMSSMTPrivateKeyParameters)kp.getPrivate();
    }

    private static XMSSPrivateKeyParameters decodeXmss(XMSSPrivateKeyParameters key, byte[] enc)
    {
        return new XMSSPrivateKeyParameters.Builder(key.getParameters()).withPrivateKey(enc).build();
    }

    private static XMSSMTPrivateKeyParameters decodeXmssMt(XMSSMTPrivateKeyParameters key, byte[] enc)
    {
        return new XMSSMTPrivateKeyParameters.Builder(key.getParameters()).withPrivateKey(enc).build();
    }

    /**
     * Two keys decoded from one encoding are two objects the same key, so they answer equal and
     * hash the same. This is the equals()/hashCode() contract on the pair the provider's key
     * factory produces every time a stored key is read back.
     */
    public void testXmssDecodedCopiesAgree()
        throws Exception
    {
        XMSSPrivateKeyParameters key = newXmssKey();
        byte[] enc = key.getEncoded();

        XMSSPrivateKeyParameters a = decodeXmss(key, enc);
        XMSSPrivateKeyParameters b = decodeXmss(key, enc);

        assertFalse("two distinct objects wanted", a == b);
        assertEquals(a, b);
        assertEquals(b, a);
        assertEquals(a.hashCode(), b.hashCode());
        assertEquals(key, a);
        assertEquals(key.hashCode(), a.hashCode());
    }

    public void testXmssMtDecodedCopiesAgree()
        throws Exception
    {
        XMSSMTPrivateKeyParameters key = newXmssMtKey();
        byte[] enc = key.getEncoded();

        XMSSMTPrivateKeyParameters a = decodeXmssMt(key, enc);
        XMSSMTPrivateKeyParameters b = decodeXmssMt(key, enc);

        assertFalse("two distinct objects wanted", a == b);
        assertEquals(a, b);
        assertEquals(b, a);
        assertEquals(a.hashCode(), b.hashCode());
        assertEquals(key, a);
        assertEquals(key.hashCode(), a.hashCode());
    }

    /**
     * A signature moves the answer equals() gives and leaves the bucket hashCode() picks alone.
     * The key at the earlier index is decoded from an encoding taken before signing rather than
     * held as a reference, because rollKey() advances the key in place and hands back the same
     * object - a reference would be the signed key under another name.
     */
    public void testXmssSignatureMovesTheAnswerNotTheBucket()
        throws Exception
    {
        XMSSPrivateKeyParameters key = newXmssKey();
        XMSSPrivateKeyParameters before = decodeXmss(key, key.getEncoded());

        XMSSSigner signer = new XMSSSigner();

        signer.init(true, key);
        signer.update(new byte[]{0x5a}, 0, 1);
        signer.generateSignature();

        XMSSPrivateKeyParameters after = (XMSSPrivateKeyParameters)signer.getUpdatedPrivateKey();

        assertEquals(before.getIndex() + 1, after.getIndex());
        assertFalse("keys at different indices are not equal", before.equals(after));
        assertFalse("keys at different indices are not equal", after.equals(before));
        assertEquals("a signature must not move the key's bucket",
            before.hashCode(), after.hashCode());
    }

    public void testXmssMtSignatureMovesTheAnswerNotTheBucket()
        throws Exception
    {
        XMSSMTPrivateKeyParameters key = newXmssMtKey();
        XMSSMTPrivateKeyParameters before = decodeXmssMt(key, key.getEncoded());

        XMSSMTSigner signer = new XMSSMTSigner();

        signer.init(true, key);
        signer.update(new byte[]{0x5a}, 0, 1);
        signer.generateSignature();

        XMSSMTPrivateKeyParameters after = (XMSSMTPrivateKeyParameters)signer.getUpdatedPrivateKey();

        assertEquals(before.getIndex() + 1, after.getIndex());
        assertFalse("keys at different indices are not equal", before.equals(after));
        assertFalse("keys at different indices are not equal", after.equals(before));
        assertEquals("a signature must not move the key's bucket",
            before.hashCode(), after.hashCode());
    }

    /**
     * Keys of two key pairs are told apart, and land in different buckets. The two are built from
     * fixed material differing in one field rather than generated, so the hash comparison decides
     * something every run: two random roots differing is not a property a test can assert.
     */
    public void testXmssPublicMaterialDecidesTheBucket()
    {
        XMSSParameters params = new XMSSParameters(HEIGHT, new SHA256Digest());
        int n = params.getTreeDigestSize();

        XMSSPrivateKeyParameters a = new XMSSPrivateKeyParameters.Builder(params)
            .withSecretKeySeed(filled((byte)1, n)).withSecretKeyPRF(filled((byte)2, n))
            .withPublicSeed(filled((byte)3, n)).withRoot(filled((byte)4, n)).build();

        XMSSPrivateKeyParameters b = new XMSSPrivateKeyParameters.Builder(params)
            .withSecretKeySeed(filled((byte)1, n)).withSecretKeyPRF(filled((byte)2, n))
            .withPublicSeed(filled((byte)3, n)).withRoot(filled((byte)5, n)).build();

        assertFalse("keys differing in their root are not equal", a.equals(b));
        assertFalse("the root has to reach the hash", a.hashCode() == b.hashCode());
    }

    public void testXmssMtPublicMaterialDecidesTheBucket()
    {
        XMSSMTParameters params = new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest());
        int n = params.getTreeDigestSize();

        XMSSMTPrivateKeyParameters a = new XMSSMTPrivateKeyParameters.Builder(params)
            .withSecretKeySeed(filled((byte)1, n)).withSecretKeyPRF(filled((byte)2, n))
            .withPublicSeed(filled((byte)3, n)).withRoot(filled((byte)4, n)).build();

        XMSSMTPrivateKeyParameters b = new XMSSMTPrivateKeyParameters.Builder(params)
            .withSecretKeySeed(filled((byte)1, n)).withSecretKeyPRF(filled((byte)2, n))
            .withPublicSeed(filled((byte)3, n)).withRoot(filled((byte)5, n)).build();

        assertFalse("keys differing in their root are not equal", a.equals(b));
        assertFalse("the root has to reach the hash", a.hashCode() == b.hashCode());
    }

    /**
     * The rest of the contract: a key is equal to itself, and to nothing that is not one of these
     * keys. An XMSS key and an XMSS^MT key are never equal, whatever they hold.
     */
    public void testForeignObjects()
    {
        XMSSPrivateKeyParameters xmss = newXmssKey();
        XMSSMTPrivateKeyParameters xmssMt = newXmssMtKey();

        assertEquals(xmss, xmss);
        assertEquals(xmssMt, xmssMt);

        assertFalse(xmss.equals(null));
        assertFalse(xmssMt.equals(null));
        assertFalse(xmss.equals("not a key"));
        assertFalse(xmssMt.equals("not a key"));
        assertFalse(xmss.equals(xmssMt));
        assertFalse(xmssMt.equals(xmss));
    }
}
