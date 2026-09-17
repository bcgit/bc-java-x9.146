package org.bouncycastle.crypto.signers.xmss;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.XMSSKeyPairGenerator;
import org.bouncycastle.crypto.generators.XMSSMTKeyPairGenerator;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.XMSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.signers.XMSSMTSigner;
import org.bouncycastle.crypto.signers.XMSSSigner;

/**
 * init() takes a key wrapped in ParametersWithRandom on either side. The signing side needs it
 * because XMSSSignatureSpi.engineInitSign(PrivateKey, SecureRandom) wraps whatever key it is
 * handed; the verification side has no such caller inside BC, but a caller driving the lightweight
 * API can wrap either key, and LMSSigner.init unwraps before it branches. The random is discarded
 * in both cases, so a signature taken through the wrapper is the one the bare key would have made.
 */
public class SignerInitParametersTests
    extends TestCase
{
    private static final int HEIGHT = 4;
    private static final int LAYERS = 2;

    public void testXmssTakesAWrappedKeyOnEitherSide()
    {
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(new XMSSParameters(HEIGHT, new SHA256Digest()), new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        XMSSSigner signer = new XMSSSigner();

        signer.init(true, new ParametersWithRandom(kp.getPrivate(), new SecureRandom()));
        signer.update(new byte[]{ 1, 2, 3 }, 0, 3);

        byte[] signature = signer.generateSignature();

        XMSSSigner verifier = new XMSSSigner();

        verifier.init(false, new ParametersWithRandom(kp.getPublic(), new SecureRandom()));
        verifier.update(new byte[]{ 1, 2, 3 }, 0, 3);

        assertTrue(verifier.verifySignature(signature));

        // the bare key still initialises, and says the wrapper changed nothing about the signature
        verifier.init(false, kp.getPublic());
        verifier.update(new byte[]{ 1, 2, 3 }, 0, 3);

        assertTrue(verifier.verifySignature(signature));
    }

    public void testXmssMtTakesAWrappedKeyOnEitherSide()
    {
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(
            new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest()), new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        XMSSMTSigner signer = new XMSSMTSigner();

        signer.init(true, new ParametersWithRandom(kp.getPrivate(), new SecureRandom()));
        signer.update(new byte[]{ 1, 2, 3 }, 0, 3);

        byte[] signature = signer.generateSignature();

        XMSSMTSigner verifier = new XMSSMTSigner();

        verifier.init(false, new ParametersWithRandom(kp.getPublic(), new SecureRandom()));
        verifier.update(new byte[]{ 1, 2, 3 }, 0, 3);

        assertTrue(verifier.verifySignature(signature));

        // the bare key still initialises, and says the wrapper changed nothing about the signature
        verifier.init(false, kp.getPublic());
        verifier.update(new byte[]{ 1, 2, 3 }, 0, 3);

        assertTrue(verifier.verifySignature(signature));
    }
}
