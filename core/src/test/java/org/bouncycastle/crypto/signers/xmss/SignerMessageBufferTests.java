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
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.signers.XMSSMTSigner;
import org.bouncycastle.crypto.signers.XMSSSigner;

/**
 * init() starts a fresh operation, so a message absorbed through update() before it must not
 * survive into the new one. A signer reused across operations would otherwise sign or verify the
 * leftover bytes concatenated with the ones the caller actually presented - and on the signing
 * side it would spend a one-time key doing so.
 */
public class SignerMessageBufferTests
    extends TestCase
{
    private static final int HEIGHT = 4;
    private static final int LAYERS = 2;

    private static final byte[] LEFTOVER = new byte[]{ (byte)0xde, (byte)0xad, (byte)0xbe, (byte)0xef };
    private static final byte[] MESSAGE = new byte[]{ 1, 2, 3, 4, 5 };

    private AsymmetricCipherKeyPair xmssKeyPair()
    {
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(new XMSSParameters(HEIGHT, new SHA256Digest()), new SecureRandom()));

        return kpg.generateKeyPair();
    }

    private AsymmetricCipherKeyPair xmssMTKeyPair()
    {
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(
            new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest()), new SecureRandom()));

        return kpg.generateKeyPair();
    }

    private boolean verifies(XMSSSigner verifier, AsymmetricCipherKeyPair kp, byte[] message, byte[] signature)
    {
        verifier.init(false, kp.getPublic());
        verifier.update(message, 0, message.length);

        return verifier.verifySignature(signature);
    }

    private boolean verifies(XMSSMTSigner verifier, AsymmetricCipherKeyPair kp, byte[] message, byte[] signature)
    {
        verifier.init(false, kp.getPublic());
        verifier.update(message, 0, message.length);

        return verifier.verifySignature(signature);
    }

    /**
     * Bytes absorbed after one signing init are discarded by the next one, so the signature covers
     * the message presented after it and nothing else.
     */
    public void testInitDiscardsBufferedMessageBeforeSigning()
    {
        AsymmetricCipherKeyPair kp = xmssKeyPair();
        XMSSSigner signer = new XMSSSigner();

        signer.init(true, kp.getPrivate());
        signer.update(LEFTOVER, 0, LEFTOVER.length);

        signer.init(true, kp.getPrivate());
        signer.update(MESSAGE, 0, MESSAGE.length);

        assertTrue(verifies(new XMSSSigner(), kp, MESSAGE, signer.generateSignature()));

        AsymmetricCipherKeyPair mtKp = xmssMTKeyPair();
        XMSSMTSigner mtSigner = new XMSSMTSigner();

        mtSigner.init(true, mtKp.getPrivate());
        mtSigner.update(LEFTOVER, 0, LEFTOVER.length);

        mtSigner.init(true, mtKp.getPrivate());
        mtSigner.update(MESSAGE, 0, MESSAGE.length);

        assertTrue(verifies(new XMSSMTSigner(), mtKp, MESSAGE, mtSigner.generateSignature()));
    }

    /**
     * The same on the verification side: an abandoned verification leaves nothing behind for the
     * next one, which would otherwise reject a perfectly good signature.
     */
    public void testInitDiscardsBufferedMessageBeforeVerifying()
    {
        AsymmetricCipherKeyPair kp = xmssKeyPair();
        XMSSSigner signer = new XMSSSigner();

        signer.init(true, kp.getPrivate());
        signer.update(MESSAGE, 0, MESSAGE.length);

        byte[] signature = signer.generateSignature();

        XMSSSigner verifier = new XMSSSigner();

        verifier.init(false, kp.getPublic());
        verifier.update(LEFTOVER, 0, LEFTOVER.length);

        assertTrue(verifies(verifier, kp, MESSAGE, signature));

        AsymmetricCipherKeyPair mtKp = xmssMTKeyPair();
        XMSSMTSigner mtSigner = new XMSSMTSigner();

        mtSigner.init(true, mtKp.getPrivate());
        mtSigner.update(MESSAGE, 0, MESSAGE.length);

        byte[] mtSignature = mtSigner.generateSignature();

        XMSSMTSigner mtVerifier = new XMSSMTSigner();

        mtVerifier.init(false, mtKp.getPublic());
        mtVerifier.update(LEFTOVER, 0, LEFTOVER.length);

        assertTrue(verifies(mtVerifier, mtKp, MESSAGE, mtSignature));
    }

    /**
     * The dangerous direction: bytes absorbed while verifying must not be carried into a signature.
     * A signer that did so would spend a one-time key on a message its caller never presented.
     */
    public void testInitDiscardsBufferedMessageAcrossModeChange()
    {
        AsymmetricCipherKeyPair kp = xmssKeyPair();
        XMSSSigner signer = new XMSSSigner();

        signer.init(false, kp.getPublic());
        signer.update(LEFTOVER, 0, LEFTOVER.length);

        signer.init(true, kp.getPrivate());
        signer.update(MESSAGE, 0, MESSAGE.length);

        assertTrue(verifies(new XMSSSigner(), kp, MESSAGE, signer.generateSignature()));

        AsymmetricCipherKeyPair mtKp = xmssMTKeyPair();
        XMSSMTSigner mtSigner = new XMSSMTSigner();

        mtSigner.init(false, mtKp.getPublic());
        mtSigner.update(LEFTOVER, 0, LEFTOVER.length);

        mtSigner.init(true, mtKp.getPrivate());
        mtSigner.update(MESSAGE, 0, MESSAGE.length);

        assertTrue(verifies(new XMSSMTSigner(), mtKp, MESSAGE, mtSigner.generateSignature()));
    }

    /**
     * The compatibility half: init() clearing the buffer must not disturb the ordinary case, where
     * a signer is initialised once and the message arrives afterwards in several updates.
     */
    public void testMessageAbsorbedAfterInitIsSigned()
    {
        AsymmetricCipherKeyPair kp = xmssKeyPair();
        XMSSSigner signer = new XMSSSigner();

        signer.init(true, kp.getPrivate());
        signer.update(MESSAGE[0]);
        signer.update(MESSAGE, 1, MESSAGE.length - 1);

        assertTrue(verifies(new XMSSSigner(), kp, MESSAGE, signer.generateSignature()));

        AsymmetricCipherKeyPair mtKp = xmssMTKeyPair();
        XMSSMTSigner mtSigner = new XMSSMTSigner();

        mtSigner.init(true, mtKp.getPrivate());
        mtSigner.update(MESSAGE[0]);
        mtSigner.update(MESSAGE, 1, MESSAGE.length - 1);

        assertTrue(verifies(new XMSSMTSigner(), mtKp, MESSAGE, mtSigner.generateSignature()));
    }
}
