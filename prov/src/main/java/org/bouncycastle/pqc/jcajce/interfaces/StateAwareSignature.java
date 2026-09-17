package org.bouncycastle.pqc.jcajce.interfaces;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;

/**
 * This interface is implemented by Signature classes returned by the PQC provider where the signature
 * algorithm is one where the private key is updated for each signature generated. Examples of these
 * are algorithms such as GMSS, XMSS, and XMSS^MT.
 * @deprecated it's better to avoid this and use extractKeyShard methods where possible.
 */
public interface StateAwareSignature
{
    void initVerify(PublicKey publicKey)
        throws InvalidKeyException;

    void initVerify(Certificate certificate)
        throws InvalidKeyException;

    void initSign(PrivateKey privateKey)
        throws InvalidKeyException;

    void initSign(PrivateKey privateKey, SecureRandom random)
        throws InvalidKeyException;

    byte[] sign()
        throws SignatureException;

    int sign(byte[] outbuf, int offset, int len)
        throws SignatureException;

    boolean verify(byte[] signature)
        throws SignatureException;

    boolean verify(byte[] signature, int offset, int length)
        throws SignatureException;

    void update(byte b)
        throws SignatureException;

    void update(byte[] data)
        throws SignatureException;

    void update(byte[] data, int off, int len)
        throws SignatureException;

    void update(ByteBuffer data)
        throws SignatureException;

    String getAlgorithm();

    /**
     * Return true if this Signature object can be used for signing. False otherwise.
     *
     * @return true if we are capable of making signatures.
     */
    boolean isSigningCapable();

    /**
     * Return the current version of the private key with the updated state.
     * <p>
     * <b>Note:</b> what this leaves behind depends on whether a signature has been generated since
     * initSign(). After one, the key handed back is the key that signature spent and the Signature
     * object keeps nothing: it cannot generate another signature without a further call to
     * initSign(), and a second call to this method throws. Before one, the object keeps a single
     * usage to sign with and hands back the rest, so it remains capable of exactly one signature -
     * that is the whole point of collecting first, since the state a caller is obliged to persist
     * is then durable before the one-time key covering it is spent. A second call in that state
     * hands back the same key again rather than a further shard.
     * </p><p>
     * Collecting first and then signing joins the two: the signature spends the one usage the
     * object kept, and a collection after it throws rather than handing that spent shard over.
     * Everything the caller has to store it was given by the first collection, and the shard adds
     * nothing to it - so a caller that collects in a finally beside an explicit collection is
     * refused instead of overwriting the remainder with a key reporting nothing remaining.
     * </p><p>
     * The key that comes back may report no usages remaining - a Signature object initialised on a
     * spent key still has state its caller has to store - so a non-null return is not on its own a
     * statement that anything is left to sign with. {@link #isSigningCapable()} is what answers
     * that, and the two do differ in that case.
     * </p>
     * @return an updated private key object, which can be used for later signature generation.
     */
   PrivateKey getUpdatedPrivateKey();
}
