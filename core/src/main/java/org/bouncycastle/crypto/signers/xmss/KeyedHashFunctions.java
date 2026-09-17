package org.bouncycastle.crypto.signers.xmss;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Xof;

/**
 * Crypto functions for XMSS: the keyed hash functions F, H, H_msg and PRF of RFC 8391 sec. 4.1.2.
 * <p>
 * Each of them hashes <code>toByte(i, n) || key || in</code> under its own domain separator i, and
 * that concatenation carries no length prefix - so it is unambiguous only because every argument has
 * the fixed length RFC 8391 sec. 4.1.2 gives it: F an n-byte key and an n-byte string, H an n-byte
 * key and a 2n-byte string, H_msg a 3n-byte key and a message of any length, PRF an n-byte key and a
 * 32-byte index, where n is the digestSize this instance was built with.
 * <p>
 * Those lengths are guaranteed by the call sites rather than checked here. This class is
 * package-private and built in exactly one place - {@link WOTSPlus}, with n taken from the owning
 * key's parameters - so the set of callers is closed: every key argument is a return value of one of
 * these functions, a {@code new byte[n]} field of WOTSPlus, or key material one of the key parameter
 * classes has already pinned to n; every in is freshly allocated at the size wanted; every PRF
 * address is an {@link XMSSAddress} encoding or a toBytesBigEndian(x, 32), both always 32
 * bytes. A new call site has to keep that true: a wrong length is not rejected here, it silently
 * hashes to something else.
 * <p>
 * Each of them comes in the form its callers want rather than in both: F and H write into an array
 * the caller owns, PRF does either, H_msg only allocates. That follows the tree walk - an h=10 key
 * generation takes 1029120 WOTS+ chain steps and 68607 interior nodes, and every F, H and bitmask
 * on those two paths is read once into a buffer that already exists, while the PRF results that
 * are not - a one-time key's seed, a chain's starting secret key, a signature's randomness - are
 * each somebody's return value. A form nothing calls is not kept for symmetry.
 * <p>
 * The buffer forms write digestSize bytes at the offset they are given, and take it, in the same
 * way as everything above, that the buffer holds that many from there; a short one fails inside
 * the digest's own doFinal or the arraycopy rather than here, which is at least loud. They are not
 * a second implementation of anything: coreDigest's body is the buffer form, and the allocating
 * one is that form into an array it has just made, so what gets hashed cannot depend on which of
 * the two a call site picked.
 * <p>
 * coreDigest also takes it that digestSize is at most the underlying digest's own output size, which
 * likewise nothing checks - the admissible (digest, n) pairs are fixed by {@link WOTSPlusOid}, and
 * one breaking that would leave the tail of the result zero rather than throw. The same bound is
 * what keeps digestSize inside the toByte table below, whose width is the largest n that fixes;
 * one above it fails there instead, on the offset, which is at least loud.
 */
final class KeyedHashFunctions
{
    /**
     * The largest tree digest size {@link WOTSPlusOid} admits, that being SHA-512's and SHAKE256's
     * 64; the others are 32 and, for the two SP 800-208 parameter sets, 24.
     */
    private static final int MAX_TREE_DIGEST_SIZE = 64;

    /**
     * toByte(i, n) for the four domain separators, as the constants they are rather than as
     * something rebuilt per hash: each is n - 1 zero bytes followed by i, because i is 0..3. One
     * table serves every n, because toByte(i, n) is then the last n bytes of
     * toByte(i, MAX_TREE_DIGEST_SIZE) - so coreDigest hashes that tail in place.
     * <p>
     * coreDigest had been calling XMSSUtil.toBytesBigEndian(i, n) instead, which is an n-byte
     * array plus an eight-byte write of seven zeros and one value byte, on every F, H, H_msg and
     * PRF - one per chain step of every leaf's len chains, plus the L-tree and the tree hash above
     * them, so a key generation at h=10 made millions. The table is only ever read, so sharing it
     * says nothing about threads.
     */
    private static final byte[][] TO_BYTE = new byte[4][MAX_TREE_DIGEST_SIZE];

    static
    {
        for (int i = 0; i != TO_BYTE.length; i++)
        {
            TO_BYTE[i][MAX_TREE_DIGEST_SIZE - 1] = (byte)i;
        }
    }

    private final Digest digest;
    private final int digestSize;

    KeyedHashFunctions(ASN1ObjectIdentifier treeDigest, int digestSize)
    {
        this.digest = DigestUtil.getDigest(treeDigest);
        this.digestSize = digestSize;
    }

    private byte[] coreDigest(int fixedValue, byte[] key, byte[] index)
    {
        byte[] out = new byte[digestSize];
        coreDigest(fixedValue, key, index, out, 0);
        return out;
    }

    private void coreDigest(int fixedValue, byte[] key, byte[] index, byte[] out, int outOff)
    {
        /* fill first n byte of out buffer */
        digest.update(TO_BYTE[fixedValue], MAX_TREE_DIGEST_SIZE - digestSize, digestSize);
        /* add key */
        digest.update(key, 0, key.length);
        /* add index */
        digest.update(index, 0, index.length);

        if (digest instanceof Xof)
        {
            ((Xof)digest).doFinal(out, outOff, digestSize);
        }
        else if (digestSize < digest.getDigestSize())
        {
            byte[] full = new byte[digest.getDigestSize()];
            digest.doFinal(full, 0);
            System.arraycopy(full, 0, out, outOff, digestSize);
        }
        else
        {
            digest.doFinal(out, outOff);
        }
    }

    void F(byte[] key, byte[] in, byte[] out)
    {
        coreDigest(0, key, in, out, 0);
    }

    void H(byte[] key, byte[] in, byte[] out)
    {
        coreDigest(1, key, in, out, 0);
    }

    byte[] HMsg(byte[] key, byte[] in)
    {
        return coreDigest(2, key, in);
    }

    byte[] PRF(byte[] key, byte[] address)
    {
        return coreDigest(3, key, address);
    }

    void PRF(byte[] key, byte[] address, byte[] out)
    {
        coreDigest(3, key, address, out, 0);
    }

    void PRF(byte[] key, byte[] address, byte[] out, int outOff)
    {
        coreDigest(3, key, address, out, outOff);
    }
}
