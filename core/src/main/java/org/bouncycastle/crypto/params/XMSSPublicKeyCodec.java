package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.signers.xmss.XMSSEngine;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * The wire form an XMSS and an XMSS^MT public key share.
 * <p>
 * RFC 8391 sec. 4.1.7 and sec. 4.2.5 give the two the same shape - root followed by SEED, both n
 * bytes - and NIST SP 800-208 sec. 5 puts a four byte parameter set identifier in front of each,
 * so the encoding differs between the families only in which parameter set the identifier names.
 * The two key classes carried a line for line copy of it each, and had to be hand edited in
 * lockstep whenever it changed; this is the one copy. It stays package private: the classes it
 * serves are the public surface, and the name starts XMSS so that the {@code crypto/params/XMSS*}
 * excludes the jdk1.4 and jdk1.3 Ant builds already carry keep covering it.
 * </p><p>
 * {@link #resolve} is the same argument one level up. A key is built either from an encoding or
 * from the fields themselves, and which of the two it was decides where its parameter set
 * identifier comes from and whether the root and the seed are checked against n or decoded at it -
 * so a rule about how a public key resolves its three fields is a rule about the encoding, and
 * belonged beside it rather than in two constructors that had it word for word.
 * </p>
 */
class XMSSPublicKeyCodec
{
    /**
     * The width of the SP 800-208 parameter set identifier. Zero is not a registered value, so it
     * is what a key written before the identifier existed is given, and a key carrying it is
     * encoded without one.
     */
    private static final int OID_SIZE = 4;

    private final int oid;
    private final byte[] root;
    private final byte[] publicSeed;

    private XMSSPublicKeyCodec(int oid, byte[] root, byte[] publicSeed)
    {
        this.oid = oid;
        this.root = root;
        this.publicSeed = publicSeed;
    }

    /**
     * Read a public key encoding, in either the current form or the pre-RFC one that carries no
     * parameter set identifier. Which one it is is decided by the length, so the length is checked
     * before anything is read out of it.
     *
     * @param publicKey the encoding.
     * @param n         the security parameter of the key's parameter set, in bytes.
     */
    static XMSSPublicKeyCodec decode(byte[] publicKey, int n)
    {
        if (publicKey.length == n + n)
        {
            // pre-rfc final key without OID.
            return new XMSSPublicKeyCodec(0, Arrays.copyOfRange(publicKey, 0, n),
                Arrays.copyOfRange(publicKey, n, n + n));
        }
        if (publicKey.length == OID_SIZE + n + n)
        {
            return new XMSSPublicKeyCodec(Pack.bigEndianToInt(publicKey, 0),
                Arrays.copyOfRange(publicKey, OID_SIZE, OID_SIZE + n),
                Arrays.copyOfRange(publicKey, OID_SIZE + n, OID_SIZE + n + n));
        }

        throw new IllegalArgumentException("public key has wrong size");
    }

    /**
     * The three fields of a public key, from whichever of the two ways its builder was given them.
     *
     * @param publicKey       an encoding to take apart, or null when the fields were set directly.
     * @param n               the security parameter of the key's parameter set, in bytes.
     * @param parameterSetOID the identifier the key's own parameter set carries, which is what a
     *                        key built from fields records; a decoded key keeps the one its
     *                        encoding named, including the zero of a key written before the
     *                        identifier existed.
     * @param root            the root, or null to be allocated at n.
     * @param publicSeed      the seed, or null to be allocated at n.
     */
    static XMSSPublicKeyCodec resolve(byte[] publicKey, int n, int parameterSetOID, byte[] root,
        byte[] publicSeed)
    {
        if (publicKey != null)
        {
            /* import */
            return decode(publicKey, n);
        }

        /* set */
        return new XMSSPublicKeyCodec(parameterSetOID,
            XMSSEngine.validateOrAllocate(root, n, "root"),
            XMSSEngine.validateOrAllocate(publicSeed, n, "publicSeed"));
    }

    /**
     * The encoding of a key holding these fields: oid || root || seed, with the oid omitted when
     * it is zero.
     * <p>
     * The sizes come from the arrays themselves rather than from the parameter set, which is where
     * the two copies took them from while copying by array length - the same number by
     * construction, since both fields are pinned to n before a key can hold them, but two ways of
     * saying it that nothing kept in step.
     * </p>
     */
    static byte[] encode(int oid, byte[] root, byte[] publicSeed)
    {
        /* oid || root || seed */
        int oidSize = (oid != 0) ? OID_SIZE : 0;
        byte[] out = new byte[oidSize + root.length + publicSeed.length];
        int position = 0;

        /* copy oid */
        if (oid != 0)
        {
            Pack.intToBigEndian(oid, out, position);
            position += OID_SIZE;
        }
        /* copy root */
        System.arraycopy(root, 0, out, position, root.length);
        position += root.length;
        /* copy public seed */
        System.arraycopy(publicSeed, 0, out, position, publicSeed.length);

        return out;
    }

    int getOid()
    {
        return oid;
    }

    byte[] getRoot()
    {
        return root;
    }

    byte[] getPublicSeed()
    {
        return publicSeed;
    }
}
