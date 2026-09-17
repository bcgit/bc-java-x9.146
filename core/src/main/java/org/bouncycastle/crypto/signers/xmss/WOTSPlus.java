package org.bouncycastle.crypto.signers.xmss;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.Pack;

/**
 * WOTS+.
 */
final class WOTSPlus
{
    /**
     * The length RFC 8391 sec. 4.1.2 fixes PRF's second argument at - the 32 bytes of an
     * {@link XMSSAddress} encoding, and the width {@link #expandSecretKeySeed} writes an index
     * in.
     */
    private static final int PRF_INDEX_SIZE = 32;

    /**
     * WOTS+ parameters.
     */
    private final WOTSPlusParameters params;
    /**
     * Randomization functions.
     */
    private final KeyedHashFunctions khf;
    /**
     * WOTS+ secret key seed.
     */
    private final byte[] secretKeySeed;
    /**
     * WOTS+ public seed.
     */
    private final byte[] publicSeed;

    /**
     * Constructs a new WOTS+ one-time signature system based on the given WOTS+
     * parameters.
     *
     * @param params Parameters for WOTSPlus object.
     */
    WOTSPlus(WOTSPlusParameters params)
    {
        this.params = params;
        int n = params.getTreeDigestSize();
        khf = new KeyedHashFunctions(params.getTreeDigest(), n);
        secretKeySeed = new byte[n];
        publicSeed = new byte[n];
    }

    /**
     * Import keys to WOTS+ instance.
     *
     * @param secretKeySeed Secret key seed.
     * @param publicSeed    Public seed.
     */
    void importKeys(byte[] secretKeySeed, byte[] publicSeed)
    {
        int n = params.getTreeDigestSize();

        // through the shared check rather than a copy of its message: a20b761bc3 put the one
        // implementation behind XMSSUtil for the specific reason that six copies of it had already
        // drifted into saying two different things about the same mistake, and these two were a
        // plain string literal duplicate of what that check says - findable by grepping the
        // message, but not by looking for the callers of the check that owns it. The size half of
        // it, without the allocate-when-absent branch: an absent seed here is not an optional
        // field left to be filled in, and taking the allocation would import an all-zero one-time
        // key rather than say so.
        XMSSUtil.validateSize(secretKeySeed, n, "secretKeySeed");
        XMSSUtil.validateSize(publicSeed, n, "publicSeed");

        // copy in rather than take the caller's arrays by reference: a caller that keeps its own
        // array could otherwise still change this instance's key material after importing it, and
        // the seeds arrive from a key object that goes on holding them. The destinations are
        // allocated once, in the constructor, and the lengths have just been checked against n, so
        // this costs nothing on the per-leaf walk that calls this for every one-time key in a tree.
        System.arraycopy(secretKeySeed, 0, this.secretKeySeed, 0, this.secretKeySeed.length);
        System.arraycopy(publicSeed, 0, this.publicSeed, 0, this.publicSeed.length);
    }

    /**
     * Zeroize the WOTS+ secret key imported last. The array cleared is this instance's own - the
     * constructor allocates it and {@link #importKeys} copies into it - so this reaches no
     * caller-owned data whatever the caller does with the seed it passed. Called when the private
     * key whose traversal state owns this instance is destroyed; the instance is not usable
     * afterwards without a fresh import.
     */
    void clearSecretKeySeed()
    {
        Arrays.clear(secretKeySeed);
    }

    /**
     * Creates a signature for the n-byte messageDigest.
     *
     * @param messageDigest  Digest to sign.
     * @param address        the 32-byte encoding of the OTS hash address this one-time key is at.
     *                       The caller owns it and has set the OTS address word, which is what
     *                       names the key; the loop below writes the chain address word of it and
     *                       {@link #chain} the two after that.
     * @return the len n-byte blocks of the signature, a fresh array of fresh blocks that the
     *         caller takes over.
     */
    byte[][] sign(byte[] messageDigest, byte[] address)
    {
        List<Integer> baseWMessage = baseWMessageWithChecksum(messageDigest);

        /* create signature */
        int n = params.getTreeDigestSize();
        byte[][] signature = new byte[params.getLen()][];
        // the caller's encoding serves the len chains, the loop below stepping the one word they
        // differ in; chain() writes the other two as it goes and says there why that does not
        // carry between chains. One set of working buffers serves them on the same terms: the
        // index PRF is applied to, the chain's starting secret key, and the pair chain() steps
        // over. Every one of them is written before it is read on each chain, and none of them is
        // what chain() returns - see there and expandSecretKeySeed below.
        byte[] indexBuffer = new byte[PRF_INDEX_SIZE];
        byte[] startHash = new byte[n];
        byte[] key = new byte[n];
        byte[] tmpMasked = new byte[n];
        for (int i = 0; i < params.getLen(); i++)
        {
            Pack.intToBigEndian(i, address, XMSSAddress.CHAIN_ADDRESS_OFFSET);
            expandSecretKeySeed(i, indexBuffer, startHash);
            signature[i] = chain(startHash, 0, baseWMessage.get(i), address, key, tmpMasked);
        }
        return signature;
    }

    /**
     * Calculates a public key based on digest and signature.
     *
     * @param messageDigest  The digest that was signed.
     * @param signature      the len n-byte blocks of the signature on that digest, which this
     *                       method reads and never writes.
     * @param address        the 32-byte encoding of the OTS hash address the signing key was at;
     *                       written as in {@link #sign}.
     * @return WOTS+ public key derived from digest and signature.
     */
    WOTSPlusPublicKeyParameters getPublicKeyFromSignature(byte[] messageDigest, byte[][] signature, byte[] address)
    {
        List<Integer> baseWMessage = baseWMessageWithChecksum(messageDigest);

        //
        // The signature's blocks are chained from where they lie rather than out of a copy of
        // the whole signature. The carrier this used to take deep-copied all len of them on the
        // way out, and that copy had been made inside the loop only to index one block out, which
        // made a verification len^2 block copies where it needs none: 4489 for the SHA-256
        // parameter sets, 17161 for SHA-512, and that again for every layer of a hypertree on the
        // XMSS^MT side. Nothing escapes by reading them in place: chain() only reads the starting
        // value it is given and returns an array of its own however many steps it takes - see
        // that method.
        //
        int n = params.getTreeDigestSize();
        byte[][] publicKey = new byte[params.getLen()][];
        // the caller's encoding serves the len chains, the loop below stepping the one word they
        // differ in; chain() writes the other two as it goes and says there why that does not
        // carry between chains. One pair of working buffers for chain() to step over serves all
        // len of them likewise.
        byte[] key = new byte[n];
        byte[] tmpMasked = new byte[n];
        for (int i = 0; i < params.getLen(); i++)
        {
            Pack.intToBigEndian(i, address, XMSSAddress.CHAIN_ADDRESS_OFFSET);
            publicKey[i] = chain(signature[i], baseWMessage.get(i),
                WOTSPlusParameters.WINTERNITZ_PARAMETER - 1 - baseWMessage.get(i), address, key, tmpMasked);
        }
        return new WOTSPlusPublicKeyParameters(publicKey);
    }

    /**
     * Computes an iteration of F on an n-byte input using outputs of PRF.
     *
     * @param startHash      Starting point. Read and never written, and never handed back, so the
     *                       caller may reuse one buffer for it across the chains of a key.
     * @param startIndex     Start index.
     * @param steps          Steps to take.
     * @param address        the 32-byte encoding of this chain's OTS hash address. The caller owns
     *                       it and has set the chain address word; this method writes the hash
     *                       address and key-and-mask words of it as it steps.
     * @param key            an n-byte working buffer the caller owns. Written and read within a
     *                       step, meaningless between calls.
     * @param tmpMasked      a second n-byte working buffer on the same terms. It must be neither
     *                       {@code key} nor {@code startHash}.
     * @return a freshly allocated n-byte array holding the value obtained by iterating F for steps
     * times on input startHash, using the outputs of PRF.
     */
    private byte[] chain(byte[] startHash, int startIndex, int steps, byte[] address, byte[] key, byte[] tmpMasked)
    {
        int n = params.getTreeDigestSize();
        if (startHash.length != n)
        {
            throw new IllegalArgumentException("startHash needs to be " + n + "bytes");
        }
        if ((startIndex + steps) > WOTSPlusParameters.WINTERNITZ_PARAMETER - 1)
        {
            throw new IllegalArgumentException("max chain length must not be greater than w");
        }

        //
        // Iteratively, over one encoding of the address and one buffer per value a step produces.
        //
        // The two words a chain step moves are the hash address and the key-and-mask, PRF reads the
        // address as the 32 bytes it is, and nothing here reads the incoming values of either word -
        // withHashAddress() overwrote both at every step - so what the recursion expressed as two
        // rebuilt addresses and two fresh toByteArray() copies per step is three int writes into one
        // encoding. That encoding is now the caller's, taken once for the len chains of a key rather
        // than once per chain, and this method writes into it: the caller sets the chain address
        // before each call, and the two words below are written at the top of every step, so what a
        // previous chain left in them is overwritten before anything is hashed. The steps == 0
        // return above writes nothing into it at all, which is the same statement the other way
        // round - it hashes nothing either. Chained from the front rather than unwound from the
        // back, which is the same sequence of hash addresses - startIndex, then upwards - in the
        // same order.
        //
        // Of the three n-byte results a step produces, two are working values and one is the
        // answer. The two are the caller's arrays, one pair for the len chains of a key rather
        // than a pair per chain, because nothing in either survives the step that writes it: PRF
        // fills all n bytes of key, and fills all n of tmpMasked before xorTo folds tmp into it,
        // so whatever the previous step - or the previous chain, or the previous call - left in
        // them is gone before it is read. The bitmask is thereby produced straight into the array
        // it is masked in, where xorTo turns it into the masked value.
        //
        // out is this method's own and is what it returns, one array per call: the caller collects
        // the len returns in a byte[][] that is handed on as a signature, or becomes a
        // WOTSPlusPublicKeyParameters, as it stands, so one shared across a key's chains would
        // leave every entry holding the last chain's value. Within the chain it is reused - F's
        // result goes into out, which the next step reads as tmp and folds into tmpMasked before F
        // writes out again, so out's previous contents are dead by the time they are overwritten,
        // and that reuse rests on this rather than on how coreDigest orders its own work.
        //
        // A zero-step chain copies startHash into out rather than handing startHash itself back.
        // That is what lets a caller reuse one startHash buffer across the len chains as well: the
        // return is then an array this method has just made whatever steps is, so no caller has to
        // know that at one particular digit value its buffer would instead escape into a signature
        // or a public key. It costs the allocation that expandSecretKeySeed used to make for that
        // same chain, and it is the only case in which anything is copied here.
        //
        byte[] out = new byte[n];
        if (steps == 0)
        {
            System.arraycopy(startHash, 0, out, 0, n);
            return out;
        }

        byte[] tmp = startHash;
        for (int i = 0; i != steps; i++)
        {
            Pack.intToBigEndian(startIndex + i, address, XMSSAddress.HASH_ADDRESS_OFFSET);

            Pack.intToBigEndian(0, address, XMSSAddress.KEY_AND_MASK_OFFSET);
            khf.PRF(publicSeed, address, key);

            Pack.intToBigEndian(1, address, XMSSAddress.KEY_AND_MASK_OFFSET);
            khf.PRF(publicSeed, address, tmpMasked);

            Bytes.xorTo(n, tmp, tmpMasked);
            khf.F(key, tmpMasked, out);
            tmp = out;
        }
        return out;
    }

    /**
     * The len = len1 + len2 base-w digits WOTS+ signs: the digest's own len1 digits followed by
     * the len2 digits of their checksum (RFC 8391 sec. 3.1.1 algorithm 1, steps 1-3). Signing and
     * public-key recovery both need exactly this sequence - one to sign it, the other to verify
     * against it - so it is derived once here rather than in each caller.
     */
    private List<Integer> baseWMessageWithChecksum(byte[] messageDigest)
    {
        List<Integer> baseWMessage = convertToBaseW(messageDigest, WOTSPlusParameters.WINTERNITZ_PARAMETER, params.getLen1());

        /* create checksum */
        int checksum = 0;
        for (int i = 0; i < params.getLen1(); i++)
        {
            checksum += WOTSPlusParameters.WINTERNITZ_PARAMETER - 1 - baseWMessage.get(i);
        }
        checksum <<= (8 - ((params.getLen2() * XMSSUtil.log2(WOTSPlusParameters.WINTERNITZ_PARAMETER)) % 8));
        int len2Bytes = (int)Math
            .ceil((double)(params.getLen2() * XMSSUtil.log2(WOTSPlusParameters.WINTERNITZ_PARAMETER)) / 8);
        List<Integer> baseWChecksum = convertToBaseW(XMSSUtil.toBytesBigEndian(checksum, len2Bytes),
            WOTSPlusParameters.WINTERNITZ_PARAMETER, params.getLen2());

        /* msg || checksum */
        baseWMessage.addAll(baseWChecksum);

        return baseWMessage;
    }

    /**
     * Obtain base w values from Input.
     *
     * @param messageDigest Input data.
     * @param w             Base.
     * @param outLength     Length of output.
     * @return outLength-length list of base w integers.
     */
    private List<Integer> convertToBaseW(byte[] messageDigest, int w, int outLength)
    {
        if (w != 4 && w != 16)
        {
            throw new IllegalArgumentException("w needs to be 4 or 16");
        }
        int logW = XMSSUtil.log2(w);
        if (outLength > ((8 * messageDigest.length) / logW))
        {
            throw new IllegalArgumentException("outLength too big");
        }

        ArrayList<Integer> res = new ArrayList<Integer>();
        for (int i = 0; i < messageDigest.length; i++)
        {
            for (int j = 8 - logW; j >= 0; j -= logW)
            {
                res.add((messageDigest[i] >> j) & (w - 1));
                if (res.size() == outLength)
                {
                    return res;
                }
            }
        }
        return res;
    }

    /**
     * Derive WOTS+ secret key for specific index as in XMSS ref impl Andreas
     * Huelsing.
     *
     * @param secretSeed     the XMSS private key's secret seed, SK_SEED of RFC 8391 sec. 4.1.3 -
     *                       the seed a one-time key is derived from, and not the derived seed this
     *                       instance holds under the near enough same name. The two are the input
     *                       and the output of this one derivation: every caller hands the result
     *                       straight to {@link #importKeys(byte[], byte[])} on the same object.
     * @param address    the 32-byte encoding of the OTS hash address this one-time key is at. The
     *                   caller owns it and has set the OTS address word; only that, the layer
     *                   address and the tree address take part in the derivation, and this method
     *                   clears the three words below them in place - see below.
     * @return WOTS+ secret key at index.
     */
    byte[] getWOTSPlusSecretKey(byte[] secretSeed, byte[] address)
    {
        // The address this is the PRF of is the caller's with its chain address, hash address and
        // key-and-mask cleared, so the zeros go into the caller's encoding where the address would
        // otherwise be rebuilt without them. That the three are cleared rather than assumed absent
        // is what lets one encoding serve a whole leaf walk: getPublicKey() and sign() below leave
        // the last chain's chain address, hash address and key-and-mask in the encoding they are
        // handed, and the next leaf's one-time key is derived from that same encoding.
        Pack.intToBigEndian(0, address, XMSSAddress.CHAIN_ADDRESS_OFFSET);
        Pack.intToBigEndian(0, address, XMSSAddress.HASH_ADDRESS_OFFSET);
        Pack.intToBigEndian(0, address, XMSSAddress.KEY_AND_MASK_OFFSET);
        return khf.PRF(secretSeed, address);
    }

    /**
     * Derive private key at index from secret key seed.
     *
     * @param index       Index.
     * @param indexBuffer a PRF_INDEX_SIZE-byte buffer the caller owns, which this writes
     *                    toByte(index, 32) into. It reaches only the last eight bytes, so one
     *                    buffer serves every index of a key: the rest are the zeros a fresh array
     *                    already carries and nothing here disturbs them.
     * @param out         an n-byte buffer the private key at index is written into.
     */
    private void expandSecretKeySeed(int index, byte[] indexBuffer, byte[] out)
    {
        if (index < 0 || index >= params.getLen())
        {
            throw new IllegalArgumentException("index out of bounds");
        }
        // toByte(index, 32) of RFC 8391 sec. 2.4, written in place rather than into an array
        // allocated per chain. This is the same encoding XMSSUtil.toBytesBigEndian(index, 32)
        // built - the low eight bytes of the value at the end of a 32-byte array, the other 24
        // left zero - and index is non-negative and below len, so the top four of those eight are
        // zero as well.
        Pack.longToBigEndian_Low(index, indexBuffer, PRF_INDEX_SIZE - 8, 8);
        khf.PRF(secretKeySeed, indexBuffer, out);
    }

    /**
     * Getter parameters.
     *
     * @return params.
     */
    WOTSPlusParameters getParams()
    {
        return params;
    }

    /**
     * Getter keyed hash functions.
     *
     * @return keyed hash functions.
     */
    KeyedHashFunctions getKhf()
    {
        return khf;
    }

    /**
     * This instance's public seed, by reference rather than through a defensive copy.
     * <p>
     * The convention a clone here would be keeping is that a key or an IV is copied as it crosses
     * the library's boundary, and importKeys() above still copies in for exactly that reason. This
     * does not cross it: WOTSPlus is package-private, so no code outside
     * org.bouncycastle.crypto.signers.xmss can name the type, let alone call this, and the one
     * caller in the package - XMSSNodeUtil.randomizeHash - passes what it gets to PRF as a key and
     * does nothing else with it. The copy this replaces was made once per interior node of every
     * tree walked, 68607 of them in an h=10 key generation.
     * </p>
     *
     * @return public seed.
     */
    byte[] getPublicSeed()
    {
        return publicSeed;
    }

    /**
     * Calculates a new public key based on the state of secretKeySeed,
     * publicSeed and the address given.
     *
     * @param address the 32-byte encoding of the OTS hash address this one-time key is at; written
     *                as in {@link #sign}.
     * @return WOTS+ public key.
     */
    WOTSPlusPublicKeyParameters getPublicKey(byte[] address)
    {
        int n = params.getTreeDigestSize();
        byte[][] publicKey = new byte[params.getLen()][];
        /* derive public key from secretKeySeed */
        // the caller's encoding serves the len chains, the loop below stepping the one word they
        // differ in; chain() writes the other two as it goes and says there why that does not
        // carry between chains. One set of working buffers serves them, as in sign() above - four
        // arrays for a leaf's whole public key rather than four per chain of it. This is the tree
        // walk's inner loop:
        // an h = 10 SHA-256 key generation takes 68608 chains over 1024 leaves, and had been
        // allocating the index, the starting secret key and chain's pair for every one of them.
        byte[] indexBuffer = new byte[PRF_INDEX_SIZE];
        byte[] startHash = new byte[n];
        byte[] key = new byte[n];
        byte[] tmpMasked = new byte[n];
        for (int i = 0; i < params.getLen(); i++)
        {
            Pack.intToBigEndian(i, address, XMSSAddress.CHAIN_ADDRESS_OFFSET);
            expandSecretKeySeed(i, indexBuffer, startHash);
            publicKey[i] = chain(startHash, 0, WOTSPlusParameters.WINTERNITZ_PARAMETER - 1, address, key, tmpMasked);
        }
        return new WOTSPlusPublicKeyParameters(publicKey);
    }
}
