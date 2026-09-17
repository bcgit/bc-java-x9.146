package org.bouncycastle.crypto.params;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.signers.xmss.XMSSEngine;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * The wire form an XMSS and an XMSS^MT private key share.
 * <p>
 * Neither family's private key is a standardised encoding - RFC 8391 sec. 4.1.3 and sec. 4.2.2
 * describe what a private key holds and leave how it is stored to the implementation, and NIST
 * SP 800-208 sec. 6 says only that the traversal state has to be stored with it - so this is BC's
 * own layout, and both families were written in it independently:
 * </p>
 * <pre>
 *     index || secretKeySeed || secretKeyPRF || publicSeed || root || BDS traversal state
 * </pre>
 * <p>
 * The four seed and root fields are n bytes each and the traversal state is variable length and
 * last, so only the head is fixed and only the head can be length checked. The two key classes
 * carried a line for line copy of all of that each, on both sides - the decoding constructor and
 * {@code toByteArray()} - so one layout was written out four times and had to be hand edited in
 * lockstep. This is the one copy, as {@link XMSSPublicKeyCodec} is for the public halves.
 * </p><p>
 * What actually differs between the families is one number: the width of the index field. Every
 * other difference between the four copies was incidental - the index read back as a signed int on
 * one side and as an unsigned long on the other, the length check spelled the same way twice - and
 * is gone. The width is named by {@link #XMSS_INDEX_SIZE} and {@link #mtIndexSize(int)}, which is
 * where a question about what the field can hold is asked.
 * </p><p>
 * The same two key classes then wrote out one equals() and one hashCode() each, again line for
 * line the same, over the same fields in the same order - so those are here too, as
 * {@link #fieldsEqual} over a {@link Fields} snapshot and {@link #stateEqual} over a {@link State}
 * one, with {@link #hashCode(ASN1ObjectIdentifier, byte[], byte[])} beside them. What is left in
 * each key class is the snapshot of its own fields, taken under its own monitor, and the typed
 * call that encodes its own traversal state - a BDS on one side and a BDSStateMap on the other,
 * which is the whole of what the two families do not share.
 * </p><p>
 * Package private, like the public codec beside it: the classes it serves are the public surface.
 * The name starts XMSS so that the {@code crypto/params/XMSS*} excludes the jdk1.4 and jdk1.3 Ant
 * builds already carry keep covering it.
 * </p>
 */
class XMSSPrivateKeyCodec
{
    /**
     * The width of an XMSS index field, four bytes whatever the tree height.
     * <p>
     * It always suffices: {@link XMSSParameters#MAX_HEIGHT} is 30, so the largest index a key can
     * hold - 2^h, the position an exhausted key sits at, one past its last leaf - is 2^30, and
     * reads back the same whether the four bytes are taken as a signed int or an unsigned long.
     * </p>
     */
    static final int XMSS_INDEX_SIZE = 4;

    private final long index;
    private final byte[] secretKeySeed;
    private final byte[] secretKeyPRF;
    private final byte[] publicSeed;
    private final byte[] root;
    private final byte[] bdsState;

    private XMSSPrivateKeyCodec(long index, byte[] secretKeySeed, byte[] secretKeyPRF,
        byte[] publicSeed, byte[] root, byte[] bdsState)
    {
        this.index = index;
        this.secretKeySeed = secretKeySeed;
        this.secretKeyPRF = secretKeyPRF;
        this.publicSeed = publicSeed;
        this.root = root;
        this.bdsState = bdsState;
    }

    /**
     * The width of an XMSS^MT index field, the fewest whole bytes that hold a leaf index of a tree
     * of this total height.
     * <p>
     * Unlike the XMSS field this is not always wide enough for every index the key can hold: a
     * total height that is a multiple of eight leaves exactly h bits, and the exhausted position
     * 2^h needs h + 1 of them. Of the standard parameter sets that is the XMSSMT_*_40/* family,
     * whose exhausted index would need a sixth byte, and 2^40 signatures is not a number anyone
     * arrives at.
     * </p>
     *
     * @param totalHeight the height of the whole hypertree.
     */
    static int mtIndexSize(int totalHeight)
    {
        return (totalHeight + 7) / 8;
    }

    /**
     * Read a private key encoding, taking the index from a field of the given width.
     * <p>
     * Only the head is fixed - the serialized traversal state that follows it is variable length -
     * so what can be checked here is that the head is all there. It has to be checked somewhere:
     * the five reads below take their bytes at computed offsets, and nothing on the way in from
     * PrivateKeyFactory looks at the length at all.
     * </p>
     *
     * @param privateKey  the encoding.
     * @param indexSize   the width of the index field, in bytes.
     * @param totalHeight the height the index is bounded by.
     * @param n           the security parameter of the key's parameter set, in bytes.
     */
    static XMSSPrivateKeyCodec decode(byte[] privateKey, int indexSize, int totalHeight, int n)
    {
        if (privateKey.length < indexSize + 4 * n)
        {
            throw new IllegalArgumentException("private key has wrong size");
        }

        int position = 0;
        long index = Pack.bigEndianToLong_Low(privateKey, position, indexSize);
        if (!XMSSEngine.isStoredIndexValid(totalHeight, index))
        {
            throw new IllegalArgumentException("index out of bounds");
        }
        position += indexSize;
        byte[] secretKeySeed = Arrays.copyOfRange(privateKey, position, position + n);
        position += n;
        byte[] secretKeyPRF = Arrays.copyOfRange(privateKey, position, position + n);
        position += n;
        byte[] publicSeed = Arrays.copyOfRange(privateKey, position, position + n);
        position += n;
        byte[] root = Arrays.copyOfRange(privateKey, position, position + n);
        position += n;
        byte[] bdsState = Arrays.copyOfRange(privateKey, position, privateKey.length);

        return new XMSSPrivateKeyCodec(index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsState);
    }

    /**
     * The encoding of a key holding these fields, with the index written in a field of the given
     * width.
     * <p>
     * The traversal state is encoded by the caller and passed in already serialized, so that it
     * can be written straight into the array that is returned: appending it afterwards meant
     * allocating the fixed part on its own and then copying both halves into a second array of the
     * full size.
     * </p><p>
     * An index the field cannot hold is refused rather than written narrowed. Exactly one index
     * can fail: the exhausted position 2^h, at an XMSS^MT total height that is a multiple of eight,
     * where {@link #mtIndexSize(int)} leaves h bits for a value needing h + 1. Written narrowed it
     * came back as zero, and nothing downstream could say so - the index a key declares is cross
     * checked against its per-layer traversal states by decomposing it into a leaf index per layer,
     * and 2^h and 0 have the same decomposition at every layer, so the check that exists for
     * exactly this disagreement is blind to this one value. What came back was a key at index 0
     * reporting a full tree of unused one-time keys, which is the opposite of the truth about where
     * a one-time key scheme has got to (RFC 8391 sec. 1.1). It could not sign - the traversal state
     * a key is left holding at exhaustion is empty, and that survives the round trip - so this was a
     * stored key that lied rather than one that signed twice; a stateful scheme's stored position is
     * still the one thing that must not be written wrong.
     * </p><p>
     * Nothing that could be written before is refused now. Every position a live key sits on, 0 to
     * 2^h - 1, fits at every height of either family, and the XMSS field is four bytes against a
     * largest index of 2^30. What an exhausted key at such a height loses is the raw form, and the
     * RFC 9802 PKCS#8 that carries the raw form; the legacy ASN.1 form, whose index field is an
     * integer with no width of its own, still holds it.
     * </p>
     *
     * @param index     the position the key is at.
     * @param indexSize the width of the index field, in bytes.
     * @param bdsState  the encoded traversal state.
     */
    static byte[] encode(long index, int indexSize, byte[] secretKeySeed, byte[] secretKeyPRF,
        byte[] publicSeed, byte[] root, byte[] bdsState)
    {
        // shifting by 8 * indexSize rather than comparing against 1L << (8 * indexSize), which at
        // the eight byte width - heights 57 to 62 - would shift by 64 and produce 1
        if (indexSize < 8 && (index >>> (8 * indexSize)) != 0)
        {
            throw new IllegalStateException("index " + index + " does not fit the " + indexSize
                + " byte index field of a stored private key");
        }

        /* index || secretKeySeed || secretKeyPRF || publicSeed || root || bdsState */
        byte[] out = new byte[indexSize + secretKeySeed.length + secretKeyPRF.length
            + publicSeed.length + root.length + bdsState.length];
        int position = 0;

        /* copy index */
        Pack.longToBigEndian_Low(index, out, position, indexSize);
        position += indexSize;
        /* copy secretKeySeed */
        System.arraycopy(secretKeySeed, 0, out, position, secretKeySeed.length);
        position += secretKeySeed.length;
        /* copy secretKeyPRF */
        System.arraycopy(secretKeyPRF, 0, out, position, secretKeyPRF.length);
        position += secretKeyPRF.length;
        /* copy publicSeed */
        System.arraycopy(publicSeed, 0, out, position, publicSeed.length);
        position += publicSeed.length;
        /* copy root */
        System.arraycopy(root, 0, out, position, root.length);
        position += root.length;
        /* copy bdsState */
        System.arraycopy(bdsState, 0, out, position, bdsState.length);

        return out;
    }

    long getIndex()
    {
        return index;
    }

    byte[] getSecretKeySeed()
    {
        return secretKeySeed;
    }

    byte[] getSecretKeyPRF()
    {
        return secretKeyPRF;
    }

    byte[] getPublicSeed()
    {
        return publicSeed;
    }

    byte[] getRoot()
    {
        return root;
    }

    byte[] getBDSState()
    {
        return bdsState;
    }
    /**
     * A snapshot of everything a private key's equals() decides on ahead of its traversal state,
     * read from one key under that key's own monitor.
     * <p>
     * The two families' equals() were a line for line copy of each other down to this point, the
     * way their encodings were before this class held those, so the comparison lives here beside
     * the layout it is over: what a key is compared on is what a key is stored as - the index and
     * the four n-byte fields - with the usages remaining and the tree digest naming the position
     * and the parameter set those are under. Only the last step differs between the families, and
     * {@link State} is where that difference is.
     * </p><p>
     * A key's index and its usages remaining are read together, under the monitor a signature is
     * taken under, because both come from state a signature replaces. Read one at a time, a
     * signature landing between them pairs an index from one side of it with a usage count from
     * the other, a combination the key was never in. The four arrays are final and are never
     * written after construction, so capturing the references beside those two says as much as
     * copying the arrays would - which is what lets each key be read in one block of its own
     * rather than one monitor being held across both. Holding the second key's monitor inside the
     * first would let a.equals(b) on one thread and b.equals(a) on another deadlock against each
     * other, and there is nothing to hold them for; {@code HSSPrivateKeyParameters.equals()} gives
     * the same reason for taking its two in sequence.
     * </p>
     */
    static final class Fields
    {
        private final ASN1ObjectIdentifier treeDigestOID;
        private final long index;
        private final long usagesRemaining;
        private final byte[] publicSeed;
        private final byte[] root;
        private final byte[] secretKeySeed;
        private final byte[] secretKeyPRF;

        Fields(ASN1ObjectIdentifier treeDigestOID, long index, long usagesRemaining,
            byte[] publicSeed, byte[] root, byte[] secretKeySeed, byte[] secretKeyPRF)
        {
            this.treeDigestOID = treeDigestOID;
            this.index = index;
            this.usagesRemaining = usagesRemaining;
            this.publicSeed = publicSeed;
            this.root = root;
            this.secretKeySeed = secretKeySeed;
            this.secretKeyPRF = secretKeyPRF;
        }
    }

    /**
     * Whether two keys agree on all seven, with every array among them compared in constant time.
     * <p>
     * Every array is compared in constant time, the root and the public seed included even though
     * they are the public key - the family's public key parameters publish root then SEED, RFC
     * 8391 sec. 4.1.7 and sec. 4.2.4 - because this is a private key's equality, where every
     * comparison in it being constant time is what stops the next field added to the chain from
     * being compared the other way. The two secret seeds are those fields, and they are why the
     * traversal state is all that is left below: a private key encoding is the index, those two
     * seeds, the public seed, the root and the state, and the first five are all here.
     * </p><p>
     * The chain is joined with {@code &} rather than {@code &&}, so all of it is evaluated
     * whatever the two keys are. Short circuited it answers a key differing in its tree digest
     * after one comparison and a key differing only in its secretKeyPRF after seven, so how long
     * it takes says which of the fields the two keys first disagree on - and two of those fields
     * are secret material, which is the thing the constant time comparisons are there to keep out
     * of the timing. Every operand is safe to evaluate unconditionally: the parameter set is
     * mandatory, and the four arrays are allocated when a builder is not given them.
     * </p><p>
     * What is left in the timing is the bit this decides - whether the two keys agree on all
     * seven - since that is what says whether {@link #stateEqual} runs at all. Two keys that get
     * there agree on both secret seeds, so the longer path is not reachable without already
     * holding what comparing those seeds in constant time is there to withhold. It is also why
     * the state is reached by a short circuit after this rather than being another {@code &} term
     * within it: producing a state to compare means encoding a whole traversal state on both
     * keys - every authentication path, retain queue, stack, tree hash and kept node, and a
     * SHA-256 checksum over the result - and as a term it would run for every pair of keys that
     * differ. Measured over 20000 comparisons at an h = 10 SHA-256 XMSS key, that is 13096ns
     * against the 419ns this answers an unequal pair in, and the unequal pair is the common one:
     * the hash below is the public key's, so keys taken from one key pair land in one bucket of a
     * Set or a Map and are told apart there by their index, which is one of the seven.
     * </p>
     */
    static boolean fieldsEqual(Fields a, Fields b)
    {
        return a.treeDigestOID.equals(b.treeDigestOID)
            & a.index == b.index
            & a.usagesRemaining == b.usagesRemaining
            & Arrays.constantTimeAreEqual(a.publicSeed, b.publicSeed)
            & Arrays.constantTimeAreEqual(a.root, b.root)
            & Arrays.constantTimeAreEqual(a.secretKeySeed, b.secretKeySeed)
            & Arrays.constantTimeAreEqual(a.secretKeyPRF, b.secretKeyPRF);
    }

    /**
     * A snapshot of a key's traversal state as an encoding of it would carry it, beside the
     * position that state is the state for.
     * <p>
     * The state is the one part of a key's content {@link #fieldsEqual} cannot reach: it carries a
     * mark saying the one-time key at its index has already signed, and no accessor reports it.
     * Like {@link Fields} it is read under the key's own monitor, the one a signature is held
     * under and the one {@code toByteArray()} takes to write the same two things: a signature
     * landing between the state and the public seed would encode a state under a seed that no
     * longer goes with it.
     * </p><p>
     * The index beside it is what pins an answer to a position, and only one of the two families
     * needs it to. Each key's monitor is taken twice over a comparison rather than once - the
     * fields, then this - so a signature landing between the two leaves the fields having
     * answered on a position their key has already left. All that can do is answer false, which
     * is the answer for the instant it read, and the pairs that reach here are the ones it found
     * equal. A lone BDS encoding opens with the maximum index and the index, so an XMSS key's
     * state pins its own position down and the field here can only agree with it. A state map
     * does not: it carries its own maximum index and each layer's position inside its subtree, but
     * an XMSS^MT key's global index is the field beside the map that rollKey() advances, and
     * {@code toByteArray()} was the only thing that ever wrote the two out together. So both
     * families read their index into this snapshot, one because the answer needs it and one so
     * that there is a single shape to describe.
     * </p>
     */
    static final class State
    {
        private final long index;
        private final byte[] encoded;

        State(long index, byte[] encoded)
        {
            this.index = index;
            this.encoded = encoded;
        }

        long getIndex()
        {
            return index;
        }

        byte[] getEncoded()
        {
            return encoded;
        }
    }

    /**
     * Whether two keys are at one position holding one traversal state, the two state encodings
     * compared in constant time.
     */
    static boolean stateEqual(State a, State b)
    {
        return a.index == b.index & Arrays.constantTimeAreEqual(a.encoded, b.encoded);
    }

    /**
     * The hash of the fields that do not move as a key signs: the tree digest, the root and the
     * public seed. Keys {@link #fieldsEqual} and {@link #stateEqual} call equal agree on all
     * three, so the equals() contract holds.
     * <p>
     * Together they are the public key - the family's public key parameters publish root then
     * SEED under the same parameter set - which is what each provider key hashed by building one
     * and encoding it, a public key parameters and a provider public key and a concatenation of
     * the two fields per call to reach three values the private key already holds. The two secret
     * seeds are left out for the reason they are compared in constant time above: a hash of
     * secret material is a commitment to it, published to wherever the hash goes, and nothing here
     * needs one - the index is what tells one key of a key pair from another, and equals() answers
     * on it without being asked for a hash at all.
     * </p>
     */
    static int hashCode(ASN1ObjectIdentifier treeDigestOID, byte[] root, byte[] publicSeed)
    {
        int hc = treeDigestOID.hashCode();
        hc = 31 * hc + Arrays.hashCode(root);
        hc = 31 * hc + Arrays.hashCode(publicSeed);
        return hc;
    }
}
