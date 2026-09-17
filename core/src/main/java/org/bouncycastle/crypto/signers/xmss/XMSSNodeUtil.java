package org.bouncycastle.crypto.signers.xmss;

import org.bouncycastle.util.Pack;

class XMSSNodeUtil
{
    /**
     * Compresses a WOTS+ public key to a single n-byte string.
     * <p>
     * The key and the length it is walked with arrive from two places - the array from publicKey,
     * len from wotsPlus - and nothing in the signature ties them together. They agree because every
     * caller takes the key from the same WOTSPlus instance it passes here, a line or two earlier:
     * BDS and BDSTreeHash from getPublicKey(), XMSSVerifierUtil from getPublicKeyFromSignature().
     * A key from another parameter set would index past the end of the array, or leave its tail
     * unread. That pairing is this method's real precondition and it is the caller's to keep.
     * </p>
     *
     * @param publicKey WOTS+ public key to compress.
     * @param address   the 32-byte encoding of this leaf's L-tree address. The caller owns it and
     *                  has set the L-tree address word, which is what names the leaf; this walk
     *                  writes the tree height and tree index words of it, and randomizeHash below
     *                  writes key-and-mask. Each of those three is written before the hash that
     *                  reads it, so what a previous leaf's walk left in them is gone before
     *                  anything is hashed.
     * @param key       an n-byte buffer the caller owns, and tmpMask a 2n-byte one, handed on to
     *                  randomizeHash for every node of this L-tree; see there for why one pair
     *                  serves a whole walk.
     * @param tmpMask   see key.
     * @return Compressed n-byte string of public key.
     */
    static XMSSNode lTree(WOTSPlus wotsPlus, WOTSPlusPublicKeyParameters publicKey, byte[] address, byte[] key,
        byte[] tmpMask)
    {
        int len = wotsPlus.getParams().getLen();
        /* the key's blocks as the leaves of the L-tree, and the walk overwrites the array, not them */
        XMSSNode[] publicKeyNodes = publicKey.toNodes();
        int treeHeight = 0;
        Pack.intToBigEndian(treeHeight, address, XMSSAddress.TREE_HEIGHT_OFFSET);
        while (len > 1)
        {
            for (int i = 0; i < (int)Math.floor(len / 2); i++)
            {
                Pack.intToBigEndian(i, address, XMSSAddress.TREE_INDEX_OFFSET);
                publicKeyNodes[i] = randomizeHash(wotsPlus, publicKeyNodes[2 * i], publicKeyNodes[(2 * i) + 1],
                    address, key, tmpMask);
            }
            if (len % 2 == 1)
            {
                publicKeyNodes[(int)Math.floor(len / 2)] = publicKeyNodes[len - 1];
            }
            len = (int)Math.ceil((double)len / 2);
            Pack.intToBigEndian(++treeHeight, address, XMSSAddress.TREE_HEIGHT_OFFSET);
        }
        return publicKeyNodes[0];
    }

    /**
     * Randomization of nodes in binary tree.
     * <p>
     * Unlike the addresses, the nodes reaching here are not always built a line earlier: they come
     * from a BDS state's stack, authentication path, kept nodes or a tree hash's tail, and such a
     * state can have arrived by deserialization. That they are there at all is settled where the
     * state enters rather than here - BDS.readObject refuses a stream carrying null collections or
     * null entries, BDS.validate walks every node a state holds, and nextAuthenticationPath names
     * the one node it fetches by index ("missing keep node in BDS state") because an NPE out of the
     * hash below would not say what was wrong. The equal-height check is a different thing again:
     * the algorithm only ever hashes two nodes of the same height together.
     * </p>
     *
     * @param left    Left node.
     * @param right   Right node.
     * @param address the 32-byte encoding of the address of the node being computed. The caller
     *                owns it and has written the words that name that node; this method writes the
     *                key-and-mask word of it, once before each of the three hashes below.
     * @param key     an n-byte buffer the caller owns, for the one of the three PRF results that H
     *                reads as a key rather than as the data it hashes.
     * @param tmpMask a 2n-byte buffer the caller owns, for the other two - the bitmasks, which are
     *                produced straight into it and which maskInto then turns into the masked pair
     *                H hashes.
     * @return Randomized hash of parent of left / right node.
     */
    static XMSSNode randomizeHash(WOTSPlus wotsPlus, XMSSNode left, XMSSNode right, byte[] address, byte[] key,
        byte[] tmpMask)
    {
        if (left.getHeight() != right.getHeight())
        {
            throw new IllegalStateException("height of both nodes must be equal");
        }
        byte[] publicSeed = wotsPlus.getPublicSeed();
        KeyedHashFunctions khf = wotsPlus.getKhf();
        int n = wotsPlus.getParams().getTreeDigestSize();

        // The three PRFs differ in one word of the address, so they run over one encoding of it
        // with that word written in before each, the way WOTSPlus.chain steps its two; the offset
        // is named on the class that lays the encoding out rather than copied here. Taking the
        // encoding rather than the address is what lets the caller keep one for a whole walk: at
        // n = 32 an L-tree over a WOTS+ public key is 66 of these calls and a tree of height 10
        // another 1023, and every one of them used to rebuild an address and encode it again.
        //
        // This is where withKeyAndMask() was, and what it did with an address that was neither an
        // L-tree address nor a hash tree address - the two that had a subclass of their own to be
        // tested for - was return it unchanged, leaving key-and-mask at whatever it already held,
        // so the three PRFs would be three of the same hash. Writing the word sets it whatever
        // address the encoding was taken from. Nothing changes today, no caller passing anything
        // else - lTree an L-tree address, BDS, BDSTreeHash and XMSSVerifierUtil a hash tree
        // address - but the rule is now the one RFC 8391 sec. 4.1.5 states rather than one about
        // subtypes.
        //
        // The two working buffers come from the caller for the same reason, one pair for a whole
        // walk rather than a pair per node, the way WOTSPlus.chain takes its two. Nothing carries
        // between nodes: PRF fills all n bytes of key and both n-byte halves of tmpMask before
        // either is read, so what the previous node left in them is gone before anything is
        // hashed.
        //
        // Only out has to be this call's own. It becomes the returned node's value, and a walk
        // collects the nodes it makes - the L-tree's array, a BDS state's stack, authentication
        // path, retain and keep - so one buffer shared across a walk would leave every one of them
        // holding the last node computed.
        Pack.intToBigEndian(0, address, XMSSAddress.KEY_AND_MASK_OFFSET);
        khf.PRF(publicSeed, address, key);

        Pack.intToBigEndian(1, address, XMSSAddress.KEY_AND_MASK_OFFSET);
        khf.PRF(publicSeed, address, tmpMask, 0);

        Pack.intToBigEndian(2, address, XMSSAddress.KEY_AND_MASK_OFFSET);
        khf.PRF(publicSeed, address, tmpMask, n);

        left.maskInto(n, tmpMask, 0);
        right.maskInto(n, tmpMask, n);

        byte[] out = new byte[n];
        khf.H(key, tmpMask, out);
        return new XMSSNode(left.getHeight(), out);
    }
}
