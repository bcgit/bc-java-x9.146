package org.bouncycastle.crypto.signers.xmss;

import org.bouncycastle.util.Pack;

class XMSSVerifierUtil
{
    /**
     * Compute a root node from a tree signature.
     * <p>
     * The length check is the verifying half of the pair described on XMSSEngine.wotsSign: a digest
     * of the wrong length is not rejected downstream but silently truncated by convertToBaseW.
     * Every messageDigest reaching here is a khf output - HMsg at the two entry points, or a node
     * this method itself returned one layer down - so it holds a boundary rather than catching a
     * live path.
     *
     * @param messageDigest Message digest.
     * @param signature     XMSS signature.
     * @param otsAddress    the 32-byte encoding of the OTS hash address the signing key was at.
     *                      The OTS address word of it names the leaf, and is read out before
     *                      getPublicKeyFromSignature below writes the three words after it.
     * @return Root node calculated from signature.
     */
    static XMSSNode getRootNodeFromSignature(WOTSPlus wotsPlus, int height, byte[] messageDigest, XMSSReducedSignature signature,
                                              byte[] otsAddress, int indexLeaf)
    {
        if (messageDigest.length != wotsPlus.getParams().getTreeDigestSize())
        {
            throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
        }

        /* prepare adresses */
        int otsIndex = XMSSAddress.otsAddressOf(otsAddress);
        byte[] lTreeAddress = XMSSAddress.subtreeAddressOf(otsAddress, XMSSAddress.LTREE_TYPE);
        Pack.intToBigEndian(otsIndex, lTreeAddress, XMSSAddress.LTREE_ADDRESS_OFFSET);
        byte[] hashTreeAddress = XMSSAddress.subtreeAddressOf(otsAddress, XMSSAddress.HASH_TREE_TYPE);
        Pack.intToBigEndian(otsIndex, hashTreeAddress, XMSSAddress.TREE_INDEX_OFFSET);
        /* the tree index of that encoding, kept alongside it as the climb halves it */
        int hashTreeIndex = otsIndex;
        /* and one pair of working buffers for every node hashed below, L-tree and climb alike; see
         * XMSSNodeUtil.randomizeHash for why one pair serves a whole walk */
        int n = wotsPlus.getParams().getTreeDigestSize();
        byte[] nodeKey = new byte[n];
        byte[] nodeMask = new byte[2 * n];
        /*
         * calculate WOTS+ public key and compress to obtain original leaf hash
         */
        WOTSPlusPublicKeyParameters wotsPlusPK = wotsPlus.getPublicKeyFromSignature(messageDigest,
            signature.getWOTSPlusSignature(), otsAddress);
        XMSSNode[] node = new XMSSNode[2];
        node[0] = XMSSNodeUtil.lTree(wotsPlus, wotsPlusPK, lTreeAddress, nodeKey, nodeMask);

        for (int k = 0; k < height; k++)
        {
            Pack.intToBigEndian(k, hashTreeAddress, XMSSAddress.TREE_HEIGHT_OFFSET);
            if (Math.floor(indexLeaf / (1 << k)) % 2 == 0)
            {
                hashTreeIndex = hashTreeIndex / 2;
                Pack.intToBigEndian(hashTreeIndex, hashTreeAddress, XMSSAddress.TREE_INDEX_OFFSET);
                node[1] = XMSSNodeUtil.randomizeHash(wotsPlus, node[0], signature.getAuthPath().get(k),
                    hashTreeAddress, nodeKey, nodeMask);
            }
            else
            {
                hashTreeIndex = (hashTreeIndex - 1) / 2;
                Pack.intToBigEndian(hashTreeIndex, hashTreeAddress, XMSSAddress.TREE_INDEX_OFFSET);
                node[1] = XMSSNodeUtil.randomizeHash(wotsPlus, signature.getAuthPath().get(k), node[0],
                    hashTreeAddress, nodeKey, nodeMask);
            }
            node[1] = node[1].incrementHeight();
            node[0] = node[1];
        }
        return node[0];
    }
}
