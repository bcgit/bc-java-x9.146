package org.bouncycastle.crypto.signers.xmss;

import java.io.Serializable;
import java.util.Stack;

import org.bouncycastle.util.Pack;


class BDSTreeHash
    implements Serializable, Cloneable
{
    private static final long serialVersionUID = 1L;

    private XMSSNode tailNode;
    private final int initialHeight;
    private int height;
    private int nextIndex;
    private boolean initialized;
    private boolean finished;

    BDSTreeHash(int initialHeight)
    {
        this.initialHeight = initialHeight;
        initialized = false;
        finished = false;
    }

    BDSTreeHash(int initialHeight, int height, int nextIndex, boolean initialized, boolean finished,
        XMSSNode tailNode)
    {
        this.initialHeight = initialHeight;
        this.height = height;
        this.nextIndex = nextIndex;
        this.initialized = initialized;
        this.finished = finished;
        this.tailNode = tailNode;
    }

    void initialize(int nextIndex)
    {
        tailNode = null;
        height = initialHeight;
        this.nextIndex = nextIndex;
        initialized = true;
        finished = false;
    }

    /**
     * Take this tree hash instance one leaf further (RFC 8391 sec. 4.1.6 algorithm 10).
     *
     * @param otsAddress the 32-byte encoding of the OTS hash address the tree starts at. This
     *                   writes the OTS address word of it, naming the leaf below, and WOTSPlus the
     *                   three words after that; the only caller is the walk in
     *                   {@link BDS#nextAuthenticationPath}, over the copy it owns, and it calls
     *                   this several times running - each of which names its own leaf here before
     *                   anything is derived from the encoding.
     */
    void update(Stack<XMSSNode> stack, WOTSPlus wotsPlus, byte[] publicSeed, byte[] secretSeed, byte[] otsAddress)
    {
        if (finished || !initialized)
        {
            throw new IllegalStateException("finished or not initialized");
        }
            /* prepare addresses */
        Pack.intToBigEndian(nextIndex, otsAddress, XMSSAddress.OTS_ADDRESS_OFFSET);
        /* the leaf's own two addresses, taken from the tree its encoding names and then named for
         * the same leaf a second and a third time */
        byte[] lTreeAddress = XMSSAddress.subtreeAddressOf(otsAddress, XMSSAddress.LTREE_TYPE);
        Pack.intToBigEndian(nextIndex, lTreeAddress, XMSSAddress.LTREE_ADDRESS_OFFSET);
        byte[] hashTreeAddress = XMSSAddress.subtreeAddressOf(otsAddress, XMSSAddress.HASH_TREE_TYPE);
        Pack.intToBigEndian(nextIndex, hashTreeAddress, XMSSAddress.TREE_INDEX_OFFSET);
        /* the two words of that encoding this climb moves, kept alongside it so stepping one is an
         * increment rather than a read back out of the bytes */
        int hashTreeHeight = 0;
        int hashTreeIndex = nextIndex;
        /* and one pair of working buffers for every node hashed below; see
         * XMSSNodeUtil.randomizeHash for why one pair serves a whole walk */
        int n = wotsPlus.getParams().getTreeDigestSize();
        byte[] nodeKey = new byte[n];
        byte[] nodeMask = new byte[2 * n];
            /* calculate leaf node */
        wotsPlus.importKeys(wotsPlus.getWOTSPlusSecretKey(secretSeed, otsAddress), publicSeed);
        WOTSPlusPublicKeyParameters wotsPlusPublicKey = wotsPlus.getPublicKey(otsAddress);
        XMSSNode node = XMSSNodeUtil.lTree(wotsPlus, wotsPlusPublicKey, lTreeAddress, nodeKey, nodeMask);

        while (!stack.isEmpty() && stack.peek().getHeight() == node.getHeight()
            && stack.peek().getHeight() != initialHeight)
        {
            hashTreeIndex = (hashTreeIndex - 1) / 2;
            Pack.intToBigEndian(hashTreeIndex, hashTreeAddress, XMSSAddress.TREE_INDEX_OFFSET);
            node = XMSSNodeUtil.randomizeHash(wotsPlus, stack.pop(), node, hashTreeAddress, nodeKey, nodeMask);
            node = node.incrementHeight();
            Pack.intToBigEndian(++hashTreeHeight, hashTreeAddress, XMSSAddress.TREE_HEIGHT_OFFSET);
        }

        if (tailNode == null)
        {
            tailNode = node;
        }
        else
        {
            if (tailNode.getHeight() == node.getHeight())
            {
                hashTreeIndex = (hashTreeIndex - 1) / 2;
                Pack.intToBigEndian(hashTreeIndex, hashTreeAddress, XMSSAddress.TREE_INDEX_OFFSET);
                node = XMSSNodeUtil.randomizeHash(wotsPlus, tailNode, node, hashTreeAddress, nodeKey, nodeMask);
                node = node.incrementHeight();
                tailNode = node;
                // the last step of the same climb the loop above makes - parent, hash, then name
                // the level above. This is the final climb, so nothing reads the result; it is
                // kept so both merges read alike and so the code still matches the unconditional
                // increment that closes the loop of RFC 8391 sec. 4.1.6 algorithm 9. The address
                // names the height of the children, so the hash above is at the right level.
                Pack.intToBigEndian(++hashTreeHeight, hashTreeAddress, XMSSAddress.TREE_HEIGHT_OFFSET);
            }
            else
            {
                stack.push(node);
            }
        }

        if (tailNode.getHeight() == initialHeight)
        {
            finished = true;
        }
        else
        {
            height = node.getHeight();
            nextIndex++;
        }
    }

    int getHeight()
    {
        if (!initialized || finished)
        {
            return Integer.MAX_VALUE;
        }
        return height;
    }

    int getIndexLeaf()
    {
        return nextIndex;
    }

    int getInitialHeight()
    {
        return initialHeight;
    }

    int getRawHeight()
    {
        return height;
    }

    void setNode(XMSSNode node)
    {
        tailNode = node;
        height = node.getHeight();
        if (height == initialHeight)
        {
            finished = true;
        }
    }

    boolean isFinished()
    {
        return finished;
    }

    boolean isInitialized()
    {
        return initialized;
    }

    public XMSSNode getTailNode()
    {
        return tailNode;
    }

    protected BDSTreeHash clone()
    {
        BDSTreeHash th = new BDSTreeHash(this.initialHeight);

        th.tailNode = this.tailNode;
        th.height = this.height;
        th.nextIndex = this.nextIndex;
        th.initialized = this.initialized;
        th.finished = this.finished;

        return th;
    }
}
