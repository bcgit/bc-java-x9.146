package org.bouncycastle.crypto.signers.xmss;

import org.bouncycastle.util.Pack;

/**
 * XMSS address.
 * <p>
 * An address is 32 bytes and nothing holds one as an object: what the three methods here produce
 * and read is the encoding itself, which is what this package hands around and steps. So a walk
 * holding one names the other addresses of the same tree out of the bytes rather than out of an
 * address - {@link #subtreeAddressOf(byte[], int)}, and {@link #otsAddressOf(byte[])} for the one
 * further word that names a leaf within it.
 * </p>
 * <p>
 * Of the three address types RFC 8391 sec. 2.5 defines only the OTS hash address is made from
 * parts, by {@link #otsHashAddress(int, long, int)}. An L-tree address and a hash tree address are
 * made from one of those by {@link #subtreeAddressOf(byte[], int)} and then written into by the
 * walk that carries them, so neither has anything to build. All three are the one 32-byte frame
 * with its words numbered the same way, and the type word is what says what the three words below
 * it mean - so those three are named here once for each meaning something writes into them, the
 * OTS address and the L-tree address being one word and the chain address and the tree height
 * another, while the key-and-mask past them means the same thing to all three.
 * </p>
 */
class XMSSAddress
{
    /**
     * Offset of the type word in the 32-byte encoding, and so also the length of what comes before
     * it. RFC 8391 sec. 2.5 gives every address type the same first three words - the layer
     * address, and the two of the tree address - so those twelve bytes say which tree an address
     * is in, and the word after them says what the three below it are going to mean.
     */
    static final int TYPE_OFFSET = 12;

    /**
     * The type word of an OTS hash address, for {@link #otsHashAddress(int, long, int)} to stamp
     * on what it produces. It is zero, and so is what a fresh array already holds; it is written
     * all the same, because the type word is what says what the three words below it mean, and the
     * other two types are written.
     */
    private static final int OTS_HASH_TYPE = 0x00;

    /**
     * The type word of an L-tree address, for {@link #subtreeAddressOf(byte[], int)} to stamp on
     * an encoding it takes the tree of from an address of another type.
     */
    static final int LTREE_TYPE = 0x01;

    /**
     * The type word of a hash tree address, the same way. The padding word this type puts where an
     * L-tree address puts its index needs no naming at all: it is zero, which is what
     * {@link #subtreeAddressOf(byte[], int)} leaves everything past the type word at, and no walk
     * writes it.
     */
    static final int HASH_TREE_TYPE = 0x02;

    /**
     * Offsets of the word below the type word under the two types that name a leaf in it - the OTS
     * hash address of a leaf's one-time key, and the L-tree address of the walk that compresses
     * that key. It is the one word, which is why between those two types it is the type word alone
     * that separates the encodings. The leaves of a tree differ in it alone, so the walks over them
     * - the leaf walks in {@link BDS} and {@link BDSTreeHash}, and the one L-tree per leaf below
     * them - step it through one encoding rather than producing an encoding per leaf. A hash tree
     * address puts a reserved padding word here instead, and nothing writes that.
     */
    static final int OTS_ADDRESS_OFFSET = 16;
    static final int LTREE_ADDRESS_OFFSET = 16;

    /**
     * Offsets of the tree height and tree index words in the 32-byte encoding. These are the two
     * words a climb writes as it goes, and the two derived types put them in the same place: the
     * L-tree walk in XMSSNodeUtil.lTree moves them over one leaf's WOTS+ public key, and the walks
     * above the leaves - BDS, BDSTreeHash and XMSSVerifierUtil - move them over the tree. Each of
     * them steps one encoding rather than producing one per node.
     */
    static final int TREE_HEIGHT_OFFSET = 20;
    static final int TREE_INDEX_OFFSET = 24;

    /**
     * Offsets of those same two words under the OTS hash address type, where they are the chain
     * address and the hash address. The len chains of a WOTS+ key differ in the first alone, so
     * the three loops that walk them step it through one encoding rather than producing one per
     * chain, and WOTSPlus.chain moves the second as it goes. Neither reaches an L-tree or a hash
     * tree address: {@link #subtreeAddressOf(byte[], int)} stops before both.
     */
    static final int CHAIN_ADDRESS_OFFSET = 20;
    static final int HASH_ADDRESS_OFFSET = 24;

    /**
     * Offset of the key-and-mask word in the 32-byte encoding. Named so that a caller stepping the
     * field through an encoding of its own - WOTSPlus.chain writes it twice per chain step - says
     * so against the one place that lays the encoding out, rather than against a copy of the
     * number.
     */
    static final int KEY_AND_MASK_OFFSET = 28;

    /**
     * The encoding of the OTS hash address of a leaf: which leaf, and the tree the three words
     * above it name.
     * <p>
     * The chain address and the hash address are not parameters, because nothing makes an address
     * in order to set them: a walk steps them through the encoding it already holds, at
     * {@link #CHAIN_ADDRESS_OFFSET} and {@link #HASH_ADDRESS_OFFSET}, rather than making one per
     * chain and per step. Both are zero in what this produces, which is where a walk starts from
     * and what {@code WOTSPlus.getWOTSPlusSecretKey} puts them back to before each one-time key.
     * So is the key-and-mask word past them: that varies per hash rather than per address, so the
     * two walks that move it write it into the encoding they are already holding - WOTSPlus.chain
     * twice per chain step, XMSSNodeUtil.randomizeHash three times per node - at
     * {@link #KEY_AND_MASK_OFFSET}, and both of those write zero into it first.
     * </p>
     *
     * @param layerAddress which layer of an XMSS^MT hypertree the leaf's tree is on; zero for
     *                     XMSS, and for the bottom layer of an XMSS^MT.
     * @param treeAddress  which tree of that layer; zero where the layer holds one.
     * @param otsAddress   which leaf of that tree.
     * @return a fresh 32-byte encoding of that address.
     */
    static byte[] otsHashAddress(int layerAddress, long treeAddress, int otsAddress)
    {
        byte[] address = new byte[32];
        Pack.intToBigEndian(layerAddress, address, 0);
        Pack.longToBigEndian(treeAddress, address, 4);
        Pack.intToBigEndian(OTS_HASH_TYPE, address, TYPE_OFFSET);
        Pack.intToBigEndian(otsAddress, address, OTS_ADDRESS_OFFSET);
        return address;
    }

    /**
     * The OTS address word of an OTS hash address encoding, for the verification walk that names
     * a leaf by it twice over - as the L-tree address of the leaf, and as where its climb through
     * the tree starts.
     *
     * @param address the 32-byte encoding of an OTS hash address.
     * @return its OTS address.
     */
    static int otsAddressOf(byte[] address)
    {
        return Pack.bigEndianToInt(address, OTS_ADDRESS_OFFSET);
    }

    /**
     * The encoding of the address of the given type in the same tree as the given encoding: the
     * twelve bytes before the type word copied across, that word set, and everything after it left
     * at zero. This is copy_subtree_addr followed by set_type of RFC 8391 sec. 2.5, and it is how a
     * walk carrying one address as bytes names the other two addresses of that tree - the L-tree
     * address of a leaf and the hash tree address of the climb over it - without taking the tree
     * apart into fields in order to build them back up.
     * <p>
     * Where the copy stops is the point of it. The three words below the type word mean something
     * different per type, and in the OTS hash address a walk hands in they are live - the OTS
     * address naming the leaf, and the chain and hash addresses the last chain of that leaf left
     * behind, with its key-and-mask in the last word of all. None of that may reach a sibling
     * address. Taking four bytes more than this does, so that the OTS address word carries into
     * the padding word a hash tree address keeps there, is caught by the compatibility oracle at
     * the ninth leaf of a tree.
     * </p>
     *
     * @param address a 32-byte address encoding.
     * @param type    the type word wanted, {@link #LTREE_TYPE} or {@link #HASH_TREE_TYPE}.
     * @return a fresh 32-byte encoding of that address.
     */
    static byte[] subtreeAddressOf(byte[] address, int type)
    {
        byte[] subtreeAddress = new byte[32];
        System.arraycopy(address, 0, subtreeAddress, 0, TYPE_OFFSET);
        Pack.intToBigEndian(type, subtreeAddress, TYPE_OFFSET);
        return subtreeAddress;
    }
}
