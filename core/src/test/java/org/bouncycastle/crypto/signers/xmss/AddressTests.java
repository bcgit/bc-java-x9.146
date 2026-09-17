package org.bouncycastle.crypto.signers.xmss;

import junit.framework.TestCase;
import org.bouncycastle.util.Pack;

/**
 * The RFC 8391 sec. 2.5 hash-address word layout. The address is the domain separation between
 * every hash call XMSS makes, so its byte layout is as much a part of the wire format as the
 * signature encoding is - but it is package-private, so nothing outside this package can assert
 * on it.
 */
public class AddressTests
    extends TestCase
{
    private static final int LAYER = 0;
    private static final int TREE = 4;
    private static final int TYPE = 12;
    private static final int WORD_4 = 16;
    private static final int WORD_5 = 20;
    private static final int WORD_6 = 24;
    private static final int KEY_AND_MASK = 28;

    /**
     * An OTS hash address with every word of it set to something distinguishable. It is the one
     * address type this package still builds, and the two below are derived from it the way a walk
     * derives them, so what does and does not carry across is visible.
     */
    private static byte[] otsHashAddress()
    {
        byte[] enc = XMSSAddress.otsHashAddress(7, 0x0102030405060708L, 0x11223344);

        // the chain address, the hash address and the key-and-mask are not factory parameters:
        // each is stepped through the encoding a walk already holds rather than set on an address
        // - the chain address once per chain by the loops over them, the hash address and the
        // key-and-mask within WOTSPlus.chain - so they are written here the way those write them.
        // They have to hold something for the two tests below to say anything, since what those
        // turn on is that none of them carries past the twelve bytes subtreeAddressOf copies; and
        // writing them through the offset constants is also what asserts the constants name words
        // 5 and 6 and the last word of all, which is the layout production depends on.
        Pack.intToBigEndian(0x55667788, enc, XMSSAddress.CHAIN_ADDRESS_OFFSET);
        Pack.intToBigEndian(0x99aabbcc, enc, XMSSAddress.HASH_ADDRESS_OFFSET);
        Pack.intToBigEndian(2, enc, XMSSAddress.KEY_AND_MASK_OFFSET);

        return enc;
    }

    public void testOTSHashAddressLayout()
    {
        // the three words the factory does not take are zero in what it produces, which is what
        // XMSSAddress says of them and what the walks that write them start from. Nothing writes
        // them to say so - it lays down the four words it is given and leaves the rest of a fresh
        // array alone - so assert it against an address nothing has stepped.
        byte[] fresh = XMSSAddress.otsHashAddress(7, 0x0102030405060708L, 0x11223344);

        assertEquals(0, Pack.bigEndianToInt(fresh, WORD_5));
        assertEquals(0, Pack.bigEndianToInt(fresh, WORD_6));
        assertEquals(0, Pack.bigEndianToInt(fresh, KEY_AND_MASK));

        byte[] enc = otsHashAddress();

        assertEquals(32, enc.length);
        assertEquals(7, Pack.bigEndianToInt(enc, LAYER));
        assertEquals(0x0102030405060708L, Pack.bigEndianToLong(enc, TREE));
        assertEquals(0x00, Pack.bigEndianToInt(enc, TYPE));
        assertEquals(0x11223344, Pack.bigEndianToInt(enc, WORD_4));
        assertEquals(0x55667788, Pack.bigEndianToInt(enc, WORD_5));
        assertEquals(0x99aabbcc, Pack.bigEndianToInt(enc, WORD_6));
        assertEquals(2, Pack.bigEndianToInt(enc, KEY_AND_MASK));
    }

    /**
     * An L-tree address is produced from the OTS hash address of the leaf it belongs to, and the
     * twelve bytes naming the tree are the whole of what comes across - RFC 8391 sec. 2.5's
     * copy_subtree_addr, which stops before the type word. The three words below that word mean
     * something else per type and belong to the walk, which writes its own into them; the last
     * word of all is the key-and-mask and is not the caller's to carry either.
     */
    public void testLTreeAddressLayout()
    {
        byte[] enc = XMSSAddress.subtreeAddressOf(otsHashAddress(), XMSSAddress.LTREE_TYPE);

        assertEquals(32, enc.length);
        assertEquals(7, Pack.bigEndianToInt(enc, LAYER));
        assertEquals(0x0102030405060708L, Pack.bigEndianToLong(enc, TREE));
        assertEquals(0x01, Pack.bigEndianToInt(enc, TYPE));
        assertEquals(0, Pack.bigEndianToInt(enc, WORD_4));
        assertEquals(0, Pack.bigEndianToInt(enc, WORD_5));
        assertEquals(0, Pack.bigEndianToInt(enc, WORD_6));
        assertEquals(0, Pack.bigEndianToInt(enc, KEY_AND_MASK));

        Pack.intToBigEndian(0x11223344, enc, XMSSAddress.LTREE_ADDRESS_OFFSET);
        Pack.intToBigEndian(0x55667788, enc, XMSSAddress.TREE_HEIGHT_OFFSET);
        Pack.intToBigEndian(0x99aabbcc, enc, XMSSAddress.TREE_INDEX_OFFSET);

        assertEquals(0x11223344, Pack.bigEndianToInt(enc, WORD_4));
        assertEquals(0x55667788, Pack.bigEndianToInt(enc, WORD_5));
        assertEquals(0x99aabbcc, Pack.bigEndianToInt(enc, WORD_6));
    }

    /**
     * The same for the hash tree address, whose word 4 is a reserved padding word rather than an
     * index - so it is left where the copy leaves it, and nothing writes it.
     */
    public void testHashTreeAddressLayout()
    {
        byte[] enc = XMSSAddress.subtreeAddressOf(otsHashAddress(), XMSSAddress.HASH_TREE_TYPE);

        assertEquals(32, enc.length);
        assertEquals(7, Pack.bigEndianToInt(enc, LAYER));
        assertEquals(0x0102030405060708L, Pack.bigEndianToLong(enc, TREE));
        assertEquals(0x02, Pack.bigEndianToInt(enc, TYPE));
        assertEquals(0, Pack.bigEndianToInt(enc, WORD_4));
        assertEquals(0, Pack.bigEndianToInt(enc, WORD_5));
        assertEquals(0, Pack.bigEndianToInt(enc, WORD_6));
        assertEquals(0, Pack.bigEndianToInt(enc, KEY_AND_MASK));

        Pack.intToBigEndian(0x55667788, enc, XMSSAddress.TREE_HEIGHT_OFFSET);
        Pack.intToBigEndian(0x99aabbcc, enc, XMSSAddress.TREE_INDEX_OFFSET);

        assertEquals(0, Pack.bigEndianToInt(enc, WORD_4));
        assertEquals(0x55667788, Pack.bigEndianToInt(enc, WORD_5));
        assertEquals(0x99aabbcc, Pack.bigEndianToInt(enc, WORD_6));
    }
}
