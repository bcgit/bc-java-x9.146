package org.bouncycastle.crypto.signers.xmss;

/**
 * A registered parameter set identifier, and the name it is registered under.
 * <p>
 * The three tables that hold them - {@link WOTSPlusOid}, {@link DefaultXMSSOid} and
 * {@link DefaultXMSSMTOid} - differ in what they are keyed by and in nothing else, so what a
 * parameter set identifier is lives here rather than three times over: the pair of fields, how they
 * are read, and the key each table looks its entries up by. That key had been written out
 * separately in each of the three, with the separator and the order of the parts agreeing between
 * them only because each was typed to match, and a table keyed differently from the one whose
 * parameters it is describing fails no compiler and answers null. Written as one, WOTS+'s key is
 * the whole of it, XMSS's is that key and a tree height, and XMSS^MT's is that key and a layer
 * count, which is what the parameter sets actually are.
 * </p><p>
 * This was an interface with the two accessors on it and no implementation, which every one of the
 * three then supplied, identically.
 * </p>
 */
abstract class XMSSOid
{
    /**
     * The identifier itself, as registered.
     */
    private final int oid;
    /**
     * The name the parameter set is registered under.
     */
    private final String stringRepresentation;

    XMSSOid(int oid, String stringRepresentation)
    {
        this.oid = oid;
        this.stringRepresentation = stringRepresentation;
    }

    public int getOid()
    {
        return oid;
    }

    public String toString()
    {
        return stringRepresentation;
    }

    /**
     * The WOTS+ half of a lookup key, and the whole of one for the WOTS+ table.
     */
    static String createKey(String algorithmName, int digestSize, int winternitzParameter, int len)
    {
        return algorithmName + "-" + digestSize + "-" + winternitzParameter + "-" + len;
    }

    /**
     * An XMSS lookup key: the WOTS+ parameters of its one-time keys, and the height of its tree.
     */
    static String createKey(String algorithmName, int digestSize, int winternitzParameter, int len,
        int height)
    {
        return createKey(algorithmName, digestSize, winternitzParameter, len) + "-" + height;
    }

    /**
     * An XMSS^MT lookup key: an XMSS key, and the number of layers the total height is divided
     * into.
     */
    static String createKey(String algorithmName, int digestSize, int winternitzParameter, int len,
        int height, int layers)
    {
        return createKey(algorithmName, digestSize, winternitzParameter, len, height) + "-" + layers;
    }
}
