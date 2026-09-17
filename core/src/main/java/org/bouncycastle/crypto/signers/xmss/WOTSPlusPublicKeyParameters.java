package org.bouncycastle.crypto.signers.xmss;

/**
 * WOTS+ public key.
 */
final class WOTSPlusPublicKeyParameters
{
    private final byte[][] publicKey;

    /**
     * This key's len n-byte blocks, taken over rather than copied in.
     * <p>
     * Both of the callers that build one - {@link WOTSPlus#getPublicKey} and
     * {@link WOTSPlus#getPublicKeyFromSignature}, and this class being package-private and final
     * is what makes that a list rather than a guess - allocate the array, fill it with what
     * chain() returns and hand it straight here, so nothing outside holds the array or any block
     * of it. That the blocks are chain()'s own arrays is the part to check rather than assume, and
     * it is chain() that makes it so: it returns an array of its own however many steps it takes,
     * copying its starting value out rather than handing it back when that number is zero.
     * Generation never reaches that case, chaining a fixed w - 1 steps, but recovery from a
     * signature does - at every digit of the message equal to w - 1 - and it chains from the
     * signature's own blocks, so without that copy a recovered key would share storage with the
     * signature it was recovered from.
     * <p>
     * Nothing escapes either. {@link #toNodes()} is the only way the blocks leave this class and
     * it hands them to a walk that only reads them - so the copy this drops was of a len-by-n
     * array no one else could reach. It was made per one-time key, which is per leaf of every tree
     * built: len + 1 arrays a leaf, 68 of them at the SHA-256 parameter sets.
     * <p>
     * The shape is the caller's as well, and nothing here measures it. Both build the array as
     * new byte[params.getLen()][] and fill every entry with what chain() returns, which is a
     * byte[params.getTreeDigestSize()], from the one WOTSPlusParameters the check that stood here
     * was handed as well - so it could only compare each of those two values with itself. That is
     * why it is gone rather than kept as cheap insurance: it read as a guard against a
     * wrong-shaped key while being unable to answer for one.
     *
     * @param publicKey the len n-byte blocks of the key, which this instance takes over.
     */
    public WOTSPlusPublicKeyParameters(byte[][] publicKey)
    {
        this.publicKey = publicKey;
    }

    /**
     * This key's blocks, each wrapped as a height-0 {@link XMSSNode}, as the L-tree walk in
     * {@link XMSSNodeUtil#lTree} starts from, and the only way they leave this class. A node only
     * ever copies its value outwards - getValue() clones it and encodeTo() writes it elsewhere -
     * so wrapping the blocks themselves, rather than a deep copy of them, lets nothing escape and
     * saves len + 1 arrays per one-time key compressed. That is one key per leaf of every tree
     * built, so at the SHA-256 parameter sets it is 68 arrays a leaf.
     */
    XMSSNode[] toNodes()
    {
        XMSSNode[] nodes = new XMSSNode[publicKey.length];
        for (int i = 0; i != publicKey.length; i++)
        {
            nodes[i] = new XMSSNode(0, publicKey[i]);
        }
        return nodes;
    }
}
