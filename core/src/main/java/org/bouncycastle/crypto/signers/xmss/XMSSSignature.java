package org.bouncycastle.crypto.signers.xmss;

import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Pack;

/**
 * XMSS Signature.
 */
final class XMSSSignature
    extends XMSSReducedSignature
    implements Encodable
{
    private static final int INDEX_SIZE = 4;

    private final int index;
    private final byte[] random;

    /**
     * The size of the encoding {@link #getEncoded()} produces for a parameter set: a four byte
     * index and the n-byte randomizer in front of what XMSSReducedSignature writes. Read as well
     * as written through here, so {@link Builder#withSignature} takes an encoding apart on the
     * layout toByteArray() lays down rather than on a second copy of it. Named for the encoding
     * rather than called sizeOf, which would hide the superclass method it is built on.
     */
    static int encodedSizeOf(XMSSParameters params)
    {
        return INDEX_SIZE + params.getTreeDigestSize() + XMSSReducedSignature.sizeOf(params);
    }

    private XMSSSignature(Builder builder)
    {
        super(builder);
        index = builder.index;
        int n = getParams().getTreeDigestSize();
        random = XMSSUtil.validateOrAllocate(builder.random, n, "random");
    }

    public byte[] getEncoded()
    {
        return toByteArray();
    }

    public static class Builder
        extends XMSSReducedSignature.Builder
    {

        private final XMSSParameters params;
        /* optional */
        private int index = 0;
        private byte[] random = null;

        public Builder(XMSSParameters params)
        {
            super(params);
            this.params = params;
        }

        public Builder withIndex(int val)
        {
            index = val;
            return this;
        }

        public Builder withRandom(byte[] val)
        {
            random = Arrays.clone(val);
            return this;
        }

        public Builder withSignature(byte[] val)
        {
            int n = params.getTreeDigestSize();
            if (val.length != encodedSizeOf(params))
            {
                /* an XMSS signature is a fixed-size encoding - anything longer or shorter, in
                 * particular a valid signature carrying trailing data, is not a signature for
                 * these parameters (RFC 8391 sec. 4.1.8). XMSSMTSignature checks the same way. */
                throw new IllegalArgumentException("signature has wrong size");
            }
            int position = 0;
            /* extract index */
            index = Pack.bigEndianToInt(val, position);

            /* the four index bytes are read as a signed int, so an encoding that arrived from
             * somewhere else can name a leaf this tree does not have, or a negative one. Refused
             * here as XMSSMTSignature refuses it, rather than left to fail further in: the two
             * halves of one scheme disagreed about whether an index outside the tree is a signature
             * that will not decode or one that does not verify. Both answers reach a verifier as
             * false - XMSSEngine.verifySignature catches RuntimeException around this decode - so
             * what changes is where it is decided and what a caller building a signature by hand is
             * told. isIndexValid raises rather than returns for the negative case; that is inside
             * the same catch. */
            if (!XMSSUtil.isIndexValid(params.getHeight(), index))
            {
                throw new IllegalArgumentException("index out of bounds");
            }
            position += INDEX_SIZE;
            /* extract random */
            random = Arrays.copyOfRange(val, position, position + n);
            position += n;
            withReducedSignature(val, position);
            return this;
        }

        public XMSSSignature build()
        {
            return new XMSSSignature(this);
        }
    }

    /**
     * @deprecated use getEncoded() this method will become private.
     */
    public byte[] toByteArray()
    {
        /* index || random || signature || authentication path */
        int n = getParams().getTreeDigestSize();
        byte[] out = new byte[encodedSizeOf(getParams())];
        int position = 0;
        /* copy index */
        Pack.intToBigEndian(index, out, position);
        position += INDEX_SIZE;
        /* copy random */
        System.arraycopy(random, 0, out, position, random.length);
        position += n;
        /* copy signature || authentication path */
        encodeTo(out, position);
        return out;
    }

    public int getIndex()
    {
        return index;
    }

    /**
     * This signature's randomizer r, by reference. XMSSEngine is the only caller and copies it
     * straight into the H_msg key it builds, so the clone this used to return protected nothing:
     * the class is package-private, the field is written once at construction and never after, and
     * the one caller only reads it. A new caller must not write to what it gets back.
     */
    byte[] getRandom()
    {
        return random;
    }
}
