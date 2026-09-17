package org.bouncycastle.crypto.signers.xmss;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Pack;

/**
 * XMSS^MT Signature.
 */
final class XMSSMTSignature
    implements Encodable
{

    private final XMSSMTParameters params;
    private final long index;
    private final byte[] random;
    private final List<XMSSReducedSignature> reducedSignatures;

    /**
     * The width of the index field: the fewest whole bytes that hold a leaf index of a hypertree
     * of this height. The private key encoding measures its own index field the same way, in
     * XMSSPrivateKeyCodec, which is in another package and so cannot share this one.
     */
    static int indexSizeOf(XMSSMTParameters params)
    {
        return (int)Math.ceil(params.getHeight() / 8.0);
    }

    /**
     * The size of the encoding {@link #toByteArray()} produces for a parameter set: the index and
     * the n-byte randomizer in front of one reduced signature per layer. Read as well as written
     * through here, so the constructor takes an encoding apart on the layout toByteArray() lays
     * down rather than on a second copy of it, and the per-layer size both of them step by is the
     * one XMSSReducedSignature itself measures - of the parameters of a single layer's tree, which
     * is what {@code getXMSSParameters()} carries.
     */
    static int encodedSizeOf(XMSSMTParameters params)
    {
        return indexSizeOf(params) + params.getTreeDigestSize()
            + XMSSReducedSignature.sizeOf(params.getXMSSParameters()) * params.getLayers();
    }

    private XMSSMTSignature(Builder builder)
    {
        params = builder.params;
        int n = params.getTreeDigestSize();
        byte[] signature = builder.signature;
        if (signature != null)
        {
            /* import */
            int indexSize = indexSizeOf(params);
            int reducedSignatureSizeSingle = XMSSReducedSignature.sizeOf(params.getXMSSParameters());
            if (signature.length != encodedSizeOf(params))
            {
                throw new IllegalArgumentException("signature has wrong size");
            }
            int position = 0;
            index = Pack.bigEndianToLong_Low(signature, position, indexSize);

            if (!XMSSUtil.isIndexValid(params.getHeight(), index))
            {
                throw new IllegalArgumentException("index out of bounds");
            }
            position += indexSize;
            random = Arrays.copyOfRange(signature, position, position + n);
            position += n;
            reducedSignatures = new ArrayList<XMSSReducedSignature>();
            while (position < signature.length)
            {
                XMSSReducedSignature xmssSig = new XMSSReducedSignature.Builder(params.getXMSSParameters())
                    .withReducedSignature(signature, position)
                    .build();
                reducedSignatures.add(xmssSig);
                position += reducedSignatureSizeSingle;
            }
        }
        else
        {
            /* set */
            index = builder.index;
            random = XMSSUtil.validateOrAllocate(builder.random, n, "random");
            reducedSignatures = new ArrayList<XMSSReducedSignature>();
        }
    }

    public byte[] getEncoded()
    {
        return toByteArray();
    }

    public static class Builder
    {

        /* mandatory */
        private final XMSSMTParameters params;
        /* optional */
        private long index = 0L;
        private byte[] random = null;

        private byte[] signature = null;

        public Builder(XMSSMTParameters params)
        {
            this.params = params;
        }

        public Builder withIndex(long val)
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
            signature = Arrays.clone(val);
            return this;
        }

        public XMSSMTSignature build()
        {
            return new XMSSMTSignature(this);
        }
    }

    public byte[] toByteArray()
    {
        /* index || random || reduced signatures */
        int n = params.getTreeDigestSize();
        int indexSize = indexSizeOf(params);
        int reducedSignatureSizeSingle = XMSSReducedSignature.sizeOf(params.getXMSSParameters());
        byte[] out = new byte[encodedSizeOf(params)];
        int position = 0;
        /* copy index - indexSize is 1..8 for every height the parameters admit (2..62) */
        Pack.longToBigEndian_Low(index, out, position, indexSize);
        position += indexSize;
        /* copy random */
        System.arraycopy(random, 0, out, position, random.length);
        position += n;
        /* copy reduced signatures */
        for (XMSSReducedSignature reducedSignature : reducedSignatures)
        {
            reducedSignature.encodeTo(out, position);
            position += reducedSignatureSizeSingle;
        }
        return out;
    }

    public long getIndex()
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

    public List<XMSSReducedSignature> getReducedSignatures()
    {
        return reducedSignatures;
    }
}
