package org.bouncycastle.crypto.signers.xmss;

import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.util.Arrays;

import java.util.ArrayList;
import java.util.List;

/**
 * Reduced XMSS Signature.
 */
class XMSSReducedSignature
{
    private final XMSSParameters params;
    private final byte[][] wotsPlusSignature;
    private final List<XMSSNode> authPath;

    /**
     * The size of the encoding {@link #toByteArray()} produces for a parameter set: the len n-byte
     * WOTS+ blocks followed by the h authentication path nodes. Read as well as written through
     * here, so the layout the constructor takes an encoding apart on is the one toByteArray() and
     * {@link #encodeTo} lay down, rather than the same product written out a second time beside
     * it. XMSSSignature puts its own head in front of this size and XMSSMTSignature takes it once
     * per layer, both from here.
     */
    static int sizeOf(XMSSParameters params)
    {
        return (params.getLen() + params.getHeight()) * params.getTreeDigestSize();
    }

    public XMSSReducedSignature(Builder builder)
    {
        params = builder.params;
        int n = params.getTreeDigestSize();
        int len = params.getLen();
        int height = params.getHeight();
        byte[] reducedSignature = builder.reducedSignature;
        if (reducedSignature != null)
        {
            /* import */
            int position = builder.reducedSignatureOff;
            if (position < 0 || sizeOf(params) > reducedSignature.length - position)
            {
                throw new IllegalArgumentException("signature has wrong size");
            }
            byte[][] wotsPlusSignature = new byte[len][];
            for (int i = 0; i < wotsPlusSignature.length; i++)
            {
                wotsPlusSignature[i] = Arrays.copyOfRange(reducedSignature, position, position + n);
                position += n;
            }
            this.wotsPlusSignature = wotsPlusSignature;

            List<XMSSNode> nodeList = new ArrayList<XMSSNode>();
            for (int i = 0; i < height; i++)
            {
                nodeList.add(new XMSSNode(i, Arrays.copyOfRange(reducedSignature, position, position + n)));
                position += n;
            }
            authPath = nodeList;
        }
        else
        {
            /* set */
            byte[][] tmpSignature = builder.wotsPlusSignature;
            if (tmpSignature != null)
            {
                wotsPlusSignature = tmpSignature;
            }
            else
            {
                wotsPlusSignature = new byte[len][n];
            }
            List<XMSSNode> tmpAuthPath = builder.authPath;
            if (tmpAuthPath != null)
            {
                if (tmpAuthPath.size() != height)
                {
                    throw new IllegalArgumentException("size of authPath needs to be equal to height of tree");
                }
                authPath = tmpAuthPath;
            }
            else
            {
                authPath = new ArrayList<XMSSNode>();
            }
        }
    }

    static class Builder
    {
        /* mandatory */
        private final XMSSParameters params;
        /* optional */
        private byte[][] wotsPlusSignature = null;
        private List<XMSSNode> authPath = null;
        private byte[] reducedSignature = null;
        private int reducedSignatureOff = 0;

        public Builder(XMSSParameters params)
        {
            this.params = params;
        }

        public Builder withWOTSPlusSignature(byte[][] val)
        {
            wotsPlusSignature = val;
            return this;
        }

        public Builder withAuthPath(List<XMSSNode> val)
        {
            authPath = val;
            return this;
        }

        /**
         * Read signature || authentication path out of {@code in} starting at {@code position},
         * the read side of {@link #encodeTo}.
         * <p>
         * At an offset, rather than out of an array of its own, because that is the shape both
         * callers are in: an XMSS signature encoding puts index || random in front of one of
         * these and an XMSS^MT encoding lays down one per layer, so each of them had been cutting
         * the region out with copyOfRange and handing it over to be cloned again - two copies of
         * the whole payload, len WOTS+ blocks and h authentication path nodes, before the
         * constructor copied it a third time into the blocks and nodes it keeps. Only that third
         * copy is a copy of anything the built object holds.
         * </p><p>
         * Nothing of {@code in} is retained, so the caller keeps it; but it is read at
         * {@link #build()} rather than here, so a builder must not be held across a write to it.
         * </p>
         *
         * @param in       the encoding to read from.
         * @param position where in it this reduced signature starts.
         */
        public Builder withReducedSignature(byte[] in, int position)
        {
            reducedSignature = in;
            reducedSignatureOff = position;
            return this;
        }

        public XMSSReducedSignature build()
        {
            return new XMSSReducedSignature(this);
        }
    }

    public byte[] toByteArray()
    {
        /* signature || authentication path */
        byte[] out = new byte[sizeOf(params)];
        encodeTo(out, 0);
        return out;
    }

    /**
     * Write signature || authentication path into {@code out} at {@code position}.
     * <p>
     * The encodings that carry one of these are filling a buffer of their own - XMSSSignature puts
     * index || random in front of it, XMSSMTSignature lays one down per layer - so writing into the
     * caller's buffer is what keeps a per-signature array out of the encoding: XMSSMTSignature had
     * been building one per layer and copying it in, and both had been taking the defensive copies
     * of the WOTS+ blocks and of every authentication path node on the way past.
     * </p>
     */
    void encodeTo(byte[] out, int position)
    {
        int n = params.getTreeDigestSize();
        /* copy signature */
        for (int i = 0; i < wotsPlusSignature.length; i++)
        {
            System.arraycopy(wotsPlusSignature[i], 0, out, position, n);
            position += n;
        }
        /* copy authentication path */
        for (int i = 0; i < authPath.size(); i++)
        {
            authPath.get(i).encodeTo(out, position);
            position += n;
        }
    }

    public XMSSParameters getParams()
    {
        return params;
    }

    /**
     * This signature's len n-byte WOTS+ blocks, by reference. The one caller chains from them and
     * writes to neither the array nor a block of it, so handing them over lets nothing escape -
     * the same terms {@link #encodeTo} reads them on.
     */
    public byte[][] getWOTSPlusSignature()
    {
        return wotsPlusSignature;
    }

    public List<XMSSNode> getAuthPath()
    {
        return authPath;
    }
}
