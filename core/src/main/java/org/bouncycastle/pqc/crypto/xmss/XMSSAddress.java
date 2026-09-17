package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.util.Pack;

/**
 * XMSS address.
 *
 * @deprecated this class is implementation detail of the XMSS / XMSS^MT engine, which has
 * moved to org.bouncycastle.crypto.signers.xmss and is package-private there. Drive XMSS
 * through {@link org.bouncycastle.crypto.signers.XMSSSigner} /
 * {@link org.bouncycastle.crypto.generators.XMSSKeyPairGenerator} and the
 * org.bouncycastle.crypto.params key classes instead; the engine operations those are
 * built on are on org.bouncycastle.crypto.signers.xmss.XMSSEngine.
 */
@Deprecated
public abstract class XMSSAddress
{

    private final int layerAddress;
    private final long treeAddress;
    private final int type;
    private final int keyAndMask;

    protected XMSSAddress(Builder builder)
    {
        layerAddress = builder.layerAddress;
        treeAddress = builder.treeAddress;
        type = builder.type;
        keyAndMask = builder.keyAndMask;
    }

    protected static abstract class Builder<T extends Builder>
    {

        /* mandatory */
        private final int type;
        /* optional */
        private int layerAddress = 0;
        private long treeAddress = 0L;
        private int keyAndMask = 0;

        protected Builder(int type)
        {
            super();
            this.type = type;
        }

        protected T withLayerAddress(int val)
        {
            layerAddress = val;
            return getThis();
        }

        protected T withTreeAddress(long val)
        {
            treeAddress = val;
            return getThis();
        }

        protected T withKeyAndMask(int val)
        {
            keyAndMask = val;
            return getThis();
        }

        protected abstract XMSSAddress build();

        protected abstract T getThis();
    }

    protected byte[] toByteArray()
    {
        byte[] byteRepresentation = new byte[32];
        Pack.intToBigEndian(layerAddress, byteRepresentation, 0);
        Pack.longToBigEndian(treeAddress, byteRepresentation, 4);
        Pack.intToBigEndian(type, byteRepresentation, 12);
        Pack.intToBigEndian(keyAndMask, byteRepresentation, 28);
        return byteRepresentation;
    }

    protected final int getLayerAddress()
    {
        return layerAddress;
    }

    protected final long getTreeAddress()
    {
        return treeAddress;
    }

    public final int getType()
    {
        return type;
    }

    public final int getKeyAndMask()
    {
        return keyAndMask;
    }
}
