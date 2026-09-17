package org.bouncycastle.pqc.crypto.xmss;

import java.io.Serializable;

/**
 * Binary tree node.
 *
 * @deprecated this class is implementation detail of the XMSS / XMSS^MT engine, which has
 * moved to org.bouncycastle.crypto.signers.xmss and is package-private there. Drive XMSS
 * through {@link org.bouncycastle.crypto.signers.XMSSSigner} /
 * {@link org.bouncycastle.crypto.generators.XMSSKeyPairGenerator} and the
 * org.bouncycastle.crypto.params key classes instead; the engine operations those are
 * built on are on org.bouncycastle.crypto.signers.xmss.XMSSEngine.
 */
@Deprecated
public final class XMSSNode
    implements Serializable
{
    private static final long serialVersionUID = 1L;

    private final int height;
    private final byte[] value;

    protected XMSSNode(int height, byte[] value)
    {
        super();
        this.height = height;
        this.value = value;
    }

    public int getHeight()
    {
        return height;
    }

    public byte[] getValue()
    {
        return XMSSUtil.cloneArray(value);
    }
}
