package org.bouncycastle.crypto.params;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Encodable;

/**
 * XMSS Public Key.
 */
public final class XMSSPublicKeyParameters
    extends XMSSKeyParameters
    implements Encodable
{

    /**
     * XMSS parameters object.
     */
    private final XMSSParameters params;
    private final int oid;
    private final byte[] root;
    private final byte[] publicSeed;

    private XMSSPublicKeyParameters(Builder builder)
    {
        super(false, builder.params.getTreeDigest());
        params = builder.params;

        // through the codec, which is where the encoding is: which of the two ways this builder
        // was given its fields decides where the parameter set identifier comes from and whether
        // the root and the seed are checked at n or read out at it, and that is the same rule for
        // both families - it was written out once per family here.
        XMSSPublicKeyCodec fields = XMSSPublicKeyCodec.resolve(builder.publicKey,
            params.getTreeDigestSize(), params.getParameterSetOID(), builder.root,
            builder.publicSeed);

        oid = fields.getOid();
        root = fields.getRoot();
        publicSeed = fields.getPublicSeed();
    }

    public byte[] getEncoded()
        throws IOException
    {
        return toByteArray();
    }

    public static class Builder
    {

        /* mandatory */
        private final XMSSParameters params;
        /* optional */
        private byte[] root = null;
        private byte[] publicSeed = null;
        private byte[] publicKey = null;

        public Builder(XMSSParameters params)
        {
            if (params == null)
            {
                throw new NullPointerException("params == null");
            }
            this.params = params;
        }

        public Builder withRoot(byte[] val)
        {
            root = Arrays.clone(val);
            return this;
        }

        public Builder withPublicSeed(byte[] val)
        {
            publicSeed = Arrays.clone(val);
            return this;
        }

        public Builder withPublicKey(byte[] val)
        {
            publicKey = Arrays.clone(val);
            return this;
        }

        public XMSSPublicKeyParameters build()
        {
            return new XMSSPublicKeyParameters(this);
        }
    }

    /**
     * @deprecated use getEncoded() - this method will become private.
     */
    @Deprecated
    public byte[] toByteArray()
    {
        return XMSSPublicKeyCodec.encode(oid, root, publicSeed);
    }

    public byte[] getRoot()
    {
        return Arrays.clone(root);
    }

    public byte[] getPublicSeed()
    {
        return Arrays.clone(publicSeed);
    }

    public XMSSParameters getParameters()
    {
        return params;
    }
}
