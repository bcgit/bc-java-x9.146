package org.bouncycastle.crypto.params;

import java.io.IOException;

import javax.security.auth.Destroyable;

import org.bouncycastle.crypto.signers.xmss.BDS;
import org.bouncycastle.crypto.signers.xmss.XMSSEngine;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Exceptions;

/**
 * XMSS Private Key.
 */
public final class XMSSPrivateKeyParameters
    extends XMSSKeyParameters
    implements Encodable, Destroyable
{

    /**
     * XMSS parameters object.
     */
    private final XMSSParameters params;
    /**
     * Secret for the derivation of WOTS+ secret keys.
     */
    private final byte[] secretKeySeed;
    /**
     * Secret for the randomization of message digests during signature
     * creation.
     */
    private final byte[] secretKeyPRF;
    /**
     * Public seed for the randomization of hashes.
     */
    private final byte[] publicSeed;
    /**
     * Public root of binary tree.
     */
    private final byte[] root;
    /**
     * BDS state.
     */
    private volatile BDS bdsState;

    private volatile boolean destroyed;

    private XMSSPrivateKeyParameters(Builder builder)
    {
        super(true, builder.params.getTreeDigest());
        params = builder.params;
        int n = params.getTreeDigestSize();
        byte[] privateKey = builder.privateKey;
        if (privateKey != null)
        {
            /* import */
            XMSSPrivateKeyCodec codec = XMSSPrivateKeyCodec.decode(privateKey,
                XMSSPrivateKeyCodec.XMSS_INDEX_SIZE, params.getHeight(), n);

            // the codec answers in the width the XMSS^MT index needs; this family's is an int
            // everywhere else in the class, and the index check the codec has already made bounds
            // it by 2^30, so nothing is lost narrowing it here
            int index = (int)codec.getIndex();
            secretKeySeed = codec.getSecretKeySeed();
            secretKeyPRF = codec.getSecretKeyPRF();
            publicSeed = codec.getPublicSeed();
            root = codec.getRoot();
            byte[] bdsStateBinary = codec.getBDSState();
            try
            {
                BDS bdsImport = XMSSEngine.getBDSFromEncoding(bdsStateBinary, publicSeed);
                bdsState = bdsImport.withWOTSDigest(builder.params.getTreeDigestOID(), builder.params.getTreeDigestSize());
                bdsState.validate(params, index);
                bdsState.validateRoot(root);
            }
            catch (IOException e)
            {
                throw Exceptions.illegalArgumentException(e.getMessage(), e);
            }
            catch (ClassNotFoundException e)
            {
                throw Exceptions.illegalArgumentException(e.getMessage(), e);
            }
            catch (IllegalStateException e)
            {
                throw Exceptions.illegalArgumentException(e.getMessage(), e);
            }
        }
        else
        {
            /* set */
            byte[] tmpSecretKeySeed = builder.secretKeySeed;
            secretKeySeed = XMSSEngine.validateOrAllocate(tmpSecretKeySeed, n, "secretKeySeed");
            byte[] tmpSecretKeyPRF = builder.secretKeyPRF;
            secretKeyPRF = XMSSEngine.validateOrAllocate(tmpSecretKeyPRF, n, "secretKeyPRF");
            byte[] tmpPublicSeed = builder.publicSeed;
            publicSeed = XMSSEngine.validateOrAllocate(tmpPublicSeed, n, "publicSeed");
            byte[] tmpRoot = builder.root;
            root = XMSSEngine.validateOrAllocate(tmpRoot, n, "root");
            BDS tmpBDSState = builder.bdsState;
            if (tmpBDSState != null)
            {
                bdsState = tmpBDSState;
            }
            else
            {
                bdsState = XMSSEngine.createBDS(params, tmpPublicSeed, tmpSecretKeySeed, builder.index);
            }
            if (builder.maxIndex >= 0 && builder.maxIndex != bdsState.getMaxIndex())
            {
                throw new IllegalArgumentException("maxIndex set but not reflected in state");
            }
            try
            {
                bdsState.validate(params, builder.index);
                if (builder.bdsState != null)
                {
                    // only a restored state carries a root worth comparing: one built here is
                    // computed from the seeds, and a key built without a root carries zeros
                    bdsState.validateRoot(builder.root);
                }
            }
            catch (IllegalStateException e)
            {
                throw Exceptions.illegalArgumentException(e.getMessage(), e);
            }
        }
    }

    public long getUsagesRemaining()
    {
        synchronized (this)
        {
            return this.bdsState.getMaxIndex() - this.getIndex() + 1;
        }
    }

    public byte[] getEncoded()
        throws IOException
    {
        synchronized (this)
        {
            return toByteArray();
        }
    }

    public XMSSPrivateKeyParameters rollKey()
    {
        synchronized (this)
        {
            checkDestroyed();

            /* prepare authentication path for next leaf */
            if (bdsState.getIndex() < bdsState.getMaxIndex())
            {
                bdsState = XMSSEngine.getNextBDSState(bdsState, publicSeed, secretKeySeed);
            }
            else
            {
                bdsState = new BDS(params, bdsState.getMaxIndex(), bdsState.getMaxIndex() + 1); // no more nodes left.
            }

            return this;
        }
    }

    public XMSSPrivateKeyParameters getNextKey()
    {
        synchronized (this)
        {
            return this.extractKeyShard(1);
        }
    }

    /**
     * Return a key that can be used usageCount times.
     * <p>
     * Note: this will use the range [index...index + usageCount) for the current key.
     * </p>
     *
     * @param usageCount the number of usages the key should have.
     * @return a key based on the current key that can be used usageCount times.
     */
    public XMSSPrivateKeyParameters extractKeyShard(int usageCount)
    {
        synchronized (this)
        {
            checkDestroyed();

            // both refusals through the one check the XMSS^MT key uses, so the two messages a
            // caller tells the two cases apart by are written down once. Inside the monitor
            // because the count it is checked against is this key's, and a signature landing
            // between the check and the shard would leave the shard covering a leaf already spent.
            long usagesRemaining = getUsagesRemaining();

            XMSSEngine.validateShardSize(usageCount, usagesRemaining);

            /* prepare authentication path for next leaf */
            XMSSPrivateKeyParameters keyParams = new XMSSPrivateKeyParameters.Builder(params)
                .withSecretKeySeed(secretKeySeed).withSecretKeyPRF(secretKeyPRF)
                .withPublicSeed(publicSeed).withRoot(root)
                .withIndex(getIndex())
                .withOwnedBDSState(bdsState.withMaxIndex(bdsState.getIndex() + usageCount - 1,
                    params.getTreeDigestOID(), params.getTreeDigestSize())).build();

            if (usageCount == usagesRemaining)
            {
                this.bdsState = new BDS(params, bdsState.getMaxIndex(), getIndex() + usageCount);   // we're finished.
            }
            else
            {
                // update the tree to the new index.
                for (int i = 0; i != usageCount; i++)
                {
                    this.bdsState = XMSSEngine.getNextBDSState(bdsState, publicSeed, secretKeySeed);
                }
            }

            return keyParams;
        }
    }

    public static class Builder
    {

        /* mandatory */
        private final XMSSParameters params;
        /* optional */
        private int index = 0;
        private int maxIndex = -1;
        private byte[] secretKeySeed = null;
        private byte[] secretKeyPRF = null;
        private byte[] publicSeed = null;
        private byte[] root = null;
        private BDS bdsState = null;
        private byte[] privateKey = null;

        public Builder(XMSSParameters params)
        {
            if (params == null)
            {
                throw new NullPointerException("params == null");
            }
            this.params = params;
        }

        public Builder withIndex(int val)
        {
            index = val;
            return this;
        }

        public Builder withMaxIndex(int val)
        {
            maxIndex = val;
            return this;
        }

        public Builder withSecretKeySeed(byte[] val)
        {
            secretKeySeed = Arrays.clone(val);
            return this;
        }

        public Builder withSecretKeyPRF(byte[] val)
        {
            secretKeyPRF = Arrays.clone(val);
            return this;
        }

        public Builder withPublicSeed(byte[] val)
        {
            publicSeed = Arrays.clone(val);
            return this;
        }

        public Builder withRoot(byte[] val)
        {
            root = Arrays.clone(val);
            return this;
        }

        public Builder withBDSState(BDS valBDS)
        {
            //
            // Copy, do not adopt, as the XMSS^MT builder does. Rolling the key replaces its state
            // rather than advancing the one it holds, but a signature still marks the state it
            // spent in place - XMSSEngine's markUsed() - so two keys sharing one BDS share that
            // record: one key's signature marks the other's state, and the other is then refused
            // by the check that reads the mark, having signed nothing. It travels the other way
            // too, a caller keeping the state it passed in seeing its own copy marked by a key it
            // has handed it to.
            //
            bdsState = valBDS.withMaxIndex(valBDS.getMaxIndex(), params.getTreeDigestOID(),
                params.getTreeDigestSize());
            return this;
        }

        /**
         * As {@link #withBDSState(BDS)}, for a state the caller has just built and shares with
         * nothing: it is adopted rather than copied a second time. Package private for the reason
         * the XMSS^MT sibling gives - a public way of asking the key to adopt a state is the
         * sharing defect the copy prevents, offered as an option.
         */
        Builder withOwnedBDSState(BDS valBDS)
        {
            bdsState = valBDS;
            return this;
        }

        public Builder withPrivateKey(byte[] privateKeyVal)
        {
            privateKey = Arrays.clone(privateKeyVal);
            return this;
        }

        public XMSSPrivateKeyParameters build()
        {
            if (!((privateKey != null) || (publicSeed != null && secretKeySeed != null)))
            {
                throw new IllegalStateException("publicSeed or secretKeySeed is null");
            }
            return new XMSSPrivateKeyParameters(this);
        }
    }

    /**
     * @deprecated use getEncoded() - this method will become private.
     */
    @Deprecated
    public byte[] toByteArray()
    {
        synchronized (this)
        {
            checkDestroyed();

            XMSSPrivateKeyCodec.State state = state();

            return XMSSPrivateKeyCodec.encode(state.getIndex(), XMSSPrivateKeyCodec.XMSS_INDEX_SIZE,
                secretKeySeed, secretKeyPRF, publicSeed, root, state.getEncoded());
        }
    }

    public int getIndex()
    {
        return bdsState.getIndex();
    }

    public byte[] getSecretKeySeed()
    {
        return cloneWithCheck(secretKeySeed);
    }

    public byte[] getSecretKeyPRF()
    {
        return cloneWithCheck(secretKeyPRF);
    }

    public byte[] getPublicSeed()
    {
        return Arrays.clone(publicSeed);
    }

    public byte[] getRoot()
    {
        return Arrays.clone(root);
    }

    public BDS getBDSState()
    {
        return bdsState;
    }

    public XMSSParameters getParameters()
    {
        return params;
    }

    /**
     * Whether these are the same key at the same position, which for a stateful key means the same
     * traversal state too.
     * <p>
     * Both halves of that are {@code XMSSPrivateKeyCodec}'s, beside the layout they are over:
     * {@code Fields} is the seven things decided ahead of the state and {@code State} is the
     * state, each taken from one key under that key's own monitor and never both at once, and
     * {@code fieldsEqual} and {@code stateEqual} compare them. {@code XMSSMTPrivateKeyParameters}
     * held a line for line copy of all of it. What is left here is a snapshot per key and the two
     * calls over them, joined with {@code &&} because what the fields decide is whether the state
     * is compared at all - the codec says why the short circuit goes there and nowhere inside.
     * </p><p>
     * The comparison belongs on this class rather than on the provider key that wraps it because
     * every part of it does: the monitor a signature is taken under is this object's, the fields
     * are this object's, and a caller reaching in through the accessors gets a clone of each array
     * and no way to hold any two of them still. {@code HSSPrivateKeyParameters} does the same for
     * the other stateful family in this package, leaving {@code BCLMSPrivateKey.equals()} a single
     * delegating line, and {@code BCXMSSPrivateKey} is now that line as well. It carries the tree
     * digest a second time, as the OID it was constructed with, and no longer compares it: that
     * OID is {@code params.getTreeDigestOID()} at every route a key is built by - generation, a
     * PKCS#8 round trip, extractKeyShard, and the key a signature hands back - so the first
     * comparison the codec makes is the comparison it was making.
     * </p>
     */
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (o == null || getClass() != o.getClass())
        {
            return false;
        }

        XMSSPrivateKeyParameters that = (XMSSPrivateKeyParameters)o;

        return XMSSPrivateKeyCodec.fieldsEqual(this.fields(), that.fields())
            && XMSSPrivateKeyCodec.stateEqual(this.state(), that.state());
    }

    /**
     * The values {@code XMSSPrivateKeyCodec.fieldsEqual} decides on, read from this key under its
     * own monitor. The index and the usages remaining are both taken from the BDS state a
     * signature replaces, so they are read in one block; the four arrays are final and are never
     * written after construction, so the references are as good as the values.
     */
    private XMSSPrivateKeyCodec.Fields fields()
    {
        synchronized (this)
        {
            return new XMSSPrivateKeyCodec.Fields(params.getTreeDigestOID(), this.getIndex(),
                this.getUsagesRemaining(), publicSeed, root, secretKeySeed, secretKeyPRF);
        }
    }

    /**
     * This key's traversal state, encoded, beside the index it is the state for - the pair
     * {@code toByteArray()} writes out and the pair equals() ends on.
     * <p>
     * This is where the two families genuinely differ: the type each holds decides which
     * {@code XMSSEngine.getEncodedBDSState} it reaches, a BDS against a BDSStateMap, and which of
     * the two messages a failure to encode carries. {@code XMSSPrivateKeyCodec.State} says what
     * the pair is for and why both families carry the index in it.
     * </p>
     */
    private XMSSPrivateKeyCodec.State state()
    {
        synchronized (this)
        {
            try
            {
                return new XMSSPrivateKeyCodec.State(this.getIndex(),
                    XMSSEngine.getEncodedBDSState(bdsState, publicSeed));
            }
            catch (IOException e)
            {
                throw Exceptions.illegalStateException("error encoding BDS state", e);
            }
        }
    }

    /**
     * The fields that do not move as this key signs, hashed as
     * {@code XMSSPrivateKeyCodec.hashCode} hashes them: the tree digest, the root and the public
     * seed.
     */
    public int hashCode()
    {
        return XMSSPrivateKeyCodec.hashCode(params.getTreeDigestOID(), root, publicSeed);
    }

    /**
     * Destroy this key, zeroizing the secret key material it holds: the seed the WOTS+ secret
     * keys are derived from, the PRF key that randomizes message digests, and the WOTS+ secret
     * key its BDS traversal state retains for the leaf it last processed.
     * <p>
     * The public seed, the root, the index and the traversal state's tree nodes are retained -
     * none of them is secret. After destruction {@link #isDestroyed()} returns true and
     * {@link #getSecretKeySeed()}, {@link #getSecretKeyPRF()}, {@link #getEncoded()},
     * {@link #getNextKey()} and {@link #extractKeyShard(int)} throw
     * {@link IllegalStateException}; a signature attempt fails before the index is advanced.
     * Keys previously split off this one hold their own copies of the seeds and are unaffected.
     */
    public synchronized void destroy()
    {
        if (!destroyed)
        {
            destroyed = true;
            Arrays.clear(secretKeySeed);
            Arrays.clear(secretKeyPRF);
            XMSSEngine.clearSecrets(bdsState);
        }
    }

    public boolean isDestroyed()
    {
        return destroyed;
    }

    private byte[] cloneWithCheck(byte[] fieldValue)
    {
        byte[] rv = Arrays.clone(fieldValue);

        // clone first, check second: a destroy() that lands in between has set the flag before
        // it clears the array, so a stale copy is never handed out.
        checkDestroyed();

        return rv;
    }

    private void checkDestroyed()
    {
        if (destroyed)
        {
            throw new IllegalStateException("key destroyed");
        }
    }
}
