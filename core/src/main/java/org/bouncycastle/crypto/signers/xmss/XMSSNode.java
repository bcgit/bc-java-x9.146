package org.bouncycastle.crypto.signers.xmss;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;

/**
 * Binary tree node.
 */
final class XMSSNode
    implements Serializable
{
    private static final long serialVersionUID = 1L;

    private final int height;
    private final byte[] value;

    public XMSSNode(int height, byte[] value)
    {
        this.height = height;
        this.value = value;
    }

    public int getHeight()
    {
        return height;
    }

    public byte[] getValue()
    {
        return Arrays.clone(value);
    }

    /**
     * Write this node's value into {@code out} at {@code position}. The signature encoders only
     * read it, so writing it straight into the buffer they are filling - rather than through the
     * defensive copy {@link #getValue()} makes - saves a clone per node of every authentication
     * path encoded, and lets nothing escape either.
     */
    void encodeTo(byte[] out, int position)
    {
        System.arraycopy(value, 0, out, position, value.length);
    }

    /**
     * The length of this node's value, for a caller that needs it before writing the value out and
     * would otherwise take {@link #getValue()}'s defensive copy just to ask.
     */
    int getValueLength()
    {
        return value.length;
    }

    /**
     * Whether this node's value is exactly {@code length} bytes.
     * <p>
     * BDS.validate() asks this of every node a state holds, and asks it here rather than through
     * {@link #getValueLength()} because such a state can have arrived by Java deserialization,
     * which writes an object's fields directly and so can leave this value null where none of the
     * calls to the constructor above can - every one of them passes an array it has just built.
     * Reporting such a node rather than dereferencing it is that method's job.
     * <p>
     * It asked through {@link #getValue()} before, which answers the same question by cloning the
     * whole value to look at its length: a 32-byte array per node of every state validated at the
     * SHA-256 parameter sets, which is per node of every private key decoded.
     */
    boolean hasValueLength(int length)
    {
        return value != null && value.length == length;
    }

    /**
     * Write this node's value to {@code out}. The BDS state codec only reads it, so writing it
     * straight to the stream - rather than through the defensive copy {@link #getValue()} makes -
     * saves a clone per node of every state encoded, and lets nothing escape either.
     */
    void encodeTo(OutputStream out)
        throws IOException
    {
        out.write(value, 0, value.length);
    }

    /**
     * XOR {@code length} bytes of this node's value into {@code out} at {@code position}, over the
     * bitmask the caller has already put there. randomizeHash() masks a pair of nodes into one
     * 2n-byte buffer this way and only reads them to do it, so masking straight from the value -
     * rather than through the defensive copy {@link #getValue()} makes - saves two clones per
     * interior node of every tree walked, and lets nothing escape either.
     * <p>
     * The bitmask is read out of the destination rather than from an array of its own because
     * that is where randomizeHash produces it, PRF having written it straight there; the form this
     * replaces held the two apart, xor'ing the value against a separate bitmask into a third
     * array, and had no other caller to keep it for.
     * <p>
     * The length is the caller's n rather than this value's own, so a node that is somehow not n
     * bytes still fails here the way it did when randomizeHash passed n to Bytes.xor itself,
     * instead of masking fewer bytes and leaving the rest of the buffer holding the raw bitmask.
     */
    void maskInto(int length, byte[] out, int position)
    {
        Bytes.xorTo(length, value, 0, out, position);
    }

    /**
     * This node's own value, one height further up the tree. Every caller computes this from a
     * node it is about to discard, so reusing the value directly - rather than round-tripping it
     * through the defensive copy {@link #getValue()} - avoids a clone nothing needs.
     */
    XMSSNode incrementHeight()
    {
        return new XMSSNode(height + 1, value);
    }
}
