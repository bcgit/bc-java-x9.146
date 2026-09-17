package org.bouncycastle.crypto.signers.xmss;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import junit.framework.TestCase;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.XMSSKeyPairGenerator;
import org.bouncycastle.crypto.generators.XMSSMTKeyPairGenerator;
import org.bouncycastle.crypto.params.XMSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSMTPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.params.XMSSPrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.asn1.XMSSMTPrivateKey;
import org.bouncycastle.pqc.asn1.XMSSPrivateKey;
import org.bouncycastle.util.Arrays;

/**
 * A private key written before the versioned BDSStateCodec form carries its BDS traversal state as
 * a bare Java serialized object, and that path is still read. Java deserialization does not run
 * field initializers, so a crafted stream that simply declares no fields leaves every field of the
 * recovered state at its default - the collections the state is made of come back null.
 * <p>
 * The import path then calls withWOTSDigest() on the recovered state to rebuild it around the
 * digest the key names, and that walks those collections before any validation runs: the null
 * checks BDS.validate() and BDSStateMap.validate() carry are real, but they are reached too late
 * to be the thing that rejects this. So the checks belong at the point of deserialization, where
 * the crafted stream actually enters, and they report as an IOException - the failure a caller of
 * PrivateKeyFactory.createKey is already handling - rather than as a NullPointerException out of
 * the middle of the rebuild.
 * </p>
 */
public class CraftedLegacyStateTests
    extends TestCase
{
    private static final byte TC_ENDBLOCKDATA = 0x78;
    private static final byte TC_NULL = 0x70;
    private static final byte TC_CLASSDESC = 0x72;
    private static final byte TC_OBJECT = 0x73;
    private static final byte TC_BLOCKDATA = 0x77;

    private static final byte SC_WRITE_METHOD = 0x01;
    private static final byte SC_SERIALIZABLE = 0x02;

    /**
     * A Java serialized object naming {@code className} and declaring no fields at all, so every
     * field of the class it names is left at its default on the way back in. {@code trailer} is
     * the class's own writeObject() data, which its readObject() still expects to find.
     */
    private static byte[] fieldlessObject(String className, long serialVersionUID, byte[] trailer)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DataOutputStream dOut = new DataOutputStream(bOut);

        dOut.writeShort(0xaced);                          // STREAM_MAGIC
        dOut.writeShort(0x0005);                          // STREAM_VERSION

        dOut.writeByte(TC_OBJECT);
        dOut.writeByte(TC_CLASSDESC);
        dOut.writeUTF(className);
        dOut.writeLong(serialVersionUID);
        dOut.writeByte(SC_WRITE_METHOD | SC_SERIALIZABLE);
        dOut.writeShort(0);                               // no fields
        dOut.writeByte(TC_ENDBLOCKDATA);                  // end of class annotation
        dOut.writeByte(TC_NULL);                          // no superclass

        // no field values follow, the descriptor declared none

        dOut.writeByte(TC_BLOCKDATA);
        dOut.writeByte(trailer.length);
        dOut.write(trailer);
        dOut.writeByte(TC_ENDBLOCKDATA);

        dOut.close();

        return bOut.toByteArray();
    }

    /**
     * A BDS whose authenticationPath, retain, stack, treeHashInstances and keep are all null. Its
     * readObject() reads a four byte maximum index, and treeHeight came back as 0, so 0 is the
     * only maximum index it will accept.
     */
    private static byte[] craftedBDS()
        throws IOException
    {
        return fieldlessObject("org.bouncycastle.crypto.signers.xmss.BDS", 1L,
            new byte[]{0, 0, 0, 0});
    }

    /**
     * A BDSStateMap whose map of per-layer states is null. Its readObject() reads an eight byte
     * maximum index.
     */
    private static byte[] craftedBDSStateMap()
        throws IOException
    {
        return fieldlessObject("org.bouncycastle.crypto.signers.xmss.BDSStateMap",
            -3464451825208522308L, new byte[]{0, 0, 0, 0, 0, 0, 0, 0});
    }

    public void testCraftedXMSSStateReported()
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(4, NISTObjectIdentifiers.id_sha256);
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        PrivateKeyInfo info = PrivateKeyInfoFactory.createPrivateKeyInfo(kp.getPrivate());
        XMSSPrivateKey asn1 = XMSSPrivateKey.getInstance(info.parsePrivateKey());

        PrivateKeyInfo crafted = new PrivateKeyInfo(info.getPrivateKeyAlgorithm(),
            new XMSSPrivateKey(asn1.getIndex(), asn1.getSecretKeySeed(), asn1.getSecretKeyPRF(),
                asn1.getPublicSeed(), asn1.getRoot(), craftedBDS()));

        try
        {
            PrivateKeyFactory.createKey(crafted);
            fail("crafted BDS state accepted");
        }
        catch (IOException e)
        {
            assertEquals("incomplete BDS state", e.getMessage());
        }
    }

    /**
     * A TreeMap holding a single null key, which put() would refuse. Its readObject() reads the
     * entries across in the order the stream gives them and so never compares a key to anything,
     * which is what lets a crafted stream carry one - and why the null survives to be walked by
     * whatever reads the map afterwards. Built by patching the serialized form of an empty one:
     * its writeObject() trailer is an entry count followed by that many key/value pairs.
     */
    private static Map craftedNullKeyMap()
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(new TreeMap());
        oOut.close();

        byte[] empty = bOut.toByteArray();
        byte[] emptyTrailer = new byte[]{TC_BLOCKDATA, 4, 0, 0, 0, 0, TC_ENDBLOCKDATA};

        assertTrue("unexpected TreeMap serial form", Arrays.areEqual(emptyTrailer,
            Arrays.copyOfRange(empty, empty.length - emptyTrailer.length, empty.length)));

        byte[] crafted = Arrays.concatenate(
            Arrays.copyOf(empty, empty.length - emptyTrailer.length),
            new byte[]{TC_BLOCKDATA, 4, 0, 0, 0, 1, TC_NULL, TC_NULL, TC_ENDBLOCKDATA});

        return (Map)new ObjectInputStream(new ByteArrayInputStream(crafted)).readObject();
    }

    /**
     * A real BDS, serialized with one of its two maps replaced by one holding a null key.
     */
    private static PrivateKeyInfo keyWithNullKeyIn(String field)
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(4, NISTObjectIdentifiers.id_sha256);
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

        // take the key apart while its state is still sound - getBDSState() hands back the live
        // state, so corrupting it first would leave nothing able to encode the key it came from
        PrivateKeyInfo info = PrivateKeyInfoFactory.createPrivateKeyInfo(kp.getPrivate());
        XMSSPrivateKey asn1 = XMSSPrivateKey.getInstance(info.parsePrivateKey());

        BDS bds = ((XMSSPrivateKeyParameters)kp.getPrivate()).getBDSState();

        Field f = BDS.class.getDeclaredField(field);

        f.setAccessible(true);
        f.set(bds, craftedNullKeyMap());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(bds);
        oOut.close();

        return new PrivateKeyInfo(info.getPrivateKeyAlgorithm(),
            new XMSSPrivateKey(asn1.getIndex(), asn1.getSecretKeySeed(), asn1.getSecretKeyPRF(),
                asn1.getPublicSeed(), asn1.getRoot(), bOut.toByteArray()));
    }

    /**
     * The keep map is walked by the rebuild the import path runs before anything validates the
     * state, exactly as the retain map beside it is, so both are refused where the stream enters.
     * Left to the rebuild, a null key is a NullPointerException out of the middle of it rather
     * than the IOException a caller of PrivateKeyFactory.createKey is already handling.
     */
    public void testCraftedNullKeyInStateMapsReported()
        throws Exception
    {
        String[] fields = new String[]{"keep", "retain"};

        for (int i = 0; i != fields.length; i++)
        {
            try
            {
                PrivateKeyFactory.createKey(keyWithNullKeyIn(fields[i]));
                fail("null key in " + fields[i] + " accepted");
            }
            catch (IOException e)
            {
                assertEquals("incomplete BDS state", e.getMessage());
            }
        }
    }

    /**
     * A real BDS, serialized with the first node of its authentication path replaced by
     * {@code node}. Java deserialization writes an object's fields directly, so it can hand back
     * an XMSSNode holding no value, or one of the wrong length - shapes that none of this
     * package's calls to that constructor produce, every one of them passing an array it has just
     * built to the length its parameters fix. BDS.readObject() does not walk into the nodes its
     * collections hold, and says so; validate() is what checks them.
     * <p>
     * The authentication path rather than the root because the root has a second net behind it:
     * validateRoot() compares it against the one the private key declares and would refuse either
     * shape there whatever validate() did. Nothing stands behind a path node, which is hashed by
     * randomizeHash() the next time the state advances.
     */
    private static PrivateKeyInfo keyWithNodeInAuthenticationPath(XMSSNode node)
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(4, NISTObjectIdentifiers.id_sha256);
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

        // as in keyWithNullKeyIn above, take the key apart while its state is still sound
        PrivateKeyInfo info = PrivateKeyInfoFactory.createPrivateKeyInfo(kp.getPrivate());
        XMSSPrivateKey asn1 = XMSSPrivateKey.getInstance(info.parsePrivateKey());

        BDS bds = ((XMSSPrivateKeyParameters)kp.getPrivate()).getBDSState();

        // getAuthenticationPath() hands back a copy, so the field itself is replaced
        List<XMSSNode> path = bds.getAuthenticationPath();

        path.set(0, node);

        Field f = BDS.class.getDeclaredField("authenticationPath");

        f.setAccessible(true);
        f.set(bds, path);

        return new PrivateKeyInfo(info.getPrivateKeyAlgorithm(),
            new XMSSPrivateKey(asn1.getIndex(), asn1.getSecretKeySeed(), asn1.getSecretKeyPRF(),
                asn1.getPublicSeed(), asn1.getRoot(), serialize(bds)));
    }

    /**
     * A node whose value is not the tree digest's size is out of bounds, and one carrying no
     * value at all is reported rather than dereferenced. validate() asks both questions at once
     * through hasValueLength(), which answers false for an absent value; asking through
     * getValue() would answer the same by cloning the value first, and asking through
     * getValueLength() would not answer at all.
     * <p>
     * Both nodes are given the height validate() expects of the first node of a path, so that
     * what it reports is the value rather than a height out of bounds - the two share a message.
     */
    public void testCraftedNodeValueReported()
        throws Exception
    {
        XMSSNode[] nodes = new XMSSNode[]{new XMSSNode(0, null), new XMSSNode(0, new byte[31])};

        for (int i = 0; i != nodes.length; i++)
        {
            try
            {
                PrivateKeyFactory.createKey(keyWithNodeInAuthenticationPath(nodes[i]));
                fail("XMSS node with a bad value accepted");
            }
            catch (IOException e)
            {
                assertEquals("malformed XMSS private key: XMSS node in BDS state out of bounds",
                    e.getMessage());
            }
        }
    }

    public void testCraftedXMSSMTStateReported()
        throws Exception
    {
        // height 4 over 2 layers is not one of the RFC 8391 sec. 5.4 registered sets, so the key
        // is written in the legacy form that carries a serialized state rather than the RFC 9802
        // raw form, which carries none
        XMSSMTParameters params = new XMSSMTParameters(4, 2, NISTObjectIdentifiers.id_sha256);
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        PrivateKeyInfo info = PrivateKeyInfoFactory.createPrivateKeyInfo(kp.getPrivate());
        XMSSMTPrivateKey asn1 = XMSSMTPrivateKey.getInstance(info.parsePrivateKey());

        PrivateKeyInfo crafted = new PrivateKeyInfo(info.getPrivateKeyAlgorithm(),
            new XMSSMTPrivateKey(asn1.getIndex(), asn1.getSecretKeySeed(), asn1.getSecretKeyPRF(),
                asn1.getPublicSeed(), asn1.getRoot(), craftedBDSStateMap()));

        try
        {
            PrivateKeyFactory.createKey(crafted);
            fail("crafted BDS state map accepted");
        }
        catch (IOException e)
        {
            assertEquals("no state in BDS state map", e.getMessage());
        }
    }

    /**
     * The block data a class's own writeObject() left behind, with one extra byte in it. The
     * serialized form of an object whose class writes custom data ends with a block data record -
     * TC_BLOCKDATA, a one byte length, the data - and then TC_ENDBLOCKDATA, so widening that
     * record by a byte puts the byte inside the object's own data rather than after the object,
     * which is the distinction that matters: bytes after the object are what
     * XMSSUtil.deserialize's "unexpected data found at end of ObjectInputStream" covers, and
     * bytes inside it are consumed by the read that recovers the object, leaving the stream at
     * its end by the time that check looks.
     *
     * @param serialized a serialized object ending in a block data record.
     * @param dataLength the length of that record.
     */
    private static byte[] withAByteAppendedInsideTheObject(byte[] serialized, int dataLength)
    {
        int end = serialized.length;

        assertEquals("not TC_ENDBLOCKDATA", TC_ENDBLOCKDATA, serialized[end - 1]);
        assertEquals("not the expected data length", dataLength, serialized[end - 2 - dataLength]);
        assertEquals("not TC_BLOCKDATA", TC_BLOCKDATA, serialized[end - 3 - dataLength]);

        byte[] out = new byte[end + 1];

        System.arraycopy(serialized, 0, out, 0, end - 2 - dataLength);
        out[end - 2 - dataLength] = (byte)(dataLength + 1);
        System.arraycopy(serialized, end - 1 - dataLength, out, end - 1 - dataLength, dataLength);
        out[end - 1] = (byte)0xff;
        out[end] = TC_ENDBLOCKDATA;

        return out;
    }

    private static byte[] serialize(Object obj)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(obj);
        oOut.close();

        return bOut.toByteArray();
    }

    /**
     * A state map encoding carrying a byte past the maximum index its readObject() reads is a
     * second encoding of the same state map, and the byte for byte equivalent on a BDS has always
     * been refused - "inconsistent BDS data detected", the last thing BDS.readObject() checks.
     * The two were reworked side by side onto read() and only one came away with the check, so
     * this asserts both families now answer the same way, and that the unpadded encoding either
     * one produces is still taken.
     */
    public void testLegacyStateWithTrailingDataRefused()
        throws Exception
    {
        // height 4 over 2 layers is not an RFC 8391 sec. 5.4 registered set, so the key is written
        // in the legacy form that carries a serialized state at all
        XMSSMTParameters mtParams = new XMSSMTParameters(4, 2, NISTObjectIdentifiers.id_sha256);
        XMSSMTKeyPairGenerator mtKpg = new XMSSMTKeyPairGenerator();

        mtKpg.init(new XMSSMTKeyGenerationParameters(mtParams, new SecureRandom()));

        AsymmetricCipherKeyPair mtKp = mtKpg.generateKeyPair();
        XMSSMTPrivateKeyParameters mtKey = (XMSSMTPrivateKeyParameters)mtKp.getPrivate();
        PrivateKeyInfo mtInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(mtKey);
        XMSSMTPrivateKey mtAsn1 = XMSSMTPrivateKey.getInstance(mtInfo.parsePrivateKey());

        // BDSStateMap.writeObject() writes an eight byte maximum index
        byte[] mtLegacy = serialize(mtKey.getBDSState());

        assertNotNull("the unpadded legacy state map is no longer read at all",
            PrivateKeyFactory.createKey(new PrivateKeyInfo(mtInfo.getPrivateKeyAlgorithm(),
                new XMSSMTPrivateKey(mtAsn1.getIndex(), mtAsn1.getSecretKeySeed(),
                    mtAsn1.getSecretKeyPRF(), mtAsn1.getPublicSeed(), mtAsn1.getRoot(), mtLegacy))));

        try
        {
            PrivateKeyFactory.createKey(new PrivateKeyInfo(mtInfo.getPrivateKeyAlgorithm(),
                new XMSSMTPrivateKey(mtAsn1.getIndex(), mtAsn1.getSecretKeySeed(),
                    mtAsn1.getSecretKeyPRF(), mtAsn1.getPublicSeed(), mtAsn1.getRoot(),
                    withAByteAppendedInsideTheObject(mtLegacy, 8))));
            fail("a legacy BDS state map with trailing data was accepted");
        }
        catch (IOException e)
        {
            assertEquals("inconsistent BDS state map data detected", e.getMessage());
        }

        XMSSParameters params = new XMSSParameters(4, NISTObjectIdentifiers.id_sha256);
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        XMSSPrivateKeyParameters key = (XMSSPrivateKeyParameters)kp.getPrivate();
        PrivateKeyInfo info = PrivateKeyInfoFactory.createPrivateKeyInfo(key);
        XMSSPrivateKey asn1 = XMSSPrivateKey.getInstance(info.parsePrivateKey());

        // BDS.writeObject() writes a four byte maximum index
        byte[] legacy = serialize(key.getBDSState());

        assertNotNull("the unpadded legacy BDS is no longer read at all",
            PrivateKeyFactory.createKey(new PrivateKeyInfo(info.getPrivateKeyAlgorithm(),
                new XMSSPrivateKey(asn1.getIndex(), asn1.getSecretKeySeed(), asn1.getSecretKeyPRF(),
                    asn1.getPublicSeed(), asn1.getRoot(), legacy))));

        try
        {
            PrivateKeyFactory.createKey(new PrivateKeyInfo(info.getPrivateKeyAlgorithm(),
                new XMSSPrivateKey(asn1.getIndex(), asn1.getSecretKeySeed(), asn1.getSecretKeyPRF(),
                    asn1.getPublicSeed(), asn1.getRoot(),
                    withAByteAppendedInsideTheObject(legacy, 4))));
            fail("a legacy BDS with trailing data was accepted");
        }
        catch (IOException e)
        {
            assertEquals("inconsistent BDS data detected", e.getMessage());
        }
    }
}
