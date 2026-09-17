package org.bouncycastle.cert.plants.test;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cert.plants.MerkleTreeHash;
import org.bouncycastle.cert.plants.MerkleTreePrimitives;
import org.bouncycastle.cert.plants.bc.BcSha256MerkleTreeHash;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * The accumulated subtree test vectors of Appendix C of
 * draft-ietf-plants-merkle-tree-certs-05. For trees of every size up to 130,
 * with leaf {@code d[i]} the single byte {@code i}, each output of the
 * Section 4 algorithms is rendered as a text line and folded into one running
 * SHA-256; the draft fixes the four resulting digests.
 */
public class SubtreeTestVectorsTest
    extends SimpleTest
{
    private static final int MAX_SIZE = 130;

    private static final String SUBTREE_HASHES = "94a95384a8c69acea9b50d035a58285b3a777cb7a724005faa5e1f1e1190007f";
    private static final String INCLUSION_PROOFS = "ac2a8f989e44d99e399db448050ff5f19757df53cfb716aa81015d3955d8163f";
    private static final String CONSISTENCY_PROOFS = "c586ebbb73a5621baf2140095d87dde934e3b6503a562a1a5215b8209edd083d";
    private static final String COVERING_SUBTREES = "e0aecb912a10c57d753b6ecc64db73217f9bc4ed10fcb4e9062be3b6fbe1ebfd";

    public String getName()
    {
        return "SubtreeTestVectors";
    }

    public void performTest()
        throws Exception
    {
        MerkleTreeHash hash = new BcSha256MerkleTreeHash();
        List<byte[]> entries = new ArrayList<byte[]>(MAX_SIZE);
        for (int i = 0; i < MAX_SIZE; i++)
        {
            entries.add(hash.hashLeaf(new byte[]{ (byte)i }));
        }

        subtreeHashes(entries, hash);
        inclusionProofs(entries, hash);
        consistencyProofs(entries, hash);
        coveringSubtrees();
    }

    // C.1: "[START, END) HASH\n" for every valid subtree.
    private void subtreeHashes(List<byte[]> entries, MerkleTreeHash hash)
    {
        Digest acc = new SHA256Digest();
        for (int end = 1; end <= MAX_SIZE; end++)
        {
            for (int start = 0; start < end; start++)
            {
                if (MerkleTreePrimitives.isValidSubtree(start, end))
                {
                    byte[] mth = MerkleTreePrimitives.computeMerkleTreeHash(entries, start, end, hash);
                    update(acc, interval(start, end) + " " + Hex.toHexString(mth) + "\n");
                }
            }
        }
        check("C.1 subtree hashes", acc, SUBTREE_HASHES);
    }

    // C.2: "INDEX [START, END)" + " HASH" per proof node + "\n" for every entry of every valid subtree.
    private void inclusionProofs(List<byte[]> entries, MerkleTreeHash hash)
    {
        Digest acc = new SHA256Digest();
        for (int end = 1; end <= MAX_SIZE; end++)
        {
            for (int start = 0; start < end; start++)
            {
                if (!MerkleTreePrimitives.isValidSubtree(start, end))
                {
                    continue;
                }
                for (int index = start; index < end; index++)
                {
                    List<byte[]> proof = MerkleTreePrimitives.generateSubtreeInclusionProof(
                        index, start, end, entries, hash);
                    update(acc, index + " " + interval(start, end) + hashes(proof) + "\n");
                }
            }
        }
        check("C.2 subtree inclusion proofs", acc, INCLUSION_PROOFS);
    }

    // C.3: "[START, END) N" + " HASH" per proof node + "\n" for every valid subtree of every tree size n.
    private void consistencyProofs(List<byte[]> entries, MerkleTreeHash hash)
    {
        Digest acc = new SHA256Digest();
        for (int n = 0; n <= MAX_SIZE; n++)
        {
            for (int end = 1; end <= n; end++)
            {
                for (int start = 0; start < end; start++)
                {
                    if (!MerkleTreePrimitives.isValidSubtree(start, end))
                    {
                        continue;
                    }
                    List<byte[]> proof = MerkleTreePrimitives.generateSubtreeConsistencyProof(
                        start, end, n, entries, hash);
                    update(acc, interval(start, end) + " " + n + hashes(proof) + "\n");
                }
            }
        }
        check("C.3 subtree consistency proofs", acc, CONSISTENCY_PROOFS);
    }

    // C.4: "[START, END)\n" for a valid subtree, else the two covering subtrees "[LS, LE) [RS, RE)\n".
    private void coveringSubtrees()
    {
        Digest acc = new SHA256Digest();
        for (int end = 1; end <= MAX_SIZE; end++)
        {
            for (int start = 0; start < end; start++)
            {
                if (MerkleTreePrimitives.isValidSubtree(start, end))
                {
                    update(acc, interval(start, end) + "\n");
                }
                else
                {
                    List<long[]> covering = MerkleTreePrimitives.findCoveringSubtrees(start, end);
                    isTrue("two covering subtrees for " + interval(start, end), covering.size() == 2);
                    long[] left = (long[])covering.get(0);
                    long[] right = (long[])covering.get(1);
                    update(acc, interval(left[0], left[1]) + " " + interval(right[0], right[1]) + "\n");
                }
            }
        }
        check("C.4 efficient covering subtrees", acc, COVERING_SUBTREES);
    }

    private static String interval(long start, long end)
    {
        return "[" + start + ", " + end + ")";
    }

    private static String hashes(List<byte[]> proof)
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < proof.size(); i++)
        {
            sb.append(' ').append(Hex.toHexString((byte[])proof.get(i)));
        }
        return sb.toString();
    }

    private static void update(Digest acc, String line)
    {
        byte[] bytes = Strings.toByteArray(line);
        acc.update(bytes, 0, bytes.length);
    }

    private void check(String name, Digest acc, String expectedHex)
    {
        byte[] out = new byte[acc.getDigestSize()];
        acc.doFinal(out, 0);
        String actual = Hex.toHexString(out);
        if (!expectedHex.equals(actual))
        {
            fail(name + ": accumulated digest " + actual + " does not match the draft's " + expectedHex);
        }
    }

    public static void main(String[] args)
    {
        runTest(new SubtreeTestVectorsTest());
    }
}
