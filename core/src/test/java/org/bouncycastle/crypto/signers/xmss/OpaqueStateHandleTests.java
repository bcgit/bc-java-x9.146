package org.bouncycastle.crypto.signers.xmss;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import junit.framework.TestCase;

/**
 * XMSSEngine's class javadoc names BDS and BDSStateMap the package's two opaque traversal-state
 * types: they are public only because an XMSS / XMSS^MT private key carries one as a field, so a
 * caller can obtain one from a live key and everything public on them is API.
 * <p>
 * That makes a public mutator on either of them a way to advance the signing position behind the
 * key's back, leaving the two records a stateful key keeps of that position disagreeing - and a
 * key whose state has run ahead of the index it reports signs twice under one one-time key, which
 * RFC 8391 sec. 1.1 exists to prevent. So the surface is listed here rather than left to drift:
 * the entries are read-only or return a fresh state, and a new one has to be added deliberately.
 * </p>
 */
public class OpaqueStateHandleTests
    extends TestCase
{
    public void testBDSExposesNoMutator()
    {
        assertPublicMethods(BDS.class, new String[]
        {
            "validate", "validateRoot", "getIndex", "getMaxIndex", "withWOTSDigest", "withMaxIndex"
        });
    }

    public void testBDSStateMapExposesNoMutator()
    {
        assertPublicMethods(BDSStateMap.class, new String[]
        {
            "validate", "validateIndex", "validateRoot", "getMaxIndex", "get", "withWOTSDigest",
            "withMaxIndex"
        });
    }

    private static void assertPublicMethods(Class clazz, String[] expected)
    {
        Set allowed = new HashSet(Arrays.asList(expected));
        Method[] methods = clazz.getDeclaredMethods();

        for (int i = 0; i != methods.length; i++)
        {
            if (Modifier.isPublic(methods[i].getModifiers()) && !methods[i].isSynthetic())
            {
                assertTrue(clazz.getSimpleName() + "." + methods[i].getName()
                    + " is public: a traversal-state handle exposes no operation that is not"
                    + " read-only or a fresh state", allowed.contains(methods[i].getName()));
            }
        }
    }
}
