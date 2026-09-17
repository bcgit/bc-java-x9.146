package org.bouncycastle.crypto.signers.xmss;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * The XMSS parameter sets, keyed by the parameters that pick one: RFC 8391 sec. 5.3 and NIST
 * SP 800-208 sec. 5.
 */
final class DefaultXMSSOid
    extends XMSSOid
{
    /**
     * XMSS OID lookup table.
     */
    private static final Map<String, DefaultXMSSOid> oidLookupTable;

    static
    {
        Map<String, DefaultXMSSOid> map = new HashMap<String, DefaultXMSSOid>();
        // RFC 8391
        map.put(createKey("SHA-256", 32, 16, 67, 10), new DefaultXMSSOid(0x00000001, "XMSS_SHA2_10_256"));
        map.put(createKey("SHA-256", 32, 16, 67, 16), new DefaultXMSSOid(0x00000002, "XMSS_SHA2_16_256"));
        map.put(createKey("SHA-256", 32, 16, 67, 20), new DefaultXMSSOid(0x00000003, "XMSS_SHA2_20_256"));
        map.put(createKey("SHA-512", 64, 16, 131, 10), new DefaultXMSSOid(0x00000004, "XMSS_SHA2_10_512"));
        map.put(createKey("SHA-512", 64, 16, 131, 16), new DefaultXMSSOid(0x00000005, "XMSS_SHA2_16_512"));
        map.put(createKey("SHA-512", 64, 16, 131, 20), new DefaultXMSSOid(0x00000006, "XMSS_SHA2_20_512"));
        map.put(createKey("SHAKE128", 32, 16, 67, 10), new DefaultXMSSOid(0x00000007, "XMSS_SHAKE_10_256"));
        map.put(createKey("SHAKE128", 32, 16, 67, 16), new DefaultXMSSOid(0x00000008, "XMSS_SHAKE_16_256"));
        map.put(createKey("SHAKE128", 32, 16, 67, 20), new DefaultXMSSOid(0x00000009, "XMSS_SHAKE_20_256"));
        map.put(createKey("SHAKE256", 64, 16, 131, 10), new DefaultXMSSOid(0x0000000a, "XMSS_SHAKE_10_512"));
        map.put(createKey("SHAKE256", 64, 16, 131, 16), new DefaultXMSSOid(0x0000000b, "XMSS_SHAKE_16_512"));
        map.put(createKey("SHAKE256", 64, 16, 131, 20), new DefaultXMSSOid(0x0000000c, "XMSS_SHAKE_20_512"));

        // SP 800-208: SHA-256/192 (n=24)
        map.put(createKey("SHA-256", 24, 16, 51, 10), new DefaultXMSSOid(0x0000000d, "XMSS_SHA2_10_192"));
        map.put(createKey("SHA-256", 24, 16, 51, 16), new DefaultXMSSOid(0x0000000e, "XMSS_SHA2_16_192"));
        map.put(createKey("SHA-256", 24, 16, 51, 20), new DefaultXMSSOid(0x0000000f, "XMSS_SHA2_20_192"));

        // SP 800-208: SHAKE256/256 (n=32)
        map.put(createKey("SHAKE256-LEN", 32, 16, 67, 10), new DefaultXMSSOid(0x00000010, "XMSS_SHAKE256_10_256"));
        map.put(createKey("SHAKE256-LEN", 32, 16, 67, 16), new DefaultXMSSOid(0x00000011, "XMSS_SHAKE256_16_256"));
        map.put(createKey("SHAKE256-LEN", 32, 16, 67, 20), new DefaultXMSSOid(0x00000012, "XMSS_SHAKE256_20_256"));

        // SP 800-208: SHAKE256/192 (n=24)
        map.put(createKey("SHAKE256-LEN", 24, 16, 51, 10), new DefaultXMSSOid(0x00000013, "XMSS_SHAKE256_10_192"));
        map.put(createKey("SHAKE256-LEN", 24, 16, 51, 16), new DefaultXMSSOid(0x00000014, "XMSS_SHAKE256_16_192"));
        map.put(createKey("SHAKE256-LEN", 24, 16, 51, 20), new DefaultXMSSOid(0x00000015, "XMSS_SHAKE256_20_192"));

        oidLookupTable = Collections.unmodifiableMap(map);
    }

    private DefaultXMSSOid(int oid, String stringRepresentation)
    {
        super(oid, stringRepresentation);
    }

    /**
     * Lookup OID.
     *
     * @param algorithmName       Algorithm name.
     * @param winternitzParameter Winternitz parameter.
     * @param height              Binary tree height.
     * @return XMSS OID if parameters were found, null else.
     */
    public static DefaultXMSSOid lookup(String algorithmName, int digestSize, int winternitzParameter, int len,
                                        int height)
    {
        if (algorithmName == null)
        {
            throw new NullPointerException("algorithmName == null");
        }
        return oidLookupTable.get(createKey(algorithmName, digestSize, winternitzParameter, len, height));
    }
}
