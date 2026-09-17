package org.bouncycastle.crypto.signers.xmss;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * The WOTS+ parameter sets, keyed by the parameters that pick one: RFC 8391 sec. 5.2 and NIST
 * SP 800-208 sec. 5.
 */
final class WOTSPlusOid
    extends XMSSOid
{
    /**
     * WOTS+ OID lookup table.
     */
    private static final Map<String, WOTSPlusOid> oidLookupTable;

    static
    {
        Map<String, WOTSPlusOid> map = new HashMap<String, WOTSPlusOid>();
        // RFC 8391
        map.put(createKey("SHA-256", 32, 16, 67), new WOTSPlusOid(0x01000001, "WOTSP_SHA2-256_W16"));
        map.put(createKey("SHA-512", 64, 16, 131), new WOTSPlusOid(0x02000002, "WOTSP_SHA2-512_W16"));
        map.put(createKey("SHAKE128", 32, 16, 67), new WOTSPlusOid(0x03000003, "WOTSP_SHAKE128_W16"));
        map.put(createKey("SHAKE256", 64, 16, 131), new WOTSPlusOid(0x04000004, "WOTSP_SHAKE256_W16"));

        // SP 800-208
        map.put(createKey("SHA-256", 24, 16, 51), new WOTSPlusOid(0x05000005, "WOTSP_SHA2-192_W16"));
        map.put(createKey("SHAKE256-LEN", 32, 16, 67), new WOTSPlusOid(0x06000006, "WOTSP_SHAKE256_256_W16"));
        map.put(createKey("SHAKE256-LEN", 24, 16, 51), new WOTSPlusOid(0x07000007, "WOTSP_SHAKE256_192_W16"));

        oidLookupTable = Collections.unmodifiableMap(map);
    }

    private WOTSPlusOid(int oid, String stringRepresentation)
    {
        super(oid, stringRepresentation);
    }

    /**
     * Lookup OID.
     *
     * @param algorithmName       Algorithm name.
     * @param winternitzParameter Winternitz parameter.
     * @return WOTS+ OID if parameters were found, null else.
     */
    public static WOTSPlusOid lookup(String algorithmName, int digestSize, int winternitzParameter, int len)
    {
        if (algorithmName == null)
        {
            throw new NullPointerException("algorithmName == null");
        }
        return oidLookupTable.get(createKey(algorithmName, digestSize, winternitzParameter, len));
    }
}
