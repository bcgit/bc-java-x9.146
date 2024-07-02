package org.bouncycastle.tls;

/**
 * X9.146
 */
public class CertificateKeySelectionType
{
    /*
     * X9.146
     */
    public static short cks_default = 0;    // native only (alternate not present)
    public static short cks_native = 1;     // ignore alternate
    public static short cks_alternate = 2;  // ignore native
    public static short cks_both = 3;       // native and alternate
    public static short cks_external = 4;   // codes are external to tls protocol ???

}
