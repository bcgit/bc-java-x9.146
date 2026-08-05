package org.bouncycastle.tls;

/**
 * Enum representing KeySelection types as described in X9.146 sec. 6.1 (draft 2026-07-21).
 * Names track the draft's enum entries ({@code default}, {@code chimera_native}, ...,
 * {@code addpsk_with_related_related}) within Java naming constraints. Wire values must agree
 * with {@link CertificateKeySelectionType}.
 */
public enum KeySelection
{
    Default(0),                          // default: Classic Certificates
    Chimera_Native(1),                   // chimera_native: Chimera Native Key's Signature
    Chimera_Alternative(2),              // chimera_alternative: Chimera Alternate Key's Signature
    Chimera_Hybrid(3),                   // chimera_hybrid: Chimera Concatenated Signatures
    Composite_Hybrid(4),                 // composite_hybrid: Composite Hybrid Signature
    Related_Certs_Hybrid(5),             // related_certs_hybrid: Related Certificates Pair (RFC 9763)
    AddPSK_with_Default(6),              // addpsk_with_default: Standard Certificate with PSK (RFC 8773)
    AddPSK_with_Chimera_Native(7),       // addpsk_with_chimera_native: Chimera (Primary Key) with PSK
    AddPSK_with_Chimera_Alternative(8),  // addpsk_with_chimera_alternative: Chimera (Alt Key) with PSK
    AddPSK_with_Composite(9),            // addpsk_with_composite: Composite Certificate with PSK
    AddPSK_with_Related_Main(10),        // addpsk_with_related_main: Related Pair (Main) with PSK
    AddPSK_with_Related_Related(11),     // addpsk_with_related_related: Related Pair (Related) with PSK
    Reserved(254),                       // Reserved for future use
    External(255);                       // Codes external to TLS

    private final int value;

    KeySelection(int value)
    {
        this.value = value;
    }

    public int getValue()
    {
        return value;
    }
}
