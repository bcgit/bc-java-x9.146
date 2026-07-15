package org.bouncycastle.tls;

/**
 * Enum representing KeySelection types as described in X9.146.
 */
public enum KeySelection
{
    Default(0),                          // Classic Certificates
    Chimera_Native(1),                   // Chimera Native Key’s Signature
    Chimera_Alternative(2),              // Chimera Alternate Key’s Signature
    Chimera_Hybrid(3),                   // Chimera Concatenated Signatures
    Composite_Hybrid(4),                 // Composite Hybrid Signature
    Related_Certificates_Pair_Hybrid(5), // Related Certificates Pair (RFC 9763; draft enum text cites RFC 7924)
    PSK_with_Certificate_Validation(6),  // PSK with Certificate Validation (RFC 8773)
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