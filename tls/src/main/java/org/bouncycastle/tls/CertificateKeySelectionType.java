package org.bouncycastle.tls;

/**
 * Certificate Key Selection (CKS) code points, per ANSI X9.146 QTLS sec. 6.1.
 * <p>
 * These are the wire values carried by the {@code certificate_key_selection}
 * extension and are the authority the handshake dispatches on. The
 * {@link KeySelection} enum must agree on every value.
 */
public class CertificateKeySelectionType
{
    /*
     * X9.146 sec. 6.1 KeySelection enum.
     */
    public static final short cks_default = 0;                          // Classic: native only (alternate not present)
    public static final short cks_native = 1;                           // Chimera: native default - ignore alternate
    public static final short cks_alternate = 2;                        // Chimera: alternate only - ignore native
    public static final short cks_both = 3;                             // Chimera: native and alternate (ExtendedCertificateVerify)
    public static final short cks_composite_hybrid = 4;                 // Composite Hybrid signature
    public static final short cks_related_certificates_pair_hybrid = 5; // Related Certificates Pair (RFC 9763), ExtendedCertificateVerify
    public static final short cks_psk_with_certificate_validation = 6;  // PSK with Certificate Validation (RFC 8773)
    public static final short cks_reserved = 254;                       // Reserved for future use
    public static final short cks_external = 255;                       // Codes external to TLS
}
