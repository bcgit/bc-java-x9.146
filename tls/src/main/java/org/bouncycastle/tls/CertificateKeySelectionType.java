package org.bouncycastle.tls;

/**
 * Certificate Key Selection (CKS) code points, per ANSI X9.146 QTLS sec. 6.1 (draft 2026-07-21).
 * <p>
 * These are the wire values carried by the {@code certificate_key_selection}
 * extension and are the authority the handshake dispatches on. The
 * {@link KeySelection} enum must agree on every value.
 * <p>
 * Values 6-11 are the RFC 8773 PSK-hybrid family: a single certificate signature in a standard
 * CertificateVerify combined with an external PSK in the early secret. The value identifies both
 * the certificate type and which of its keys signs: 6 = Standard certificate, 7/8 = Chimera
 * native/alternative key, 9 = Composite, 10/11 = Related pair Main/Related certificate.
 */
public class CertificateKeySelectionType
{
    /*
     * X9.146 sec. 6.1 KeySelection enum (draft names in comments).
     */
    public static final short cks_default = 0;                          // default: classic, native only
    public static final short cks_chimera_native = 1;                   // chimera_native: ignore alternate
    public static final short cks_chimera_alternative = 2;              // chimera_alternative: ignore native
    public static final short cks_chimera_hybrid = 3;                   // chimera_hybrid: both (ExtendedCertificateVerify)
    public static final short cks_composite_hybrid = 4;                 // composite_hybrid
    public static final short cks_related_certs_hybrid = 5;             // related_certs_hybrid (RFC 9763), ExtendedCertificateVerify
    public static final short cks_addpsk_with_default = 6;              // addpsk_with_default (RFC 8773)
    public static final short cks_addpsk_with_chimera_native = 7;       // addpsk_with_chimera_native
    public static final short cks_addpsk_with_chimera_alternative = 8;  // addpsk_with_chimera_alternative
    public static final short cks_addpsk_with_composite = 9;            // addpsk_with_composite
    public static final short cks_addpsk_with_related_main = 10;        // addpsk_with_related_main
    public static final short cks_addpsk_with_related_related = 11;     // addpsk_with_related_related
    public static final short cks_reserved = 254;                       // Reserved for future use
    public static final short cks_external = 255;                       // Codes external to TLS
}
