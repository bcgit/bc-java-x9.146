package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * The ExtendedCertificateVerify message of ANSI X9.146 QTLS (draft 2026-07-07 sec. 6.4).
 * <p>
 * It carries two independently-signalled signatures and is used in place of the RFC 8446
 * {@link CertificateVerify} body (under handshake type {@code certificate_verify(15)}) if and
 * only if the negotiated CKS value is {@code cks_both(3)} or
 * {@code cks_related_certificates_pair_hybrid(5)}:
 * <pre>
 * struct {
 *     SignatureScheme primaryAlgorithm;
 *     opaque         signature&lt;0..2^16-1&gt;;
 *     SignatureScheme altAlgorithm;
 *     opaque         altSignature&lt;0..2^16-1&gt;;
 * } ExtendedCertificateVerify;
 * </pre>
 * Each signature is verified against its own explicitly-signalled scheme, unlike the pre-2026
 * interim transport that repurposed a single combined {@code SignatureScheme} codepoint and
 * concatenated the two signatures into one {@code DigitallySigned} body.
 *
 * @see TlsUtils#cksUsesExtendedCertificateVerify(short)
 */
public final class ExtendedCertificateVerify
{
    private final int primaryAlgorithm;
    private final byte[] primarySignature;
    private final int altAlgorithm;
    private final byte[] altSignature;

    public ExtendedCertificateVerify(int primaryAlgorithm, byte[] primarySignature, int altAlgorithm,
        byte[] altSignature)
    {
        if (!TlsUtils.isValidUint16(primaryAlgorithm))
        {
            throw new IllegalArgumentException("'primaryAlgorithm'");
        }
        if (!TlsUtils.isValidUint16(altAlgorithm))
        {
            throw new IllegalArgumentException("'altAlgorithm'");
        }
        if (primarySignature == null)
        {
            throw new NullPointerException("'primarySignature' cannot be null");
        }
        if (altSignature == null)
        {
            throw new NullPointerException("'altSignature' cannot be null");
        }

        this.primaryAlgorithm = primaryAlgorithm;
        this.primarySignature = primarySignature;
        this.altAlgorithm = altAlgorithm;
        this.altSignature = altSignature;
    }

    /**
     * @return the primary algorithm (a signature scheme)
     * @see SignatureScheme
     */
    public int getPrimaryAlgorithm()
    {
        return primaryAlgorithm;
    }

    public byte[] getPrimarySignature()
    {
        return primarySignature;
    }

    /**
     * @return the alternate algorithm (a signature scheme)
     * @see SignatureScheme
     */
    public int getAltAlgorithm()
    {
        return altAlgorithm;
    }

    public byte[] getAltSignature()
    {
        return altSignature;
    }

    /**
     * Encode this {@link ExtendedCertificateVerify} to an {@link OutputStream}.
     *
     * @param output
     *            the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output) throws IOException
    {
        TlsUtils.writeUint16(primaryAlgorithm, output);
        TlsUtils.writeOpaque16(primarySignature, output);
        TlsUtils.writeUint16(altAlgorithm, output);
        TlsUtils.writeOpaque16(altSignature, output);
    }

    /**
     * Parse an {@link ExtendedCertificateVerify} from an {@link InputStream}.
     *
     * @param context
     *            the {@link TlsContext} of the current connection.
     * @param input
     *            the {@link InputStream} to parse from.
     * @return an {@link ExtendedCertificateVerify} object.
     * @throws IOException
     */
    public static ExtendedCertificateVerify parse(TlsContext context, InputStream input) throws IOException
    {
        if (!TlsUtils.isTLSv13(context))
        {
            throw new IllegalStateException();
        }

        int primaryAlgorithm = TlsUtils.readUint16(input);
        byte[] primarySignature = TlsUtils.readOpaque16(input);
        int altAlgorithm = TlsUtils.readUint16(input);
        byte[] altSignature = TlsUtils.readOpaque16(input);
        return new ExtendedCertificateVerify(primaryAlgorithm, primarySignature, altAlgorithm, altSignature);
    }
}
