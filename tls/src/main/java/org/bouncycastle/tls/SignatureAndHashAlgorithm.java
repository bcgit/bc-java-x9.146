package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * RFC 5246 7.4.1.4.1
 */
public class SignatureAndHashAlgorithm
{
    public static final SignatureAndHashAlgorithm ecdsa_brainpoolP256r1tls13_sha256 =
        create(SignatureScheme.ecdsa_brainpoolP256r1tls13_sha256);
    public static final SignatureAndHashAlgorithm ecdsa_brainpoolP384r1tls13_sha384 =
        create(SignatureScheme.ecdsa_brainpoolP384r1tls13_sha384);
    public static final SignatureAndHashAlgorithm ecdsa_brainpoolP512r1tls13_sha512 =
        create(SignatureScheme.ecdsa_brainpoolP512r1tls13_sha512);
    public static final SignatureAndHashAlgorithm ed25519 =
        create(SignatureScheme.ed25519);
    public static final SignatureAndHashAlgorithm ed448 =
        create(SignatureScheme.ed448);

    //TODO[x9145]: add falcon
    public static final SignatureAndHashAlgorithm OQS_CODEPOINT_P256_MLDSA44 =
            create(SignatureScheme.OQS_CODEPOINT_P256_MLDSA44);
    public static final SignatureAndHashAlgorithm OQS_CODEPOINT_RSA3072_MLDSA44 =
            create(SignatureScheme.OQS_CODEPOINT_RSA3072_MLDSA44);
    public static final SignatureAndHashAlgorithm OQS_CODEPOINT_P384_MLDSA65 =
            create(SignatureScheme.OQS_CODEPOINT_P384_MLDSA65);
    public static final SignatureAndHashAlgorithm OQS_CODEPOINT_P521_MLDSA87 =
            create(SignatureScheme.OQS_CODEPOINT_P521_MLDSA87);
    public static final SignatureAndHashAlgorithm WOLFSSL_HYBRID_P256_MLDSA_LEVEL2 =
            create(SignatureScheme.WOLFSSL_HYBRID_P256_MLDSA_LEVEL2);
    public static final SignatureAndHashAlgorithm WOLFSSL_HYBRID_RSA3072_MLDSA_LEVEL2 =
            create(SignatureScheme.WOLFSSL_HYBRID_RSA3072_MLDSA_LEVEL2);
    public static final SignatureAndHashAlgorithm WOLFSSL_HYBRID_P384_MLDSA_LEVEL3 =
            create(SignatureScheme.WOLFSSL_HYBRID_P384_MLDSA_LEVEL3);
    public static final SignatureAndHashAlgorithm WOLFSSL_HYBRID_P521_MLDSA_LEVEL5 =
            create(SignatureScheme.WOLFSSL_HYBRID_P521_MLDSA_LEVEL5);


    public static final SignatureAndHashAlgorithm DRAFT_mldsa44 =
        create(SignatureScheme.DRAFT_mldsa44);
    public static final SignatureAndHashAlgorithm DRAFT_mldsa65 =
            create(SignatureScheme.DRAFT_mldsa65);
    public static final SignatureAndHashAlgorithm DRAFT_mldsa87 =
            create(SignatureScheme.DRAFT_mldsa87);
    public static final SignatureAndHashAlgorithm mldsa44_ecdsa_secp256r1_sha256 =
            create(SignatureScheme.mldsa44_ecdsa_secp256r1_sha256);
    public static final SignatureAndHashAlgorithm mldsa65_ecdsa_secp384r1_sha384 =
            create(SignatureScheme.mldsa65_ecdsa_secp384r1_sha384);
    public static final SignatureAndHashAlgorithm mldsa87_ecdsa_secp521r1_sha51 =
            create(SignatureScheme.mldsa87_ecdsa_secp521r1_sha51);
    public static final SignatureAndHashAlgorithm mldsa44_ed25519 =
            create(SignatureScheme.mldsa44_ed25519);
    public static final SignatureAndHashAlgorithm mldsa65_ed25519 =
            create(SignatureScheme.mldsa65_ed25519);
    public static final SignatureAndHashAlgorithm mldsa44_rsa2048_pkcs1_sha256 =
            create(SignatureScheme.mldsa44_rsa2048_pkcs1_sha256);
    public static final SignatureAndHashAlgorithm mldsa65_rsa3072_pkcs1_sha256 =
            create(SignatureScheme.mldsa65_rsa3072_pkcs1_sha256);
    public static final SignatureAndHashAlgorithm mldsa65_rsa4096_pkcs1_sha384 =
            create(SignatureScheme.mldsa65_rsa4096_pkcs1_sha384);
    public static final SignatureAndHashAlgorithm mldsa44_rsa2048_pss_pss_sha256 =
            create(SignatureScheme.mldsa44_rsa2048_pss_pss_sha256);
    public static final SignatureAndHashAlgorithm mldsa65_rsa3072_pss_pss_sha256 =
            create(SignatureScheme.mldsa65_rsa3072_pss_pss_sha256);
    public static final SignatureAndHashAlgorithm mldsa65_rsa4096_pss_pss_sha384 =
            create(SignatureScheme.mldsa65_rsa4096_pss_pss_sha384);
    public static final SignatureAndHashAlgorithm mldsa87_ed448 =
            create(SignatureScheme.mldsa87_ed448);

    public static final SignatureAndHashAlgorithm gostr34102012_256 =
        create(HashAlgorithm.Intrinsic, SignatureAlgorithm.gostr34102012_256);
    public static final SignatureAndHashAlgorithm gostr34102012_512 =
        create(HashAlgorithm.Intrinsic, SignatureAlgorithm.gostr34102012_512);
    public static final SignatureAndHashAlgorithm rsa_pss_rsae_sha256 =
        create(SignatureScheme.rsa_pss_rsae_sha256);
    public static final SignatureAndHashAlgorithm rsa_pss_rsae_sha384 =
        create(SignatureScheme.rsa_pss_rsae_sha384);
    public static final SignatureAndHashAlgorithm rsa_pss_rsae_sha512 =
        create(SignatureScheme.rsa_pss_rsae_sha512);
    public static final SignatureAndHashAlgorithm rsa_pss_pss_sha256 =
        create(SignatureScheme.rsa_pss_pss_sha256);
    public static final SignatureAndHashAlgorithm rsa_pss_pss_sha384 =
        create(SignatureScheme.rsa_pss_pss_sha384);
    public static final SignatureAndHashAlgorithm rsa_pss_pss_sha512 =
        create(SignatureScheme.rsa_pss_pss_sha512);

//TODO[x9145]: No hash algorithm, find another way
    public static SignatureAndHashAlgorithm getHybrid(SignatureAndHashAlgorithm nativeAlg, SignatureAndHashAlgorithm altAlg)
    {
        if (nativeAlg.equals(create(SignatureScheme.ecdsa_secp256r1_sha256)) && altAlg.equals(SignatureAndHashAlgorithm.DRAFT_mldsa44))
        {
            return SignatureAndHashAlgorithm.WOLFSSL_HYBRID_P256_MLDSA_LEVEL2;
        }
        if (nativeAlg.equals(create(SignatureScheme.ecdsa_secp384r1_sha384)) && altAlg.equals(SignatureAndHashAlgorithm.DRAFT_mldsa65))
        {
            return SignatureAndHashAlgorithm.WOLFSSL_HYBRID_P384_MLDSA_LEVEL3;
        }
        if (nativeAlg.equals(create(SignatureScheme.ecdsa_secp521r1_sha512)) && altAlg.equals(SignatureAndHashAlgorithm.DRAFT_mldsa87))
        {
            return SignatureAndHashAlgorithm.WOLFSSL_HYBRID_P521_MLDSA_LEVEL5;
        }
        if (nativeAlg.equals(create(SignatureScheme.rsa_pss_rsae_sha256)) && altAlg.equals(SignatureAndHashAlgorithm.DRAFT_mldsa44))
        {
            return SignatureAndHashAlgorithm.WOLFSSL_HYBRID_RSA3072_MLDSA_LEVEL2;
        }
        return null;
    }
    public static SignatureAndHashAlgorithm getInstance(short hashAlgorithm, short signatureAlgorithm)
    {
        switch (hashAlgorithm)
        {
        case HashAlgorithm.Intrinsic:
            return getInstanceIntrinsic(signatureAlgorithm);
        default:
            return create(hashAlgorithm, signatureAlgorithm);
        }
    }

    private static SignatureAndHashAlgorithm getInstanceIntrinsic(short signatureAlgorithm)
    {
        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.ed25519:
            return ed25519;
        case SignatureAlgorithm.ed448:
            return ed448;
        case SignatureAlgorithm.gostr34102012_256:
            return gostr34102012_256;
        case SignatureAlgorithm.gostr34102012_512:
            return gostr34102012_512;
        case SignatureAlgorithm.rsa_pss_rsae_sha256:
            return rsa_pss_rsae_sha256;
        case SignatureAlgorithm.rsa_pss_rsae_sha384:
            return rsa_pss_rsae_sha384;
        case SignatureAlgorithm.rsa_pss_rsae_sha512:
            return rsa_pss_rsae_sha512;
        case SignatureAlgorithm.rsa_pss_pss_sha256:
            return rsa_pss_pss_sha256;
        case SignatureAlgorithm.rsa_pss_pss_sha384:
            return rsa_pss_pss_sha384;
        case SignatureAlgorithm.rsa_pss_pss_sha512:
            return rsa_pss_pss_sha512;
        case SignatureAlgorithm.ecdsa_brainpoolP256r1tls13_sha256:
            return ecdsa_brainpoolP256r1tls13_sha256;
        case SignatureAlgorithm.ecdsa_brainpoolP384r1tls13_sha384:
            return ecdsa_brainpoolP384r1tls13_sha384;
        case SignatureAlgorithm.ecdsa_brainpoolP512r1tls13_sha512:
            return ecdsa_brainpoolP512r1tls13_sha512;
        //TODO[x9146]: add falcon
        default:
            return create(HashAlgorithm.Intrinsic, signatureAlgorithm);
        }
    }

    private static SignatureAndHashAlgorithm create(int signatureScheme)
    {
        short hashAlgorithm = SignatureScheme.getHashAlgorithm(signatureScheme);
        short signatureAlgorithm = SignatureScheme.getSignatureAlgorithm(signatureScheme);
        return create(hashAlgorithm, signatureAlgorithm);
    }

    private static SignatureAndHashAlgorithm create(short hashAlgorithm, short signatureAlgorithm)
    {
        return new SignatureAndHashAlgorithm(hashAlgorithm, signatureAlgorithm);
    }

    protected final short hash;
    protected final short signature;

    /**
     * @param hash      {@link HashAlgorithm}
     * @param signature {@link SignatureAlgorithm}
     */
    public SignatureAndHashAlgorithm(short hash, short signature)
    {
        /*
         * TODO]tls] The TlsUtils methods are inlined here to avoid circular static initialization
         * b/w these classes. We should refactor parts of TlsUtils into separate classes. e.g. the
         * TLS low-level encoding methods, and/or the SigAndHash registry and methods.
         */

//        if (!TlsUtils.isValidUint8(hash))
        if ((hash & 0xFF) != hash)
        {
            throw new IllegalArgumentException("'hash' should be a uint8");
        }
//        if (!TlsUtils.isValidUint8(signature))
        if ((signature & 0xFF) != signature)
        {
            throw new IllegalArgumentException("'signature' should be a uint8");
        }

        this.hash = hash;
        this.signature = signature;
    }

    /**
     * @return {@link HashAlgorithm}
     */
    public short getHash()
    {
        return hash;
    }

    /**
     * @return {@link SignatureAlgorithm}
     */
    public short getSignature()
    {
        return signature;
    }

    /**
     * Encode this {@link SignatureAndHashAlgorithm} to an {@link OutputStream}.
     *
     * @param output the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output)
        throws IOException
    {
        TlsUtils.writeUint8(getHash(), output);
        TlsUtils.writeUint8(getSignature(), output);
    }

    /**
     * Parse a {@link SignatureAndHashAlgorithm} from an {@link InputStream}.
     *
     * @param input the {@link InputStream} to parse from.
     * @return a {@link SignatureAndHashAlgorithm} object.
     * @throws IOException
     */
    public static SignatureAndHashAlgorithm parse(InputStream input)
        throws IOException
    {
        short hash = TlsUtils.readUint8(input);
        short signature = TlsUtils.readUint8(input);

        return getInstance(hash, signature);
    }

    public boolean equals(Object obj)
    {
        if (!(obj instanceof SignatureAndHashAlgorithm))
        {
            return false;
        }
        SignatureAndHashAlgorithm other = (SignatureAndHashAlgorithm)obj;
        return other.getHash() == getHash() && other.getSignature() == getSignature();
    }

    public int hashCode()
    {
        return (getHash() << 16) | getSignature();
    }

    public String toString()
    {
        return "{" + HashAlgorithm.getText(hash) + "," + SignatureAlgorithm.getText(signature) + "}";
    }
}
