package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.CryptoHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsCryptoUtils;

public class SignatureScheme
{
    /*
     * RFC 8446
     */

    public static final int rsa_pkcs1_sha1 = 0x0201;
    public static final int ecdsa_sha1 = 0x0203;

    public static final int rsa_pkcs1_sha256 = 0x0401;
    public static final int rsa_pkcs1_sha384 = 0x0501;
    public static final int rsa_pkcs1_sha512 = 0x0601;

    public static final int ecdsa_secp256r1_sha256 = 0x0403;
    public static final int ecdsa_secp384r1_sha384 = 0x0503;
    public static final int ecdsa_secp521r1_sha512 = 0x0603;

    public static final int rsa_pss_rsae_sha256 = 0x0804;
    public static final int rsa_pss_rsae_sha384 = 0x0805;
    public static final int rsa_pss_rsae_sha512 = 0x0806;

    public static final int ed25519 = 0x0807;
    public static final int ed448 = 0x0808;

    public static final int rsa_pss_pss_sha256 = 0x0809;
    public static final int rsa_pss_pss_sha384 = 0x080A;
    public static final int rsa_pss_pss_sha512 = 0x080B;

    /*
     * RFC 8734
     */

    public static final int ecdsa_brainpoolP256r1tls13_sha256 = 0x081A;
    public static final int ecdsa_brainpoolP384r1tls13_sha384 = 0x081B;
    public static final int ecdsa_brainpoolP512r1tls13_sha512 = 0x081C;

    /*
     * RFC 8998
     */

    public static final int sm2sig_sm3 = 0x0708;

    /*
     * draft-tls-westerbaan-mldsa-00
     */
    public static final int DRAFT_mldsa44 = 0x0904;
    public static final int DRAFT_mldsa65 = 0x0905;
    public static final int DRAFT_mldsa87 = 0x0906;


    /*
     * LIB OQS CODEPOINTS FOR WOLFSSL
     */
    public static final int OQS_CODEPOINT_P256_MLDSA44 = 0xff06;
    public static final int OQS_CODEPOINT_RSA3072_MLDSA44 = 0xff07;
    public static final int OQS_CODEPOINT_P384_MLDSA65 = 0xff08;
    public static final int OQS_CODEPOINT_P521_MLDSA87 = 0xff09;

    /*
     * wolf ssl hybrid codepoints
     */

    public static final int WOLFSSL_HYBRID_P256_MLDSA_LEVEL2    = 0xFEA1;
    public static final int WOLFSSL_HYBRID_RSA3072_MLDSA_LEVEL2 = 0xFEA2;
    public static final int WOLFSSL_HYBRID_P384_MLDSA_LEVEL3    = 0xFEA4;
    public static final int WOLFSSL_HYBRID_P521_MLDSA_LEVEL5    = 0xFEA6;

    /*
     * draft-reddy-tls-composite-mldsa-01
     */
    public static final int mldsa44_ecdsa_secp256r1_sha256 = 0x0907;
    public static final int mldsa65_ecdsa_secp384r1_sha384 = 0x0908;
    public static final int mldsa87_ecdsa_secp521r1_sha51 = 0x0909; // changed this to _secp521r1_sha51 instead of _secp384r1_sha384
    public static final int mldsa44_ed25519 = 0x090A;
    public static final int mldsa65_ed25519 = 0x090B;
    public static final int mldsa44_rsa2048_pkcs1_sha256 = 0x090C;
    public static final int mldsa65_rsa3072_pkcs1_sha256 = 0x090D;
    public static final int mldsa65_rsa4096_pkcs1_sha384 = 0x090E;
    public static final int mldsa44_rsa2048_pss_pss_sha256 = 0x090F;
    public static final int mldsa65_rsa3072_pss_pss_sha256 = 0x0910;
    public static final int mldsa65_rsa4096_pss_pss_sha384 = 0x0911;
    public static final int mldsa87_ed448 = 0x0912;
    /*
     * x9.164 OQS values for ml dsa
     */
//    public static final int X9146_mldsa44 = 0xFED0;
//    public static final int X9146_mldsa65 = 0xFED1;
//    public static final int X9146_mldsa87 = 0xFED2;
    /*
     * x9.164 OQS values for falcon
     */
    public static final int X9146_falcon512 = 0xFEAE;
    public static final int X9146_falcon1024 = 0xFEB1;

    /*
     * x9.164 OQS values for hybrid
     */
//    public static final int OQS_P256_MLDSA44 = 0xFF06;
//    public static final int OQS_RSA3072_MLDSA44 = 0xFF07;
//    public static final int OQS_P384_MLDSA65 = 0xFF08;
//    public static final int OQS_P521_MLDSA87 = 0xFF09;
//
//
//    public static final int X9146_HYBRID_P256_falcon512 = 0xFEAF;
//    public static final int X9146_HYBRID_RSA3072_falcon512 = 0xFEB0;
//    public static final int X9146_HYBRID_P521_falcon1024 = 0xFEB2;



    /*
     * RFC 8446 reserved for private use (0xFE00..0xFFFF)
     */

    public static int from(SignatureAndHashAlgorithm sigAndHashAlg)
    {
        if (null == sigAndHashAlg)
        {
            throw new NullPointerException();
        }

        return from(sigAndHashAlg.getHash(), sigAndHashAlg.getSignature());
    }

    public static int from(short hashAlgorithm, short signatureAlgorithm)
    {
        return ((hashAlgorithm & 0xFF) << 8) | (signatureAlgorithm & 0xFF);
    }

    public static int getCryptoHashAlgorithm(int signatureScheme)
    {
        switch (signatureScheme)
        {
        case ed25519:
        case ed448:
        case DRAFT_mldsa44:
        case DRAFT_mldsa65:
        case DRAFT_mldsa87:
            return -1;
        case ecdsa_brainpoolP256r1tls13_sha256:
        case rsa_pss_pss_sha256:
        case rsa_pss_rsae_sha256:
            return CryptoHashAlgorithm.sha256;
        case ecdsa_brainpoolP384r1tls13_sha384:
        case rsa_pss_pss_sha384:
        case rsa_pss_rsae_sha384:
            return CryptoHashAlgorithm.sha384;
        case ecdsa_brainpoolP512r1tls13_sha512:
        case rsa_pss_pss_sha512:
        case rsa_pss_rsae_sha512:
            return CryptoHashAlgorithm.sha512;
        case sm2sig_sm3:
            return CryptoHashAlgorithm.sm3;
        default:
        {
            short hashAlgorithm = getHashAlgorithm(signatureScheme);
            if (HashAlgorithm.Intrinsic == hashAlgorithm || !HashAlgorithm.isRecognized(hashAlgorithm))
            {
                return -1;
            }
            return TlsCryptoUtils.getHash(hashAlgorithm);
        }
        }
    }

    public static int getCryptoHashAlgorithm(SignatureAndHashAlgorithm signatureAndHashAlgorithm)
    {
        return getCryptoHashAlgorithm(from(signatureAndHashAlgorithm));
    }

    public static String getName(int signatureScheme)
    {
        switch (signatureScheme)
        {
        case rsa_pkcs1_sha1:
            return "rsa_pkcs1_sha1";
        case ecdsa_sha1:
            return "ecdsa_sha1";
        case rsa_pkcs1_sha256:
            return "rsa_pkcs1_sha256";
        case rsa_pkcs1_sha384:
            return "rsa_pkcs1_sha384";
        case rsa_pkcs1_sha512:
            return "rsa_pkcs1_sha512";
        case ecdsa_secp256r1_sha256:
            return "ecdsa_secp256r1_sha256";
        case ecdsa_secp384r1_sha384:
            return "ecdsa_secp384r1_sha384";
        case ecdsa_secp521r1_sha512:
            return "ecdsa_secp521r1_sha512";
        case rsa_pss_rsae_sha256:
            return "rsa_pss_rsae_sha256";
        case rsa_pss_rsae_sha384:
            return "rsa_pss_rsae_sha384";
        case rsa_pss_rsae_sha512:
            return "rsa_pss_rsae_sha512";
        case ed25519:
            return "ed25519";
        case ed448:
            return "ed448";
        case rsa_pss_pss_sha256:
            return "rsa_pss_pss_sha256";
        case rsa_pss_pss_sha384:
            return "rsa_pss_pss_sha384";
        case rsa_pss_pss_sha512:
            return "rsa_pss_pss_sha512";
        case ecdsa_brainpoolP256r1tls13_sha256:
            return "ecdsa_brainpoolP256r1tls13_sha256";
        case ecdsa_brainpoolP384r1tls13_sha384:
            return "ecdsa_brainpoolP384r1tls13_sha384";
        case ecdsa_brainpoolP512r1tls13_sha512:
            return "ecdsa_brainpoolP512r1tls13_sha512";
        case sm2sig_sm3:
            return "sm2sig_sm3";
        case DRAFT_mldsa44:
            return "DRAFT_mldsa44";
        case DRAFT_mldsa65:
            return "DRAFT_mldsa65";
        case DRAFT_mldsa87:
            return "DRAFT_mldsa87";
        default:
            return "UNKNOWN";
        }
    }

    /**
     * For TLS 1.3+ usage, some signature schemes are constrained to use a particular
     * ({@link NamedGroup}. Not relevant for TLS 1.2 and below.
     */
    public static int getNamedGroup(int signatureScheme)
    {
        switch (signatureScheme)
        {
        case ecdsa_brainpoolP256r1tls13_sha256:
            return NamedGroup.brainpoolP256r1tls13;
        case ecdsa_brainpoolP384r1tls13_sha384:
            return NamedGroup.brainpoolP384r1tls13;
        case ecdsa_brainpoolP512r1tls13_sha512:
            return NamedGroup.brainpoolP512r1tls13;
        case ecdsa_secp256r1_sha256:
            return NamedGroup.secp256r1;
        case ecdsa_secp384r1_sha384:
            return NamedGroup.secp384r1;
        case ecdsa_secp521r1_sha512:
            return NamedGroup.secp521r1;
        case sm2sig_sm3:
            return NamedGroup.curveSM2;
        default:
            return -1;
        }
    }

    /** @deprecated Use {@link #getCryptoHashAlgorithm(int)} instead. */
    public static int getRSAPSSCryptoHashAlgorithm(int signatureScheme)
    {
        switch (signatureScheme)
        {
        case rsa_pss_pss_sha256:
        case rsa_pss_rsae_sha256:
            return CryptoHashAlgorithm.sha256;
        case rsa_pss_pss_sha384:
        case rsa_pss_rsae_sha384:
            return CryptoHashAlgorithm.sha384;
        case rsa_pss_pss_sha512:
        case rsa_pss_rsae_sha512:
            return CryptoHashAlgorithm.sha512;
        default:
            return -1;
        }
    }

    public static short getHashAlgorithm(int signatureScheme)
    {
        return (short)((signatureScheme >>> 8) & 0xFF);
    }

    public static short getSignatureAlgorithm(int signatureScheme)
    {
        // TODO[RFC 8998] sm2sig_sm3

        return (short)(signatureScheme & 0xFF);
    }

    public static SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(int signatureScheme)
    {
        return SignatureAndHashAlgorithm.getInstance(
            getHashAlgorithm(signatureScheme),
            getSignatureAlgorithm(signatureScheme));
    }

    public static String getText(int signatureScheme)
    {
        return getName(signatureScheme) + "(0x" + Integer.toHexString(signatureScheme) + ")";
    }

    public static boolean isPrivate(int signatureScheme)
    {
        return (signatureScheme >>> 9) == 0xFE; 
    }

    public static boolean isECDSA(int signatureScheme)
    {
        switch (signatureScheme)
        {
        case ecdsa_brainpoolP256r1tls13_sha256:
        case ecdsa_brainpoolP384r1tls13_sha384:
        case ecdsa_brainpoolP512r1tls13_sha512:
            return true;
        default:
            return SignatureAlgorithm.ecdsa == getSignatureAlgorithm(signatureScheme);
        }
    }

    public static boolean isMLDSA(int signatureScheme)
    {
        switch (signatureScheme)
        {
        case DRAFT_mldsa44:
        case DRAFT_mldsa65:
        case DRAFT_mldsa87:
        case mldsa44_ecdsa_secp256r1_sha256:
        case mldsa65_ecdsa_secp384r1_sha384:
        case mldsa87_ecdsa_secp521r1_sha51:
        case mldsa44_ed25519:
        case mldsa65_ed25519:
        case mldsa44_rsa2048_pkcs1_sha256:
        case mldsa65_rsa3072_pkcs1_sha256:
        case mldsa65_rsa4096_pkcs1_sha384:
        case mldsa44_rsa2048_pss_pss_sha256:
        case mldsa65_rsa3072_pss_pss_sha256:
        case mldsa65_rsa4096_pss_pss_sha384:
        case mldsa87_ed448:
            return true;
        default:
            return false;
        }
    }

    public static boolean isPQ(int signatureScheme)
    {
        switch (signatureScheme)
        {
            case DRAFT_mldsa44:
            case DRAFT_mldsa65:
            case DRAFT_mldsa87:
            case X9146_falcon512:
            case X9146_falcon1024:
                return true;
            default:
                return false;
        }
    }

    public static boolean isRSAPSS(int signatureScheme)
    {
        switch (signatureScheme)
        {
        case rsa_pss_rsae_sha256:
        case rsa_pss_rsae_sha384:
        case rsa_pss_rsae_sha512:
        case rsa_pss_pss_sha256:
        case rsa_pss_pss_sha384:
        case rsa_pss_pss_sha512:
            return true;
        default:
            return false;
        }
    }
}
