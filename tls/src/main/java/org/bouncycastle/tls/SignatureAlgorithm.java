package org.bouncycastle.tls;

/**
 * RFC 5246 7.4.1.4.1 (in RFC 2246, there were no specific values assigned)
 */
public class SignatureAlgorithm
{
    public static final short anonymous = 0;
    public static final short rsa = 1;
    public static final short dsa = 2;
    public static final short ecdsa = 3;

    /*
     * RFC 8422
     */
    public static final short ed25519 = 7;
    public static final short ed448 = 8;

    /*
     * RFC 8446 (implied from SignatureScheme values)
     * RFC 8447 reserved these values without allocating the implied names
     */
    public static final short rsa_pss_rsae_sha256 = 4;
    public static final short rsa_pss_rsae_sha384 = 5;
    public static final short rsa_pss_rsae_sha512 = 6;
    public static final short rsa_pss_pss_sha256 = 9;
    public static final short rsa_pss_pss_sha384 = 10;
    public static final short rsa_pss_pss_sha512 = 11;

    /*
     * RFC 8734 (implied from SignatureScheme values)
     */
    public static final short ecdsa_brainpoolP256r1tls13_sha256 = 26;
    public static final short ecdsa_brainpoolP384r1tls13_sha384 = 27;
    public static final short ecdsa_brainpoolP512r1tls13_sha512 = 28;

    /*
     * RFC 9189
     */
    public static final short gostr34102012_256 = 64;
    public static final short gostr34102012_512 = 65;

    /*
     * custom values to link mldsa
     */
    public static final short falcon_512 = 12;
    public static final short falcon_1024 = 13;
    public static final short custom_mldsa44 = 0x94;
    public static final short custom_mldsa65 = 0x95;
    public static final short custom_mldsa87 = 0x96;

    public static final short custom_mldsa44_ecdsa_secp256r1_sha256 = 0x97;
    public static final short custom_mldsa65_ecdsa_secp384r1_sha384 = 0x98;
    public static final short custom_mldsa87_ecdsa_secp521r1_sha51 = 0x99;
    public static final short custom_mldsa44_ed25519 = 0x9A;
    public static final short custom_mldsa65_ed25519 = 0x9B;
    public static final short custom_mldsa44_rsa2048_pkcs1_sha256 = 0x9C;
    public static final short custom_mldsa65_rsa3072_pkcs1_sha256 = 0x9D;
    public static final short custom_mldsa65_rsa4096_pkcs1_sha384 = 0x9E;
    public static final short custom_mldsa44_rsa2048_pss_pss_sha256 = 0x9F;
    public static final short custom_mldsa65_rsa3072_pss_pss_sha256 = 0xA0;
    public static final short custom_mldsa65_rsa4096_pss_pss_sha384 = 0xA1;
    public static final short custom_mldsa87_ed448 = 0xA2;

//    public static final short id_ml_dsa_44 = 0xD0;
//    public static final short id_ml_dsa_65 = 0xD1;
//    public static final short id_ml_dsa_87 = 0xD2;

    public static short getClientCertificateType(short signatureAlgorithm)
    {
        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.rsa:
        case SignatureAlgorithm.rsa_pss_rsae_sha256:
        case SignatureAlgorithm.rsa_pss_rsae_sha384:
        case SignatureAlgorithm.rsa_pss_rsae_sha512:
        case SignatureAlgorithm.rsa_pss_pss_sha256:
        case SignatureAlgorithm.rsa_pss_pss_sha384:
        case SignatureAlgorithm.rsa_pss_pss_sha512:
            return ClientCertificateType.rsa_sign;

        case SignatureAlgorithm.dsa:
            return ClientCertificateType.dss_sign;

        case SignatureAlgorithm.ecdsa:
        case SignatureAlgorithm.ed25519:
        case SignatureAlgorithm.ed448:
            return ClientCertificateType.ecdsa_sign;

        case SignatureAlgorithm.gostr34102012_256:
            return ClientCertificateType.gost_sign256;

        case SignatureAlgorithm.gostr34102012_512:
            return ClientCertificateType.gost_sign512;

//        case SignatureAlgorithm.dilithiumr3_2:
//        case SignatureAlgorithm.dilithiumr3_3:
//        case SignatureAlgorithm.dilithiumr3_5:

        default:
            return -1;
        }
    }



    public static int getSignatureScheme(short signatureAlgorithm)
    {
        switch (signatureAlgorithm)
        {
        case custom_mldsa44:
            return SignatureScheme.DRAFT_mldsa44;
        case custom_mldsa44_ecdsa_secp256r1_sha256:
            return SignatureScheme.mldsa44_ecdsa_secp256r1_sha256;
        case custom_mldsa44_ed25519:
            return SignatureScheme.mldsa44_ed25519;
        case custom_mldsa44_rsa2048_pkcs1_sha256:
            return SignatureScheme.mldsa44_rsa2048_pkcs1_sha256;
        case custom_mldsa44_rsa2048_pss_pss_sha256:
            return SignatureScheme.mldsa44_rsa2048_pss_pss_sha256;
        case custom_mldsa65:
            return SignatureScheme.DRAFT_mldsa65;
        case custom_mldsa65_ecdsa_secp384r1_sha384:
            return SignatureScheme.mldsa65_ecdsa_secp384r1_sha384;
        case custom_mldsa65_ed25519:
            return SignatureScheme.mldsa65_ed25519;
        case custom_mldsa65_rsa3072_pkcs1_sha256:
            return SignatureScheme.mldsa65_rsa3072_pkcs1_sha256;
        case custom_mldsa65_rsa4096_pkcs1_sha384:
            return SignatureScheme.mldsa65_rsa4096_pkcs1_sha384;
        case custom_mldsa65_rsa3072_pss_pss_sha256:
            return SignatureScheme.mldsa65_rsa3072_pss_pss_sha256;
        case custom_mldsa65_rsa4096_pss_pss_sha384:
            return SignatureScheme.mldsa65_rsa4096_pss_pss_sha384;
        case custom_mldsa87:
            return SignatureScheme.DRAFT_mldsa87;
        case custom_mldsa87_ecdsa_secp521r1_sha51:
            return SignatureScheme.mldsa87_ecdsa_secp521r1_sha51;
        case custom_mldsa87_ed448:
            return SignatureScheme.mldsa87_ed448;
        default:
            return -1;
        }
    }
    public static boolean isMLDSA(short signatureAlgorithm)
    {
        switch (signatureAlgorithm)
        {
        case custom_mldsa44:
        case custom_mldsa65:
        case custom_mldsa87:
        case custom_mldsa44_ecdsa_secp256r1_sha256:
        case custom_mldsa65_ecdsa_secp384r1_sha384:
        case custom_mldsa87_ecdsa_secp521r1_sha51:
        case custom_mldsa44_ed25519:
        case custom_mldsa65_ed25519:
        case custom_mldsa44_rsa2048_pkcs1_sha256:
        case custom_mldsa65_rsa3072_pkcs1_sha256:
        case custom_mldsa65_rsa4096_pkcs1_sha384:
        case custom_mldsa44_rsa2048_pss_pss_sha256:
        case custom_mldsa65_rsa3072_pss_pss_sha256:
        case custom_mldsa65_rsa4096_pss_pss_sha384:
        case custom_mldsa87_ed448:
                return true;
        default:
            return false;
        }
    }

    public static String getName(short signatureAlgorithm)
    {
        switch (signatureAlgorithm)
        {
        case anonymous:
            return "anonymous";
        case rsa:
            return "rsa";
        case dsa:
            return "dsa";
        case ecdsa:
            return "ecdsa";
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
        case gostr34102012_256:
            return "gostr34102012_256";
        case gostr34102012_512:
            return "gostr34102012_512";
        case custom_mldsa44:
            return "DRAFT_mldsa44";
        case custom_mldsa65:
            return "DRAFT_mldsa65";
        case custom_mldsa87:
            return "DRAFT_mldsa87";
        default:
            return "UNKNOWN";
        }
    }

    public static String getText(short signatureAlgorithm)
    {
        return getName(signatureAlgorithm) + "(" + signatureAlgorithm + ")";
    }

    public static boolean isRecognized(short signatureAlgorithm)
    {
        switch (signatureAlgorithm)
        {
        case anonymous:
        case rsa:
        case dsa:
        case ecdsa:
        case rsa_pss_rsae_sha256:
        case rsa_pss_rsae_sha384:
        case rsa_pss_rsae_sha512:
        case ed25519:
        case ed448:
        case rsa_pss_pss_sha256:
        case rsa_pss_pss_sha384:
        case rsa_pss_pss_sha512:
        case ecdsa_brainpoolP256r1tls13_sha256:
        case ecdsa_brainpoolP384r1tls13_sha384:
        case ecdsa_brainpoolP512r1tls13_sha512:
        case gostr34102012_256:
        case gostr34102012_512:
            return true;
        default:
            return false;
        }
    }
}
