package org.bouncycastle.tls.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.RelatedCertificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateEntry;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

/**
 * Builds an X9.146 QTLS Related Certificates Pair (RFC 9763) credential for tests: two independent
 * end-entity certificates (a "Related" and a "Main"), where the Main certificate carries the
 * {@code RelatedCertificate} extension whose digest binds it to the Related certificate. The returned
 * {@link TlsCredentialedSigner} carries both certificates in one Certificate message (Related first, Main
 * second) and signs the ExtendedCertificateVerify with the Related key (primary) and the Main key (alt),
 * per draft sec. 9.5.
 * <p>
 * Both certificates use ECDSA (P-256 Related / P-384 Main) so the fixture exercises the full CKS-5 code
 * path -- dual-chain Certificate message, relation-digest check, and a two-certificate
 * ExtendedCertificateVerify -- without depending on PQC certificate generation.
 */
class X9146RelatedPairUtil
{
    // Use a provider instance directly so the fixture works whether or not "BC" is registered globally.
    private static final Provider BC = new BouncyCastleProvider();

    static TlsCredentialedSigner createRelatedPairCredentials(TlsContext context) throws Exception
    {
        BcTlsCrypto crypto = (BcTlsCrypto)context.getCrypto();

        KeyPair relatedKeyPair = generateEC("P-256");
        KeyPair mainKeyPair = generateEC("P-384");

        X509CertificateHolder relatedHolder = buildSelfSigned("CN=X9146 Related", relatedKeyPair,
            "SHA256withECDSA", null);

        // The Main certificate binds the Related certificate by digest (RFC 9763 sec. 3, SHA-256).
        DigestCalculator sha256 = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()
            .get(new DefaultDigestAlgorithmIdentifierFinder().find("SHA-256"));
        RelatedCertificate relatedCertExtension =
            org.bouncycastle.cert.RelatedCertificateTool.createRelatedCertificate(relatedHolder, sha256);

        X509CertificateHolder mainHolder = buildSelfSigned("CN=X9146 Main", mainKeyPair,
            "SHA384withECDSA", relatedCertExtension);

        // Certificate message: Related first, Main second (draft sec. 6.3).
        CertificateEntry[] entries = new CertificateEntry[]{
            new CertificateEntry(new BcTlsCertificate(crypto, relatedHolder.getEncoded()), null),
            new CertificateEntry(new BcTlsCertificate(crypto, mainHolder.getEncoded()), null)
        };
        Certificate certificate = new Certificate(TlsUtils.EMPTY_BYTES, entries);

        AsymmetricKeyParameter relatedKey = PrivateKeyFactory.createKey(relatedKeyPair.getPrivate().getEncoded());
        AsymmetricKeyParameter mainKey = PrivateKeyFactory.createKey(mainKeyPair.getPrivate().getEncoded());

        // ALG_1 = Related (first chain) key, ALG_2 = Main (second chain) key.
        return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(context), crypto,
            relatedKey, mainKey, certificate,
            SignatureScheme.getSignatureAndHashAlgorithm(SignatureScheme.ecdsa_secp256r1_sha256),
            SignatureScheme.getSignatureAndHashAlgorithm(SignatureScheme.ecdsa_secp384r1_sha384));
    }

    private static KeyPair generateEC(String curve) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BC);
        kpg.initialize(new ECGenParameterSpec(curve));
        return kpg.generateKeyPair();
    }

    private static X509CertificateHolder buildSelfSigned(String dn, KeyPair keyPair, String sigAlg,
        RelatedCertificate relatedCertExtension) throws Exception
    {
        X500Name name = new X500Name(dn);
        PublicKey pub = keyPair.getPublic();
        PrivateKey priv = keyPair.getPrivate();

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            name,
            BigInteger.valueOf(System.identityHashCode(keyPair) & 0x7fffffffL),
            new Date(System.currentTimeMillis() - 1000L * 60 * 60),
            new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24),
            name,
            pub);

        if (relatedCertExtension != null)
        {
            // RFC 9763 sec. 3.1: SHOULD NOT be marked critical.
            builder.addExtension(Extension.relatedCertificate, false, relatedCertExtension);
        }

        return builder.build(new JcaContentSignerBuilder(sigAlg).setProvider(BC).build(priv));
    }
}
