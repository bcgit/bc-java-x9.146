package org.bouncycastle.tls.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateEntry;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

/**
 * Builds a fresh three-certificate Chimera chain (root CA -&gt; intermediate CA -&gt; end-entity, all with
 * X.509 2019 alternate-key extensions unless a variant says otherwise) and the matching dual-signer
 * credential, so the X9.146 tests can exercise {@code TlsUtils.checkPeerSigAlgs}' per-link chimera
 * chain-signature verification across MULTIPLE links -- the static PEM fixtures only ever produce a
 * single EE-&gt;CA link. The Certificate message carries {EE, intermediate, root} so a relying party can
 * validate the received chain directly.
 */
class X9146ChimeraChainUtil
{
    // Use a provider instance directly so the fixture works whether or not "BC" is registered globally.
    private static final Provider BC = new BouncyCastleProvider();

    private static final SecureRandom RANDOM = new SecureRandom();

    enum Variant
    {
        /** Fully hybrid chain: every link carries a valid native AND alternate signature. */
        FULL,
        /**
         * The intermediate CA is classical (no alternate key): no link carries an alternate signature,
         * so the alternate chain pass must SKIP each link (the pre-2026 NPE guard) while the end-entity
         * still holds its own alternate key for the CertificateVerify.
         */
        CLASSICAL_INTERMEDIATE,
        /**
         * The end-entity's altSignatureValue is produced by a rogue ML-DSA key instead of the
         * intermediate's: the alternate chain pass MUST fail (fatal bad_certificate) whenever the
         * negotiated CKS uses the alternate signatures, and MUST be ignored when it does not.
         * The native signature (computed over the TBS including the rogue value) remains valid.
         */
        BAD_ALT_SIGNATURE
    }

    static TlsCredentialedSigner createChainCredentials(TlsContext context, Variant variant) throws Exception
    {
        BcTlsCrypto crypto = (BcTlsCrypto)context.getCrypto();
        boolean classicalIntermediate = (variant == Variant.CLASSICAL_INTERMEDIATE);

        KeyPair rootNative = generateEC();
        KeyPair rootAlt = generateMLDSA();
        KeyPair intermediateNative = generateEC();
        KeyPair intermediateAlt = classicalIntermediate ? null : generateMLDSA();
        KeyPair eeNative = generateEC();
        KeyPair eeAlt = generateMLDSA();

        X500Name rootName = new X500Name("CN=X9146 Chain Root");
        X500Name intermediateName = new X500Name("CN=X9146 Chain Intermediate");
        X500Name eeName = new X500Name("CN=X9146 Chain EE");

        ContentSigner rootSigner = signer("SHA256withECDSA", rootNative.getPrivate());
        ContentSigner rootAltSigner = signer("ML-DSA-44", rootAlt.getPrivate());
        ContentSigner intermediateSigner = signer("SHA256withECDSA", intermediateNative.getPrivate());

        // Self-signed chimera root.
        JcaX509v3CertificateBuilder rootBuilder = builder(rootName, rootName, rootNative.getPublic());
        rootBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        rootBuilder.addExtension(Extension.subjectAltPublicKeyInfo, false, altSpki(rootAlt.getPublic()));
        X509CertificateHolder rootCert = rootBuilder.build(rootSigner, false, rootAltSigner);

        // Intermediate issued by the root: chimera, or classical (no alternate anything) per variant.
        JcaX509v3CertificateBuilder intermediateBuilder =
            builder(rootName, intermediateName, intermediateNative.getPublic());
        intermediateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        X509CertificateHolder intermediateCert;
        if (classicalIntermediate)
        {
            intermediateCert = intermediateBuilder.build(rootSigner);
        }
        else
        {
            intermediateBuilder.addExtension(Extension.subjectAltPublicKeyInfo, false,
                altSpki(intermediateAlt.getPublic()));
            intermediateCert = intermediateBuilder.build(rootSigner, false, rootAltSigner);
        }

        // End-entity issued by the intermediate. It always carries its own alternate key (for the
        // CertificateVerify); whether it carries an alternate SIGNATURE -- and whose key made it --
        // depends on the variant.
        JcaX509v3CertificateBuilder eeBuilder = builder(intermediateName, eeName, eeNative.getPublic());
        eeBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        eeBuilder.addExtension(Extension.subjectAltPublicKeyInfo, false, altSpki(eeAlt.getPublic()));
        X509CertificateHolder eeCert;
        if (classicalIntermediate)
        {
            // A classical issuer cannot produce an alternate signature.
            eeCert = eeBuilder.build(intermediateSigner);
        }
        else if (variant == Variant.BAD_ALT_SIGNATURE)
        {
            ContentSigner rogueAltSigner = signer("ML-DSA-44", generateMLDSA().getPrivate());
            eeCert = eeBuilder.build(intermediateSigner, false, rogueAltSigner);
        }
        else
        {
            ContentSigner intermediateAltSigner = signer("ML-DSA-44", intermediateAlt.getPrivate());
            eeCert = eeBuilder.build(intermediateSigner, false, intermediateAltSigner);
        }

        // Wire chain {EE, intermediate, root}: including the root lets the relying party validate the
        // received chain directly (RFC 8446 permits including the trust anchor).
        CertificateEntry[] entries = new CertificateEntry[]{
            new CertificateEntry(new BcTlsCertificate(crypto, eeCert.getEncoded()), null),
            new CertificateEntry(new BcTlsCertificate(crypto, intermediateCert.getEncoded()), null),
            new CertificateEntry(new BcTlsCertificate(crypto, rootCert.getEncoded()), null)
        };
        Certificate certificate = new Certificate(TlsUtils.EMPTY_BYTES, entries);

        AsymmetricKeyParameter eeNativeKey = PrivateKeyFactory.createKey(eeNative.getPrivate().getEncoded());
        AsymmetricKeyParameter eeAltKey = PrivateKeyFactory.createKey(eeAlt.getPrivate().getEncoded());

        return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(context), crypto,
            eeNativeKey, eeAltKey, certificate,
            SignatureScheme.getSignatureAndHashAlgorithm(SignatureScheme.ecdsa_secp256r1_sha256),
            SignatureAndHashAlgorithm.DRAFT_mldsa44);
    }

    private static JcaX509v3CertificateBuilder builder(X500Name issuer, X500Name subject, PublicKey publicKey)
    {
        long now = System.currentTimeMillis();
        return new JcaX509v3CertificateBuilder(issuer, new BigInteger(63, RANDOM),
            new Date(now - 1000L * 60 * 60), new Date(now + 1000L * 60 * 60 * 24), subject, publicKey);
    }

    private static SubjectAltPublicKeyInfo altSpki(PublicKey publicKey)
    {
        return new SubjectAltPublicKeyInfo(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
    }

    private static ContentSigner signer(String algorithm, PrivateKey key) throws Exception
    {
        return new JcaContentSignerBuilder(algorithm).setProvider(BC).build(key);
    }

    private static KeyPair generateEC() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BC);
        kpg.initialize(new ECGenParameterSpec("P-256"), RANDOM);
        return kpg.generateKeyPair();
    }

    private static KeyPair generateMLDSA() throws Exception
    {
        return KeyPairGenerator.getInstance("ML-DSA-44", BC).generateKeyPair();
    }
}
