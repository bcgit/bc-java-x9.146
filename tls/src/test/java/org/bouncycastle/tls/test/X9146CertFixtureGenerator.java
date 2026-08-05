package org.bouncycastle.tls.test;

import java.io.File;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.RelatedCertificate;
import org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.RelatedCertificateTool;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * Generates the ANSI X9.146 QTLS certificate fixtures under
 * {@code tls/src/test/resources/org/bouncycastle/tls/test/x9146/}, covering every certificate type the
 * CKS code points (draft 2026-07-21 sec. 6.1) can select:
 * <ul>
 * <li>four Chimera CA + server sets (X.509 2019 alternate-key extensions; CKS 1/2/3/7/8, and used as
 * classic single-signer credentials for the Standard rows 0/6),</li>
 * <li>a Composite set -- classic ECDSA P-256 CA issuing a server certificate whose SubjectPublicKeyInfo
 * is a composite ML-DSA-44 + ECDSA-P256-SHA256 key (CKS 4/9; the certificate itself is CA-signed with
 * plain ECDSA, so no composite ContentSigner is required),</li>
 * <li>a classic (single-algorithm ECDSA P-256) CA + server set (CKS 0/6 with a genuinely Standard
 * certificate),</li>
 * <li>a static Related Certificates Pair (RFC 9763; CKS 5/10/11) -- the protocol tests generate their
 * pair fresh each run via {@link X9146RelatedPairUtil}, these static PEMs are for interop use.</li>
 * </ul>
 * Not a JUnit test: run its {@code main} to (re)generate the fixtures in place. See the README.md next
 * to the fixtures for the exact command and the regeneration policy. Keys are newly generated on each
 * run, so regenerating replaces the whole set coherently (certificates and private keys together).
 * <p>
 * The tests load these resources through {@code TestResourceFinder} from
 * {@code bc-test-data/tls/credentials/x9146}; this repo also tracks a mirror copy under
 * {@code tls/src/test/resources/org/bouncycastle/tls/test/x9146}. With no arguments the generator
 * writes the SAME set to both locations (when present) so they cannot drift; passing explicit
 * directory arguments writes to those instead.
 */
public class X9146CertFixtureGenerator
{
    private static final String[] DEFAULT_OUTPUT_DIRS = {
        "tls/src/test/resources/org/bouncycastle/tls/test/x9146",
        "../bc-test-data/tls/credentials/x9146"
    };

    private static final long VALIDITY_MILLIS = 10 * 365L * 24 * 60 * 60 * 1000;    // ~10 years

    private static final SecureRandom RANDOM = new SecureRandom();

    private final File[] outputDirs;
    private final Date notBefore;
    private final Date notAfter;

    public static void main(String[] args)
        throws Exception
    {
        // The composite-signature SPI resolves its component algorithms by the "BC" provider name.
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        String[] dirNames = (args.length > 0) ? args : DEFAULT_OUTPUT_DIRS;
        java.util.List<File> dirs = new java.util.ArrayList<File>();
        for (int i = 0; i < dirNames.length; ++i)
        {
            File dir = new File(dirNames[i]);
            if (dir.isDirectory())
            {
                dirs.add(dir);
            }
            else if (args.length > 0)
            {
                // Explicitly-requested directories must exist; missing defaults are just skipped.
                throw new IllegalArgumentException("output directory does not exist: " + dir);
            }
        }
        if (dirs.isEmpty())
        {
            throw new IllegalStateException(
                "no output directory found; run from the bc-java root or pass directories explicitly");
        }

        X9146CertFixtureGenerator generator =
            new X9146CertFixtureGenerator((File[])dirs.toArray(new File[dirs.size()]));

        generator.generateChimeraSet("P256-mldsa44", "P-256", "SHA256withECDSA", "ML-DSA-44",
            "server-P256-key.pem", "server-mldsa44-key-pq.pem");
        generator.generateChimeraSet("P384-mldsa65", "P-384", "SHA384withECDSA", "ML-DSA-65",
            "server-P384-key.pem", "server-mldsa65-key-pq.pem");
        generator.generateChimeraSet("P521-mldsa87", "P-521", "SHA512withECDSA", "ML-DSA-87",
            "server-P521-key.pem", "server-mldsa87-key-pq.pem");
        generator.generateChimeraSet("rsa3072-mldsa44", "RSA-3072", "SHA256withRSA", "ML-DSA-44",
            "server-rsa3072-key.pem", "server-mldsa44-rsa-key-pq.pem");

        generator.generateCompositeSet();
        generator.generateClassicSet();
        generator.generateRelatedPairSet();

        for (int i = 0; i < generator.outputDirs.length; ++i)
        {
            System.out.println("X9.146 fixtures written to " + generator.outputDirs[i].getAbsolutePath());
        }
    }

    private X9146CertFixtureGenerator(File[] outputDirs)
    {
        this.outputDirs = outputDirs;
        long now = System.currentTimeMillis();
        this.notBefore = new Date(now - 24L * 60 * 60 * 1000);
        this.notAfter = new Date(now + VALIDITY_MILLIS);
    }

    /**
     * One Chimera family: a self-signed Chimera root CA (native + ML-DSA alternate keys, alternate
     * signature per X.509 2019) issuing a Chimera server certificate whose native and alternate
     * signatures both come from the CA's keys, and whose SubjectAltPublicKeyInfo carries the server's
     * own ML-DSA public key (the key that signs the TLS alternate CertificateVerify signature).
     */
    private void generateChimeraSet(String label, String nativeAlg, String nativeSigAlg, String mldsaAlg,
        String serverNativeKeyFile, String serverPqKeyFile)
        throws Exception
    {
        KeyPair caNative = generateKeyPair(nativeAlg);
        KeyPair caAlt = generateKeyPair(mldsaAlg);
        KeyPair serverNative = generateKeyPair(nativeAlg);
        KeyPair serverAlt = generateKeyPair(mldsaAlg);

        X500Name caName = name("X9.146 Test Chimera CA (" + label + ")");
        X500Name serverName = name("X9.146 Test Chimera Server (" + label + ")");

        ContentSigner caSigner = signer(nativeSigAlg, caNative.getPrivate());
        ContentSigner caAltSigner = signer(mldsaAlg, caAlt.getPrivate());

        JcaX509v3CertificateBuilder caBuilder = new JcaX509v3CertificateBuilder(
            caName, serial(), notBefore, notAfter, caName, caNative.getPublic());
        caBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        caBuilder.addExtension(Extension.subjectAltPublicKeyInfo, false, altPublicKeyInfo(caAlt.getPublic()));
        X509CertificateHolder caCert = caBuilder.build(caSigner, false, caAltSigner);

        JcaX509v3CertificateBuilder serverBuilder = new JcaX509v3CertificateBuilder(
            caName, serial(), notBefore, notAfter, serverName, serverNative.getPublic());
        serverBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        serverBuilder.addExtension(Extension.subjectAltPublicKeyInfo, false,
            altPublicKeyInfo(serverAlt.getPublic()));
        X509CertificateHolder serverCert = serverBuilder.build(caSigner, false, caAltSigner);

        writeCert("ca-" + label + "-cert.pem", caCert);
        writeKey("ca-" + label + "-key.pem", caNative.getPrivate());
        writeKey("ca-" + label + "-key-pq.pem", caAlt.getPrivate());
        writeCert("server-" + label + "-cert.pem", serverCert);
        writeKey(serverNativeKeyFile, serverNative.getPrivate());
        writeKey(serverPqKeyFile, serverAlt.getPrivate());
    }

    /**
     * Composite set (CKS 4/9): a classic ECDSA P-256 CA issues a server certificate whose
     * SubjectPublicKeyInfo is a composite ML-DSA-44 + ECDSA-P256-SHA256 key
     * (draft-reddy-tls-composite-mldsa codepoint 0x0907). The certificate signature itself is plain
     * ECDSA from the CA, so chain validation needs no composite support -- only the CertificateVerify
     * exercises the composite algorithm.
     */
    private void generateCompositeSet()
        throws Exception
    {
        String compositeAlg = IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256.getId();

        KeyPair caKeyPair = generateKeyPair("P-256");
        KeyPair serverKeyPair = generateKeyPair(compositeAlg);

        if (serverKeyPair.getPrivate().getEncoded() == null)
        {
            throw new IllegalStateException("composite private key is not PKCS#8-encodable");
        }

        X500Name caName = name("X9.146 Test Composite CA (mldsa44-p256)");
        X500Name serverName = name("X9.146 Test Composite Server (mldsa44-p256)");

        ContentSigner caSigner = signer("SHA256withECDSA", caKeyPair.getPrivate());

        JcaX509v3CertificateBuilder caBuilder = new JcaX509v3CertificateBuilder(
            caName, serial(), notBefore, notAfter, caName, caKeyPair.getPublic());
        caBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        X509CertificateHolder caCert = caBuilder.build(caSigner);

        JcaX509v3CertificateBuilder serverBuilder = new JcaX509v3CertificateBuilder(
            caName, serial(), notBefore, notAfter, serverName, serverKeyPair.getPublic());
        serverBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        X509CertificateHolder serverCert = serverBuilder.build(caSigner);

        writeCert("ca-composite-mldsa44-p256-cert.pem", caCert);
        writeKey("ca-composite-mldsa44-p256-key.pem", caKeyPair.getPrivate());
        writeCert("server-composite-mldsa44-p256-cert.pem", serverCert);
        writeKey("server-composite-mldsa44-p256-key.pem", serverKeyPair.getPrivate());
    }

    /**
     * Classic set (CKS 0/6 with a genuinely Standard certificate): plain ECDSA P-256, no alternate
     * extensions anywhere.
     */
    private void generateClassicSet()
        throws Exception
    {
        KeyPair caKeyPair = generateKeyPair("P-256");
        KeyPair serverKeyPair = generateKeyPair("P-256");

        X500Name caName = name("X9.146 Test Classic CA (P256)");
        X500Name serverName = name("X9.146 Test Classic Server (P256)");

        ContentSigner caSigner = signer("SHA256withECDSA", caKeyPair.getPrivate());

        JcaX509v3CertificateBuilder caBuilder = new JcaX509v3CertificateBuilder(
            caName, serial(), notBefore, notAfter, caName, caKeyPair.getPublic());
        caBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        X509CertificateHolder caCert = caBuilder.build(caSigner);

        JcaX509v3CertificateBuilder serverBuilder = new JcaX509v3CertificateBuilder(
            caName, serial(), notBefore, notAfter, serverName, serverKeyPair.getPublic());
        serverBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        X509CertificateHolder serverCert = serverBuilder.build(caSigner);

        writeCert("ca-P256-classic-cert.pem", caCert);
        writeKey("ca-P256-classic-key.pem", caKeyPair.getPrivate());
        writeCert("server-P256-classic-cert.pem", serverCert);
        writeKey("server-P256-classic-key.pem", serverKeyPair.getPrivate());
    }

    /**
     * Static Related Certificates Pair (RFC 9763; CKS 5/10/11): two self-signed end-entity certificates,
     * the Main (P-384) carrying the RelatedCertificate extension binding the Related (P-256) by SHA-256
     * digest. Mirrors what {@link X9146RelatedPairUtil} builds at runtime for the protocol tests.
     */
    private void generateRelatedPairSet()
        throws Exception
    {
        KeyPair relatedKeyPair = generateKeyPair("P-256");
        KeyPair mainKeyPair = generateKeyPair("P-384");

        X500Name relatedName = name("X9.146 Test Related EE (P256)");
        X500Name mainName = name("X9.146 Test Main EE (P384)");

        JcaX509v3CertificateBuilder relatedBuilder = new JcaX509v3CertificateBuilder(
            relatedName, serial(), notBefore, notAfter, relatedName, relatedKeyPair.getPublic());
        X509CertificateHolder relatedCert =
            relatedBuilder.build(signer("SHA256withECDSA", relatedKeyPair.getPrivate()));

        DigestCalculator sha256 = new JcaDigestCalculatorProviderBuilder()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME).build()
            .get(new DefaultDigestAlgorithmIdentifierFinder().find("SHA-256"));
        RelatedCertificate relation = RelatedCertificateTool.createRelatedCertificate(relatedCert, sha256);

        JcaX509v3CertificateBuilder mainBuilder = new JcaX509v3CertificateBuilder(
            mainName, serial(), notBefore, notAfter, mainName, mainKeyPair.getPublic());
        // RFC 9763 sec. 3.1: SHOULD NOT be marked critical.
        mainBuilder.addExtension(Extension.relatedCertificate, false, relation);
        X509CertificateHolder mainCert = mainBuilder.build(signer("SHA384withECDSA", mainKeyPair.getPrivate()));

        writeCert("related-P256-cert.pem", relatedCert);
        writeKey("related-P256-key.pem", relatedKeyPair.getPrivate());
        writeCert("main-P384-cert.pem", mainCert);
        writeKey("main-P384-key.pem", mainKeyPair.getPrivate());
    }

    private static KeyPair generateKeyPair(String algorithm)
        throws Exception
    {
        if (algorithm.startsWith("P-"))
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            kpg.initialize(new ECGenParameterSpec(algorithm), RANDOM);
            return kpg.generateKeyPair();
        }
        if (algorithm.equals("RSA-3072"))
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            kpg.initialize(3072, RANDOM);
            return kpg.generateKeyPair();
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        return kpg.generateKeyPair();
    }

    private static ContentSigner signer(String algorithm, PrivateKey key)
        throws Exception
    {
        return new JcaContentSignerBuilder(algorithm).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(key);
    }

    private static SubjectAltPublicKeyInfo altPublicKeyInfo(PublicKey publicKey)
    {
        return new SubjectAltPublicKeyInfo(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
    }

    private static X500Name name(String commonName)
    {
        return new X500Name("C=AU,O=The Legion of the Bouncy Castle,OU=X9.146 QTLS test certificates,CN="
            + commonName);
    }

    private static BigInteger serial()
    {
        return new BigInteger(63, RANDOM);
    }

    private void writeCert(String fileName, X509CertificateHolder cert)
        throws Exception
    {
        writePem(fileName, new PemObject("CERTIFICATE", cert.getEncoded()));
    }

    private void writeKey(String fileName, PrivateKey key)
        throws Exception
    {
        writePem(fileName, new PemObject("PRIVATE KEY", key.getEncoded()));
    }

    private void writePem(String fileName, PemObject pemObject)
        throws Exception
    {
        for (int i = 0; i < outputDirs.length; ++i)
        {
            PemWriter writer = new PemWriter(new FileWriter(new File(outputDirs[i], fileName)));
            try
            {
                writer.writeObject(pemObject);
            }
            finally
            {
                writer.close();
            }
        }
    }
}
