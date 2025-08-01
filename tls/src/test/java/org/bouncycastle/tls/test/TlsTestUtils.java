package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PipedInputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Hashtable;
import java.util.Vector;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateEntry;
import org.bouncycastle.tls.CertificateKeySelectionType;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsCredentialedAgreement;
import org.bouncycastle.tls.TlsCredentialedDecryptor;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedAgreement;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedDecryptor;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JceDefaultTlsCredentialedAgreement;
import org.bouncycastle.tls.crypto.impl.jcajce.JceDefaultTlsCredentialedDecryptor;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

public class TlsTestUtils
{
    static final byte[] rsaCertData = Base64
        .decode("MIICUzCCAf2gAwIBAgIBATANBgkqhkiG9w0BAQQFADCBjzELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb2"
            + "4gb2YgdGhlIEJvdW5jeSBDYXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExLzAtBgkq"
            + "hkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3JnMB4XDTEzMDIyNTA2MDIwNVoXDTEzMDIyNT"
            + "A2MDM0NVowgY8xCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIw"
            + "EAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMS8wLQYJKoZIhvcNAQkBFiBmZWVkYmFjay1jcnlwdG"
            + "9AYm91bmN5Y2FzdGxlLm9yZzBaMA0GCSqGSIb3DQEBAQUAA0kAMEYCQQC0p+RhcFdPFqlwgrIr5YtqKmKXmEGb4Shy"
            + "pL26Ymz66ZAPdqv7EhOdzl3lZWT6srZUMWWgQMYGiHQg4z2R7X7XAgERo0QwQjAOBgNVHQ8BAf8EBAMCBSAwEgYDVR"
            + "0lAQH/BAgwBgYEVR0lADAcBgNVHREBAf8EEjAQgQ50ZXN0QHRlc3QudGVzdDANBgkqhkiG9w0BAQQFAANBAHU55Ncz"
            + "eglREcTg54YLUlGWu2WOYWhit/iM1eeq8Kivro7q98eW52jTuMI3CI5ulqd0hYzshQKQaZ5GDzErMyM=");

    static final byte[] dudRsaCertData = Base64
        .decode("MIICUzCCAf2gAwIBAgIBATANBgkqhkiG9w0BAQQFADCBjzELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb2"
            + "4gb2YgdGhlIEJvdW5jeSBDYXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExLzAtBgkq"
            + "hkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3JnMB4XDTEzMDIyNTA1NDcyOFoXDTEzMDIyNT"
            + "A1NDkwOFowgY8xCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIw"
            + "EAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMS8wLQYJKoZIhvcNAQkBFiBmZWVkYmFjay1jcnlwdG"
            + "9AYm91bmN5Y2FzdGxlLm9yZzBaMA0GCSqGSIb3DQEBAQUAA0kAMEYCQQC0p+RhcFdPFqlwgrIr5YtqKmKXmEGb4Shy"
            + "pL26Ymz66ZAPdqv7EhOdzl3lZWT6srZUMWWgQMYGiHQg4z2R7X7XAgERo0QwQjAOBgNVHQ8BAf8EBAMCAAEwEgYDVR"
            + "0lAQH/BAgwBgYEVR0lADAcBgNVHREBAf8EEjAQgQ50ZXN0QHRlc3QudGVzdDANBgkqhkiG9w0BAQQFAANBAJg55PBS"
            + "weg6obRUKF4FF6fCrWFi6oCYSQ99LWcAeupc5BofW5MstFMhCOaEucuGVqunwT5G7/DweazzCIrSzB0=");

    static String fingerprint(org.bouncycastle.asn1.x509.Certificate c)
        throws IOException
    {
        byte[] der = c.getEncoded();
        byte[] sha1 = sha256DigestOf(der);
        byte[] hexBytes = Hex.encode(sha1);
        String hex = new String(hexBytes, "ASCII").toUpperCase();

        StringBuffer fp = new StringBuffer();
        int i = 0;
        fp.append(hex.substring(i, i + 2));
        while ((i += 2) < hex.length())
        {
            fp.append(':');
            fp.append(hex.substring(i, i + 2));
        }
        return fp.toString();
    }

    static byte[] sha256DigestOf(byte[] input)
    {
        SHA256Digest d = new SHA256Digest();
        d.update(input, 0, input.length);
        byte[] result = new byte[d.getDigestSize()];
        d.doFinal(result, 0);
        return result;
    }

    static String getCACertResource(short signatureAlgorithm) throws IOException
    {
        return "x509-ca-" + getResourceName(signatureAlgorithm) + ".pem";
    }

    static String getCACertResource(String eeCertResource) throws IOException
    {
        if (eeCertResource.startsWith("x9146/ca-"))
        {
//            eeCertResource = eeCertResource.replace("ca", "server");
            return eeCertResource;
        }
        if (eeCertResource.startsWith("x9146/server-"))
        {
            eeCertResource = eeCertResource.replace("server", "ca");
            return eeCertResource;
        }

        if (eeCertResource.startsWith("x509-client-"))
        {
            eeCertResource = eeCertResource.substring("x509-client-".length());
        }
        if (eeCertResource.startsWith("x509-server-"))
        {
            eeCertResource = eeCertResource.substring("x509-server-".length());
        }

        if (eeCertResource.endsWith(".pem"))
        {
            eeCertResource = eeCertResource.substring(0, eeCertResource.length() - ".pem".length());
        }

        if ("dsa".equalsIgnoreCase(eeCertResource))
        {
            return getCACertResource(SignatureAlgorithm.dsa);
        }

        if ("ecdh".equalsIgnoreCase(eeCertResource)
            || "ecdsa".equalsIgnoreCase(eeCertResource))
        {
            return getCACertResource(SignatureAlgorithm.ecdsa);
        }

        if ("ed25519".equalsIgnoreCase(eeCertResource))
        {
            return getCACertResource(SignatureAlgorithm.ed25519);
        }

        if ("ed448".equalsIgnoreCase(eeCertResource))
        {
            return getCACertResource(SignatureAlgorithm.ed448);
        }

        if ("rsa".equalsIgnoreCase(eeCertResource)
            || "rsa-enc".equalsIgnoreCase(eeCertResource)
            || "rsa-sign".equalsIgnoreCase(eeCertResource))
        {
            return getCACertResource(SignatureAlgorithm.rsa);
        }

        if ("rsa_pss_256".equalsIgnoreCase(eeCertResource))
        {
            return getCACertResource(SignatureAlgorithm.rsa_pss_pss_sha256);
        }
        if ("rsa_pss_384".equalsIgnoreCase(eeCertResource))
        {
            return getCACertResource(SignatureAlgorithm.rsa_pss_pss_sha384);
        }
        if ("rsa_pss_512".equalsIgnoreCase(eeCertResource))
        {
            return getCACertResource(SignatureAlgorithm.rsa_pss_pss_sha512);
        }

        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    static String getResourceName(short signatureAlgorithm) throws IOException
    {
        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.rsa:
        case SignatureAlgorithm.rsa_pss_rsae_sha256:
        case SignatureAlgorithm.rsa_pss_rsae_sha384:
        case SignatureAlgorithm.rsa_pss_rsae_sha512:
            return "rsa";
        case SignatureAlgorithm.dsa:
            return "dsa";
        case SignatureAlgorithm.ecdsa:
            return "ecdsa";
        case SignatureAlgorithm.ed25519:
            return "ed25519";
        case SignatureAlgorithm.ed448:
            return "ed448";
        case SignatureAlgorithm.rsa_pss_pss_sha256:
            return "rsa_pss_256";
        case SignatureAlgorithm.rsa_pss_pss_sha384:
            return "rsa_pss_384";
        case SignatureAlgorithm.rsa_pss_pss_sha512:
            return "rsa_pss_512";

        // TODO[RFC 9189] Choose names here and apply reverse mappings in getCACertResource(String)
        case SignatureAlgorithm.gostr34102012_256:
        case SignatureAlgorithm.gostr34102012_512:

        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    static TlsCredentialedAgreement loadAgreementCredentials(TlsContext context, String[] certResources,
        String keyResource) throws IOException
    {
        TlsCrypto crypto = context.getCrypto();
        Certificate certificate = loadCertificateChain(context, certResources);

        // TODO[tls-ops] Need to have TlsCrypto construct the credentials from the certs/key (as raw data)
        if (crypto instanceof BcTlsCrypto)
        {
            AsymmetricKeyParameter privateKey = loadBcPrivateKeyResource(keyResource);

            return new BcDefaultTlsCredentialedAgreement((BcTlsCrypto)crypto, certificate, privateKey);
        }
        else
        {
            JcaTlsCrypto jcaCrypto = (JcaTlsCrypto)crypto;
            PrivateKey privateKey = loadJcaPrivateKeyResource(jcaCrypto, keyResource);

            return new JceDefaultTlsCredentialedAgreement(jcaCrypto, certificate, privateKey);
        }
    }

    static TlsCredentialedDecryptor loadEncryptionCredentials(TlsContext context, String[] certResources,
        String keyResource) throws IOException
    {
        TlsCrypto crypto = context.getCrypto();
        Certificate certificate = loadCertificateChain(context, certResources);

        // TODO[tls-ops] Need to have TlsCrypto construct the credentials from the certs/key (as raw data)
        if (crypto instanceof BcTlsCrypto)
        {
            AsymmetricKeyParameter privateKey = loadBcPrivateKeyResource(keyResource);

            return new BcDefaultTlsCredentialedDecryptor((BcTlsCrypto)crypto, certificate, privateKey);
        }
        else
        {
            JcaTlsCrypto jcaCrypto = (JcaTlsCrypto)crypto;
            PrivateKey privateKey = loadJcaPrivateKeyResource(jcaCrypto, keyResource);

            return new JceDefaultTlsCredentialedDecryptor(jcaCrypto, certificate, privateKey);
        }
    }

    public static TlsCredentialedSigner loadDualSignerCredentials(TlsCryptoParameters cryptoParams, TlsCrypto crypto,
        String[] certResources, String keyResource, SignatureAndHashAlgorithm signatureAndHashAlgorithm,
                                String altKeyResource, SignatureAndHashAlgorithm altSignatureAndHashAlgorithm)
        throws IOException
    {
        Certificate certificate = loadCertificateChain(cryptoParams.getServerVersion(), crypto, certResources);

        // TODO[tls-ops] Need to have TlsCrypto construct the credentials from the certs/key (as raw data)
        if (crypto instanceof BcTlsCrypto)
        {
            AsymmetricKeyParameter privateKey = loadBcPrivateKeyResource(keyResource);
            AsymmetricKeyParameter altPrivateKey = loadBcPrivateKeyResource(altKeyResource);


            return new BcDefaultTlsCredentialedSigner(cryptoParams, (BcTlsCrypto)crypto, privateKey, altPrivateKey,
                    certificate, signatureAndHashAlgorithm, altSignatureAndHashAlgorithm);
        }
        else
        {
            JcaTlsCrypto jcaCrypto = (JcaTlsCrypto)crypto;
            PrivateKey privateKey = loadJcaPrivateKeyResource(jcaCrypto, keyResource);

            //TODO[x9.146]: do for jca

            return new JcaDefaultTlsCredentialedSigner(cryptoParams, jcaCrypto, privateKey, certificate, signatureAndHashAlgorithm);
        }
    }
    public static TlsCredentialedSigner loadSignerCredentials(TlsCryptoParameters cryptoParams, TlsCrypto crypto,
        String[] certResources, String keyResource, SignatureAndHashAlgorithm signatureAndHashAlgorithm)
        throws IOException
    {
        Certificate certificate = loadCertificateChain(cryptoParams.getServerVersion(), crypto, certResources);

        // TODO[tls-ops] Need to have TlsCrypto construct the credentials from the certs/key (as raw data)
        if (crypto instanceof BcTlsCrypto)
        {
            AsymmetricKeyParameter privateKey = loadBcPrivateKeyResource(keyResource);

            return new BcDefaultTlsCredentialedSigner(cryptoParams, (BcTlsCrypto)crypto, privateKey, certificate, signatureAndHashAlgorithm);
        }
        else
        {
            JcaTlsCrypto jcaCrypto = (JcaTlsCrypto)crypto;
            PrivateKey privateKey = loadJcaPrivateKeyResource(jcaCrypto, keyResource);

            return new JcaDefaultTlsCredentialedSigner(cryptoParams, jcaCrypto, privateKey, certificate, signatureAndHashAlgorithm);
        }
    }

    static TlsCredentialedSigner loadSignerCredentials(TlsContext context, String[] certResources,
        String keyResource, SignatureAndHashAlgorithm signatureAndHashAlgorithm) throws IOException
    {
        TlsCrypto crypto = context.getCrypto();
        TlsCryptoParameters cryptoParams = new TlsCryptoParameters(context);

        return loadSignerCredentials(cryptoParams, crypto, certResources, keyResource, signatureAndHashAlgorithm);
    }
    static TlsCredentialedSigner loadDualSignerCredentials(TlsContext context, String[] certResources,
        String keyResource, String altKeyResource, SignatureAndHashAlgorithm signatureAndHashAlgorithm, SignatureAndHashAlgorithm altSignatureAndHashAlgorithm) throws IOException
    {
        TlsCrypto crypto = context.getCrypto();
        TlsCryptoParameters cryptoParams = new TlsCryptoParameters(context);

        return loadDualSignerCredentials(cryptoParams, crypto, certResources, keyResource, signatureAndHashAlgorithm, altKeyResource, altSignatureAndHashAlgorithm);
    }

    static TlsCredentialedSigner loadDualSignerCredentials(TlsContext context, Vector supportedSignatureAlgorithms,
       short signatureAlgorithm, short altSignatureAlgorithm, String certResource, String keyResource,
       String altKeyResource) throws IOException
    {
        SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
        SignatureAndHashAlgorithm altSignatureAndHashAlgorithm = null;
        //TODO: do altsignature hash algorithm
        if (supportedSignatureAlgorithms == null)
        {
            supportedSignatureAlgorithms = TlsUtils.getDefaultSignatureAlgorithms(signatureAlgorithm);
        }

        short targetHash = -1;
        if (keyResource.contains("P256"))
        {
            targetHash = SignatureScheme.getHashAlgorithm(SignatureScheme.ecdsa_secp256r1_sha256);
        }
        if (keyResource.contains("P384"))
        {
            targetHash = SignatureScheme.getHashAlgorithm(SignatureScheme.ecdsa_secp384r1_sha384);
        }
        if (keyResource.contains("P521"))
        {
            targetHash = SignatureScheme.getHashAlgorithm(SignatureScheme.ecdsa_secp521r1_sha512);
        }
        if (keyResource.contains("rsa3072"))
        {
            targetHash = SignatureScheme.getHashAlgorithm(SignatureScheme.rsa_pss_rsae_sha256);
        }


        for (int i = 0; i < supportedSignatureAlgorithms.size(); ++i)
        {
            SignatureAndHashAlgorithm alg = (SignatureAndHashAlgorithm)
                    supportedSignatureAlgorithms.elementAt(i);

            // find target signature and hash
            if (targetHash == alg.getHash() &&  alg.getSignature() == signatureAlgorithm)
            {
                signatureAndHashAlgorithm = alg;
                break;
            }

            // Just grab the first one we find if keyResource does not specify hash
            if (targetHash == -1 &&  alg.getSignature() == signatureAlgorithm)
            {
                signatureAndHashAlgorithm = alg;
                break;
            }
        }

        //TODO do better
        for (int i = 0; i < supportedSignatureAlgorithms.size(); ++i)
        {
            SignatureAndHashAlgorithm alg = (SignatureAndHashAlgorithm)
                    supportedSignatureAlgorithms.elementAt(i);


            if (alg.getHash() == (altSignatureAlgorithm >> 8) && alg.getSignature() == (altSignatureAlgorithm & 0x00FF))
            {
                // Just grab the first one we find
                altSignatureAndHashAlgorithm = alg;
                break;
            }
        }

        if (signatureAndHashAlgorithm == null || altSignatureAndHashAlgorithm == null)
        {
            return null;
        }

        return loadDualSignerCredentials(context, new String[]{ certResource }, keyResource, altKeyResource,
                signatureAndHashAlgorithm, altSignatureAndHashAlgorithm);
    }
    static TlsCredentialedSigner loadSignerCredentials(TlsContext context, Vector supportedSignatureAlgorithms,
        short signatureAlgorithm, String certResource, String keyResource) throws IOException
    {
        SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
        if (supportedSignatureAlgorithms == null)
        {
            supportedSignatureAlgorithms = TlsUtils.getDefaultSignatureAlgorithms(signatureAlgorithm);
        }

        for (int i = 0; i < supportedSignatureAlgorithms.size(); ++i)
        {
            SignatureAndHashAlgorithm alg = (SignatureAndHashAlgorithm)
                supportedSignatureAlgorithms.elementAt(i);
            if (alg.getSignature() == signatureAlgorithm)
            {
                // Just grab the first one we find
                signatureAndHashAlgorithm = alg;
                break;
            }
        }

        if (signatureAndHashAlgorithm == null)
        {
            return null;
        }

        return loadSignerCredentials(context, new String[]{ certResource }, keyResource, signatureAndHashAlgorithm);
    }

    static TlsCredentialedSigner loadSignerCredentialsServer(TlsContext context, Vector supportedSignatureAlgorithms,
        short signatureAlgorithm) throws IOException
    {
        String sigName = getResourceName(signatureAlgorithm);

        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.rsa:
        case SignatureAlgorithm.rsa_pss_rsae_sha256:
        case SignatureAlgorithm.rsa_pss_rsae_sha384:
        case SignatureAlgorithm.rsa_pss_rsae_sha512:
            sigName += "-sign";
            break;
        }

        String certResource = "x509-server-" + sigName + ".pem";
        String keyResource = "x509-server-key-" + sigName + ".pem";

        return loadSignerCredentials(context, supportedSignatureAlgorithms, signatureAlgorithm, certResource, keyResource);
    }

    static Certificate loadCertificateChain(ProtocolVersion protocolVersion, TlsCrypto crypto, String[] resources)
        throws IOException
    {
        if (TlsUtils.isTLSv13(protocolVersion))
        {
            CertificateEntry[] certificateEntryList = new CertificateEntry[resources.length];
            for (int i = 0; i < resources.length; ++i)
            {
                TlsCertificate certificate = loadCertificateResource(crypto, resources[i]);

                // TODO[tls13] Add possibility of specifying e.g. CertificateStatus 
                Hashtable extensions = null;

                certificateEntryList[i] = new CertificateEntry(certificate, extensions);
            }

            // TODO[tls13] Support for non-empty request context
            byte[] certificateRequestContext = TlsUtils.EMPTY_BYTES;

            return new Certificate(certificateRequestContext, certificateEntryList);
        }
        else
        {
            TlsCertificate[] chain = new TlsCertificate[resources.length];
            for (int i = 0; i < resources.length; ++i)
            {
                chain[i] = loadCertificateResource(crypto, resources[i]);
            }
            return new Certificate(chain);
        }
    }

    static Certificate loadCertificateChain(TlsContext context, String[] resources)
        throws IOException
    {
        return loadCertificateChain(context.getServerVersion(), context.getCrypto(), resources);
    }

    static org.bouncycastle.asn1.x509.Certificate loadBcCertificateResource(String resource)
        throws IOException
    {
        PemObject pem = loadPemResource(resource);
        if (pem.getType().endsWith("CERTIFICATE"))
        {
            return org.bouncycastle.asn1.x509.Certificate.getInstance(pem.getContent());
        }
        throw new IllegalArgumentException("'resource' doesn't specify a valid certificate");
    }

    static TlsCertificate loadCertificateResource(TlsCrypto crypto, String resource)
        throws IOException
    {
        PemObject pem = loadPemResource(resource);
        if (pem.getType().endsWith("CERTIFICATE"))
        {
            return crypto.createCertificate(pem.getContent());
        }
        throw new IllegalArgumentException("'resource' doesn't specify a valid certificate");
    }

    static AsymmetricKeyParameter loadBcPrivateKeyResource(String resource)
        throws IOException
    {
        PemObject pem = loadPemResource(resource);
        if (pem.getType().equals("PRIVATE KEY"))
        {
            // TODO:[x9.146] maybe have a separation for pq private keys?
            AsymmetricKeyParameter kp;
            try
            {
                kp = PrivateKeyFactory.createKey(pem.getContent());
            }
            catch (Exception e)
            {
                kp = org.bouncycastle.pqc.crypto.util.PrivateKeyFactory.createKey(pem.getContent());
            }
            return kp;

        }
        if (pem.getType().equals("ENCRYPTED PRIVATE KEY"))
        {
            throw new UnsupportedOperationException("Encrypted PKCS#8 keys not supported");
        }
        if (pem.getType().equals("RSA PRIVATE KEY"))
        {
            RSAPrivateKey rsa = RSAPrivateKey.getInstance(pem.getContent());
            return new RSAPrivateCrtKeyParameters(rsa.getModulus(), rsa.getPublicExponent(),
                rsa.getPrivateExponent(), rsa.getPrime1(), rsa.getPrime2(), rsa.getExponent1(),
                rsa.getExponent2(), rsa.getCoefficient());
        }
        if (pem.getType().equals("EC PRIVATE KEY"))
        {
            ECPrivateKey pKey = ECPrivateKey.getInstance(pem.getContent());
            AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, pKey.getParametersObject());
            PrivateKeyInfo privInfo = new PrivateKeyInfo(algId, pKey);
            return PrivateKeyFactory.createKey(privInfo);
        }
        throw new IllegalArgumentException("'resource' doesn't specify a valid private key");
    }

    static PrivateKey loadJcaPrivateKeyResource(JcaTlsCrypto crypto, String resource)
        throws IOException
    {
        Throwable cause = null;
        try
        {
            PemObject pem = loadPemResource(resource);
            if (pem.getType().equals("PRIVATE KEY"))
            {
                return loadJcaPkcs8PrivateKey(crypto, pem.getContent());
            }
            if (pem.getType().equals("ENCRYPTED PRIVATE KEY"))
            {
                throw new UnsupportedOperationException("Encrypted PKCS#8 keys not supported");
            }
            if (pem.getType().equals("RSA PRIVATE KEY"))
            {
                RSAPrivateKey rsa = RSAPrivateKey.getInstance(pem.getContent());
                KeyFactory keyFact = crypto.getHelper().createKeyFactory("RSA");
                return keyFact.generatePrivate(new RSAPrivateCrtKeySpec(rsa.getModulus(), rsa.getPublicExponent(),
                    rsa.getPrivateExponent(), rsa.getPrime1(), rsa.getPrime2(), rsa.getExponent1(), rsa.getExponent2(),
                    rsa.getCoefficient()));
            }
        }
        catch (GeneralSecurityException e)
        {
            cause = e;
        }
        throw new IllegalArgumentException("'resource' doesn't specify a valid private key", cause);
    }

    static PrivateKey loadJcaPkcs8PrivateKey(JcaTlsCrypto crypto, byte[] encoded) throws GeneralSecurityException
    {
        PrivateKeyInfo pki = PrivateKeyInfo.getInstance(encoded);
        AlgorithmIdentifier algID = pki.getPrivateKeyAlgorithm();
        ASN1ObjectIdentifier oid = algID.getAlgorithm();

        String name;
        if (X9ObjectIdentifiers.id_dsa.equals(oid))
        {
            name = "DSA";
        }
        else if (X9ObjectIdentifiers.id_ecPublicKey.equals(oid))
        {
            // TODO Try ECDH/ECDSA according to intended use?
            name = "EC";
        }
        else if (PKCSObjectIdentifiers.rsaEncryption.equals(oid)
            || PKCSObjectIdentifiers.id_RSASSA_PSS.equals(oid))
        {
            name = "RSA";
        }
        else if (EdECObjectIdentifiers.id_Ed25519.equals(oid))
        {
            name = "Ed25519";
        }
        else if (EdECObjectIdentifiers.id_Ed448.equals(oid))
        {
            name = "Ed448";
        }
        else
        {
            name = oid.getId();
        }

        KeyFactory kf = crypto.getHelper().createKeyFactory(name);
        return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }

    static PemObject loadPemResource(String resource)
        throws IOException
    {
        InputStream s = TlsTestUtils.class.getResourceAsStream(resource);
        PemReader p = new PemReader(new InputStreamReader(s));
        PemObject o = p.readPemObject();
        p.close();
        return o;
    }

    static boolean areSameCertificate(TlsCrypto crypto, TlsCertificate cert, String resource) throws IOException
    {
        // TODO Cache test resources?
        return areSameCertificate(cert, loadCertificateResource(crypto, resource));
    }

    static boolean areSameCertificate(TlsCertificate a, TlsCertificate b) throws IOException
    {
        // TODO[tls-ops] Support equals on TlsCertificate?
        return Arrays.areEqual(a.getEncoded(), b.getEncoded());
    }

    static TlsCertificate[] getTrustedCertPath(TlsCrypto crypto, TlsCertificate cert, String[] resources)
        throws IOException
    {
        for (int i = 0; i < resources.length; ++i)
        {
            String eeCertResource = resources[i];
            TlsCertificate eeCert = loadCertificateResource(crypto, eeCertResource);

            if (areSameCertificate(cert, eeCert))
            {
                String caCertResource = getCACertResource(eeCertResource);
                TlsCertificate caCert = loadCertificateResource(crypto, caCertResource);
                if (null != caCert)
                {
                    return new TlsCertificate[]{ eeCert, caCert };
                }
            }
        }
        return null;
    }
    static TlsCertificate[] getTrustedCertPath(TlsCrypto crypto, TlsCertificate cert, String[] resources, short cksCode)
        throws IOException
    {
        for (int i = 0; i < resources.length; ++i)
        {
            String eeCertResource = resources[i];
            TlsCertificate eeCert = loadCertificateResource(crypto, eeCertResource);

            switch (cksCode)
            {
                case CertificateKeySelectionType.cks_native:
                case CertificateKeySelectionType.cks_default:
                    break;
                case CertificateKeySelectionType.cks_alternate:
                case CertificateKeySelectionType.cks_both:
                    //TODO[X9.146]: do i need to modify certs to check?
                    break;

                case CertificateKeySelectionType.cks_external:
                default:
                    throw new RuntimeException("Unknown Certificate Key Selection Code: " + cksCode);

            }



//            if (areSameCertificate(cert, eeCert))
            {
                String caCertResource = getCACertResource(eeCertResource);
                TlsCertificate caCert = loadCertificateResource(crypto, caCertResource);
                if (null != caCert)
                {
                    return new TlsCertificate[]{ eeCert, caCert };
                }
            }
        }
        return null;
    }

    static TrustManagerFactory getSunX509TrustManagerFactory()
        throws NoSuchAlgorithmException
    {
        if (Security.getProvider("IBMJSSE2") != null)
        {
            return TrustManagerFactory.getInstance("IBMX509");
        }
        else
        {
            return TrustManagerFactory.getInstance("SunX509");
        }
    }

    static KeyManagerFactory getSunX509KeyManagerFactory()
        throws NoSuchAlgorithmException
    {
        if (Security.getProvider("IBMJSSE2") != null)
        {
            return KeyManagerFactory.getInstance("IBMX509");
        }
        else
        {
            return KeyManagerFactory.getInstance("SunX509");
        }
    }

    static PipedInputStream createPipedInputStream()
    {
        return new BigPipedInputStream(16384);
    }

    private static class BigPipedInputStream
        extends PipedInputStream
    {
        BigPipedInputStream(int size)
        {
            this.buffer = new byte[size];
        }
    }
}
