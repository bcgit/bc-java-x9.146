package org.bouncycastle.openpgp.api.test;

import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Regression test: an expired primary key must take its subkeys with it.
 * <p>
 * A certificate whose primary key's Key Expiration Time (RFC 9580, section 5.2.3.13) had passed went
 * on offering a longer-lived encryption or signing subkey from {@code getEncryptionKeys()} /
 * {@code getSigningKeys()}, because the binding check evaluated only the subkey's own binding
 * signature. The certificate then contradicted itself: {@code getExpirationTime()} in the past and
 * {@code getPrimaryKey().isBoundAt()} false, while a subkey was still handed out. An expired primary
 * key can no longer certify, so the subkeys it bound are not usable with it either - which is what
 * GnuPG and Sequoia do too. Primary key <i>revocation</i> already propagated, since a revocation
 * appears in the subkey's signature chain; expiration is not carried on the chain, so it did not.
 * <p>
 * A subkey does not inherit the primary key's validity period either: section 5.2.3.13 counts it from
 * the creation time of the key the carrying self-signature is on, so re-basing the primary key's
 * period on the subkey's creation time - which is what letting the subpacket shadow down did - moved
 * the expiration date, giving a subkey created after the primary a later expiry than the primary it
 * came from.
 */
public class OpenPGPPrimaryKeyExpiryTest
    extends SimpleTest
{
    private static final long DAY = 86400L;
    private static final long TEN_YEARS = 10L * 365 * DAY;
    private static final long NEVER = 0L;

    private KeyPairGenerator kpg;
    private PGPDigestCalculator sha1;

    public String getName()
    {
        return "OpenPGPPrimaryKeyExpiryTest";
    }

    public void performTest()
        throws Exception
    {
        kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        sha1 = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

        expiredPrimaryOffersNoSubkey();
        expiredPrimaryDoesNotBindItsSubkey();
        validPrimaryOffersItsSubkey();
        validPrimaryOffersSubkeyWithoutOwnExpiry();
        nonExpiringPrimaryOffersItsSubkey();
        expiredSubkeyUnderValidPrimaryIsNotOffered();
    }

    private void expiredPrimaryOffersNoSubkey()
        throws Exception
    {
        // primary valid for 10 of the 100 days since its creation, subkey good for another 10 years
        OpenPGPCertificate cert = certificate(100 * DAY, 10 * DAY, TEN_YEARS);

        Date now = new Date();

        isTrue("test setup: primary key should be expired",
            cert.getExpirationTime().before(now));
        isTrue("test setup: primary key should not be bound",
            !cert.getPrimaryKey().isBoundAt(now));

        isEquals("an expired primary key must offer no encryption subkey",
            0, cert.getEncryptionKeys().size());
        isEquals("an expired primary key must offer no signing key",
            0, cert.getSigningKeys().size());
    }

    private void expiredPrimaryDoesNotBindItsSubkey()
        throws Exception
    {
        OpenPGPCertificate cert = certificate(100 * DAY, 10 * DAY, TEN_YEARS);

        OpenPGPCertificate.OpenPGPComponentKey subkey = subkeyOf(cert);

        isTrue("a subkey of an expired primary key must not report itself bound",
            !subkey.isBoundAt(new Date()));
    }

    private void validPrimaryOffersItsSubkey()
        throws Exception
    {
        // the compatibility assertion - the same shape with a primary key that has not expired
        OpenPGPCertificate cert = certificate(DAY, TEN_YEARS, TEN_YEARS);

        isEquals("a valid primary key should offer its encryption subkey",
            1, cert.getEncryptionKeys().size());
        isTrue("a subkey of a valid primary key should report itself bound",
            subkeyOf(cert).isBoundAt(new Date()));
    }

    private void validPrimaryOffersSubkeyWithoutOwnExpiry()
        throws Exception
    {
        // a subkey with no Key Expiration Time of its own no longer inherits the primary key's period
        OpenPGPCertificate cert = certificate(DAY, TEN_YEARS, NEVER);

        isEquals("a subkey without its own expiry should be offered under a valid primary key",
            1, cert.getEncryptionKeys().size());
        isTrue("a subkey without its own expiry should not report an expiration date",
            subkeyOf(cert).getKeyExpirationDate() == null);
    }

    private void nonExpiringPrimaryOffersItsSubkey()
        throws Exception
    {
        OpenPGPCertificate cert = certificate(DAY, NEVER, TEN_YEARS);

        isTrue("test setup: primary key should not expire", cert.getExpirationTime() == null);
        isEquals("a non-expiring primary key should offer its encryption subkey",
            1, cert.getEncryptionKeys().size());
    }

    private void expiredSubkeyUnderValidPrimaryIsNotOffered()
        throws Exception
    {
        // the control in the other direction - the subkey's own expiry still applies on its own
        OpenPGPCertificate cert = certificate(100 * DAY, TEN_YEARS, 10 * DAY);

        isTrue("test setup: primary key should be bound",
            cert.getPrimaryKey().isBoundAt(new Date()));
        isEquals("an expired subkey must not be offered",
            0, cert.getEncryptionKeys().size());
    }

    /**
     * Build a version 4 certificate whose primary key and encryption subkey were both created
     * <pre>ageSecs</pre> ago, the primary key valid for <pre>primaryValiditySecs</pre> and the subkey
     * for <pre>subkeyValiditySecs</pre> from then, either of which may be zero for "never expires".
     */
    private OpenPGPCertificate certificate(long ageSecs, long primaryValiditySecs, long subkeyValiditySecs)
        throws Exception
    {
        char[] passphrase = "test".toCharArray();
        Date keyTime = new Date(1000L * (System.currentTimeMillis() / 1000L - ageSecs));

        PGPKeyPair primary = new JcaPGPKeyPair(
            PublicKeyPacket.VERSION_4, PGPPublicKey.RSA_SIGN, kpg.generateKeyPair(), keyTime);
        PGPKeyPair subkey = new JcaPGPKeyPair(
            PublicKeyPacket.VERSION_4, PGPPublicKey.RSA_GENERAL, kpg.generateKeyPair(), keyTime);

        PGPSignatureSubpacketGenerator primarySubpackets = new PGPSignatureSubpacketGenerator();
        primarySubpackets.setKeyFlags(true, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA);
        primarySubpackets.setKeyExpirationTime(true, primaryValiditySecs);
        primarySubpackets.setSignatureCreationTime(true, keyTime);

        PGPKeyRingGenerator gen = new PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, primary, "Alice <alice@example.com>",
            sha1, primarySubpackets.generate(), null,
            new JcaPGPContentSignerBuilder(primary.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256),
            new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256).setProvider("BC").build(passphrase));

        PGPSignatureSubpacketGenerator subkeySubpackets = new PGPSignatureSubpacketGenerator();
        subkeySubpackets.setKeyFlags(true, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
        if (subkeyValiditySecs != NEVER)
        {
            subkeySubpackets.setKeyExpirationTime(true, subkeyValiditySecs);
        }
        subkeySubpackets.setSignatureCreationTime(true, keyTime);
        gen.addSubKey(subkey, subkeySubpackets.generate(), null);

        PGPPublicKeyRing ring = gen.generatePublicKeyRing();

        return new OpenPGPCertificate(ring);
    }

    private OpenPGPCertificate.OpenPGPComponentKey subkeyOf(OpenPGPCertificate cert)
    {
        for (Iterator<OpenPGPCertificate.OpenPGPComponentKey> it = cert.getKeys().iterator(); it.hasNext(); )
        {
            OpenPGPCertificate.OpenPGPComponentKey key = it.next();
            if (!key.isPrimaryKey())
            {
                return key;
            }
        }
        fail("test setup: certificate should carry a subkey");
        return null;
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new OpenPGPPrimaryKeyExpiryTest());
    }
}
