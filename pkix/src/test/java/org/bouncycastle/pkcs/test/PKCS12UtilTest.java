package org.bouncycastle.pkcs.test;

import java.math.BigInteger;
import java.security.Security;

import junit.framework.TestCase;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PBMAC1Params;
import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.PKCS12SecretBag;
import org.bouncycastle.pkcs.PKCS12SecretBagBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS12PBMac1CalculatorBuilder;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.pkcs.jcajce.JcePBMac1CalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCS12MacCalculatorBuilderProvider;
import org.bouncycastle.pkcs.util.PKCS12Util;
import org.bouncycastle.util.Strings;

public class PKCS12UtilTest
    extends TestCase
{
    private static final char[] passwd = "secret".toCharArray();

    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testConvertToDefiniteLength_PBE_RoundTrips()
        throws Exception
    {
        byte[] pfxBytes = buildPfx(new BcPKCS12MacCalculatorBuilder()).getEncoded();

        byte[] derBytes = org.bouncycastle.pkcs.util.PKCS12Util
            .convertToDefiniteLength(pfxBytes, passwd, "BC");

        PKCS12PfxPdu pfx = new PKCS12PfxPdu(derBytes);
        assertTrue(pfx.hasMac());
        assertTrue(pfx.isMacValid(
            new JcePKCS12MacCalculatorBuilderProvider().setProvider("BC"), passwd));
    }

    public void testConvertToDefiniteLength_PBMAC1_RoundTrips()
        throws Exception
    {
        BcPKCS12PBMac1CalculatorBuilder mac1Builder = new BcPKCS12PBMac1CalculatorBuilder(new PBMAC1Params(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2,
                new PBKDF2Params(Strings.toByteArray("saltsalt"), 1024, 256,
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256))),
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA512)));

        byte[] pfxBytes = buildPfx(mac1Builder).getEncoded();

        byte[] derBytes = org.bouncycastle.pkcs.util.PKCS12Util
            .convertToDefiniteLength(pfxBytes, passwd, "BC");

        PKCS12PfxPdu pfx = new PKCS12PfxPdu(derBytes);
        assertTrue(pfx.hasMac());
        assertTrue(pfx.isMacValid(
            new JcePKCS12MacCalculatorBuilderProvider().setProvider("BC"), passwd));
    }

    public void testConvertToDefiniteLength_Idempotent()
        throws Exception
    {
        byte[] pfxBytes = buildPfx(new BcPKCS12MacCalculatorBuilder()).getEncoded();

        byte[] once = org.bouncycastle.pkcs.util.PKCS12Util
            .convertToDefiniteLength(pfxBytes, passwd, "BC");
        byte[] twice = org.bouncycastle.pkcs.util.PKCS12Util
            .convertToDefiniteLength(once, passwd, "BC");

        assertTrue(java.util.Arrays.equals(once, twice));
    }

    public void testDeprecatedClass_StillRejectsPBMAC1()
        throws Exception
    {
        BcPKCS12PBMac1CalculatorBuilder mac1Builder = new BcPKCS12PBMac1CalculatorBuilder(new PBMAC1Params(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2,
                new PBKDF2Params(Strings.toByteArray("saltsalt"), 1024, 256,
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256))),
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA512)));

        byte[] pfxBytes = buildPfx(mac1Builder).getEncoded();

        try
        {
            org.bouncycastle.jce.PKCS12Util.convertToDefiniteLength(pfxBytes, passwd, "BC");
            fail("deprecated PKCS12Util accepted PBMAC1");
        }
        catch (java.io.IOException e)
        {
            // expected: deprecated class wraps UnsupportedOperationException as
            // "error constructing MAC: ..."
            assertTrue("unexpected cause: " + e.getCause(),
                e.getCause() instanceof UnsupportedOperationException);
        }
    }

    /**
     * RFC 9579 sec. 9: "It's RECOMMENDED to reject any KDF parameters that specify key lengths less
     * than 20 octets." The floor belongs to validateMacKeyLength alone - validateKeyLength also
     * bounds the PBES2 content-encryption keyLength reached from PKCS12KeyStoreSpi.wrapKey, where
     * 16 octets is AES-128 and BC writes it into every PKCS12-AES256-AES128 file it produces.
     */
    public void testValidateMacKeyLengthBounds()
    {
        try
        {
            PKCS12Util.validateMacKeyLength(BigInteger.valueOf(8));
            fail("short MAC keyLength accepted");
        }
        catch (IllegalStateException e)
        {
            assertEquals("keyLength 8 less than 20", e.getMessage());
        }

        // the upper bound is unchanged, and stays well above the HMAC output size: BC's
        // PKCS12-PBMAC1 keystore asked for a 256-octet MAC key up to release 1.86.
        try
        {
            PKCS12Util.validateMacKeyLength(BigInteger.valueOf(2000));
            fail("oversized MAC keyLength accepted");
        }
        catch (IllegalStateException e)
        {
            assertEquals("keyLength 2000 greater than 1024", e.getMessage());
        }

        assertEquals(20, PKCS12Util.validateMacKeyLength(BigInteger.valueOf(20)));
        assertEquals(64, PKCS12Util.validateMacKeyLength(BigInteger.valueOf(64)));
        assertEquals(256, PKCS12Util.validateMacKeyLength(BigInteger.valueOf(256)));   // pre-1.87 files

        // and the encryption-side validator must NOT have picked the floor up
        assertEquals(16, PKCS12Util.validateKeyLength(BigInteger.valueOf(16)));
        assertEquals(32, PKCS12Util.validateKeyLength(BigInteger.valueOf(32)));

        try
        {
            PKCS12Util.validateKeyLength(BigInteger.ZERO);
            fail("zero keyLength accepted");
        }
        catch (IllegalStateException e)
        {
            assertEquals("keyLength must be positive", e.getMessage());
        }
    }

    /**
     * The PBMAC1 keyDerivationFunc field names the key-derivation function, so it carries id-PBKDF2
     * (RFC 9579 sec. 4, RFC 8018 app. A.2). JcePBMac1CalculatorBuilder emitted id-PBES2 there, which
     * BC's own readers tolerate - they take the PBKDF2Params without looking at the OID - but
     * BcPKCS12PBMac1CalculatorBuilder does not: it refuses anything else with "unrecognised PBKDF".
     * So BC's two PKCS#12 MAC stacks disagreed about parameters BC itself had generated.
     */
    public void testJcePBMac1EmitsPbkdf2Oid()
        throws Exception
    {
        MacCalculator calculator = new JcePBMac1CalculatorBuilder("HmacSHA256", 256)
            .setProvider("BC").build(passwd);

        PBMAC1Params params = PBMAC1Params.getInstance(calculator.getAlgorithmIdentifier().getParameters());

        assertEquals(PKCSObjectIdentifiers.id_PBKDF2, params.getKeyDerivationFunc().getAlgorithm());

        // the lightweight side has to accept what the JCA side generates, and a PFX MACed with those
        // parameters has to verify end to end
        PKCS12PfxPdu pfx = buildPfx(new BcPKCS12PBMac1CalculatorBuilder(params));

        assertTrue(pfx.hasMac());
        assertTrue(pfx.isMacValid(new JcePKCS12MacCalculatorBuilderProvider().setProvider("BC"), passwd));
    }

    /**
     * Compatibility half: releases up to 1.86 wrote id-PBES2 in that field, so a PFX carrying one has
     * to keep verifying. The readers ignore the OID and this must stay that way - lenient on read,
     * correct on write. The MAC covers the content, not the algorithm identifier, so rewriting the
     * OID on a good PFX reproduces exactly what an earlier release emitted.
     */
    public void testLegacyPbes2KdfOidStillVerifies()
        throws Exception
    {
        PBMAC1Params current = new PBMAC1Params(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2,
                new PBKDF2Params(Strings.toByteArray("saltsalt"), 1024, 32,
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256))),
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256));

        Pfx pfx = buildPfx(new BcPKCS12PBMac1CalculatorBuilder(current)).toASN1Structure();
        MacData macData = pfx.getMacData();
        DigestInfo mac = macData.getMac();

        PBMAC1Params legacy = new PBMAC1Params(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2,
                PBKDF2Params.getInstance(current.getKeyDerivationFunc().getParameters())),
            current.getMessageAuthScheme());

        Pfx rewritten = new Pfx(pfx.getAuthSafe(), new MacData(
            new DigestInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBMAC1, legacy), mac.getDigest()),
            macData.getSalt(), macData.getIterationCount().intValue()));

        PKCS12PfxPdu legacyPfx = new PKCS12PfxPdu(rewritten);

        assertEquals(PKCSObjectIdentifiers.id_PBES2,
            PBMAC1Params.getInstance(legacyPfx.getMacAlgorithmID().getParameters())
                .getKeyDerivationFunc().getAlgorithm());
        assertTrue(legacyPfx.hasMac());
        assertTrue("a PFX written by an earlier release no longer verifies",
            legacyPfx.isMacValid(new JcePKCS12MacCalculatorBuilderProvider().setProvider("BC"), passwd));
    }

    private static PKCS12PfxPdu buildPfx(
        org.bouncycastle.pkcs.PKCS12MacCalculatorBuilder macBuilder)
        throws Exception
    {
        PKCS12SecretBag secret = new PKCS12SecretBagBuilder(
            CMSAlgorithm.AES256_CBC, new DEROctetString(new byte[]{1, 2, 3, 4}))
            .build();
        PKCS12SafeBag bag = new PKCS12SafeBagBuilder(secret).build();

        PKCS12PfxPduBuilder builder = new PKCS12PfxPduBuilder();
        builder.addData(bag);

        return builder.build(macBuilder, passwd);
    }
}
