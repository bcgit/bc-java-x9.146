package org.bouncycastle.crypto.signers.xmss;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.XMSSKeyPairGenerator;
import org.bouncycastle.crypto.generators.XMSSMTKeyPairGenerator;
import org.bouncycastle.crypto.params.XMSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSMTPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSMTPublicKeyParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.params.XMSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSPublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.internal.asn1.isara.IsaraObjectIdentifiers;
import org.bouncycastle.util.Arrays;

/**
 * The ISARA vendor OIDs name the same structures as the legacy PQCObjectIdentifiers form - the same
 * XMSSKeyParams beside the algorithm and the same XMSSPrivateKey / XMSSPublicKey inside - and the
 * public side has always read them. The private side did not, so a key pair stored under those OIDs
 * came back half readable: the public half decoded and the private half was rejected as an
 * unrecognised algorithm. Both halves are read here.
 */
public class IsaraOidKeyTests
    extends TestCase
{
    private static PrivateKeyInfo underOID(PrivateKeyInfo info, ASN1ObjectIdentifier algOID)
        throws Exception
    {
        AlgorithmIdentifier algId = new AlgorithmIdentifier(algOID,
            info.getPrivateKeyAlgorithm().getParameters());

        return new PrivateKeyInfo(algId, info.parsePrivateKey());
    }

    private static SubjectPublicKeyInfo underOID(SubjectPublicKeyInfo info, ASN1ObjectIdentifier algOID)
        throws Exception
    {
        AlgorithmIdentifier algId = new AlgorithmIdentifier(algOID, info.getAlgorithm().getParameters());

        return new SubjectPublicKeyInfo(algId, info.getPublicKeyData().getBytes());
    }

    public void testXMSSKeyPairUnderIsaraOID()
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(4, NISTObjectIdentifiers.id_sha256);
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        XMSSPrivateKeyParameters privKey = (XMSSPrivateKeyParameters)kp.getPrivate();
        XMSSPublicKeyParameters pubKey = (XMSSPublicKeyParameters)kp.getPublic();

        PrivateKeyInfo privInfo = underOID(PrivateKeyInfoFactory.createPrivateKeyInfo(privKey),
            IsaraObjectIdentifiers.id_alg_xmss);
        SubjectPublicKeyInfo pubInfo = underOID(
            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pubKey),
            IsaraObjectIdentifiers.id_alg_xmss);

        XMSSPrivateKeyParameters decodedPriv =
            (XMSSPrivateKeyParameters)PrivateKeyFactory.createKey(privInfo);
        XMSSPublicKeyParameters decodedPub =
            (XMSSPublicKeyParameters)PublicKeyFactory.createKey(pubInfo);

        assertEquals(privKey.getIndex(), decodedPriv.getIndex());
        assertTrue(Arrays.areEqual(privKey.getSecretKeySeed(), decodedPriv.getSecretKeySeed()));
        assertTrue(Arrays.areEqual(pubKey.getRoot(), decodedPub.getRoot()));
        assertTrue(Arrays.areEqual(decodedPriv.getRoot(), decodedPub.getRoot()));
    }

    public void testXMSSMTKeyPairUnderIsaraOID()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(4, 2, NISTObjectIdentifiers.id_sha256);
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        XMSSMTPrivateKeyParameters privKey = (XMSSMTPrivateKeyParameters)kp.getPrivate();
        XMSSMTPublicKeyParameters pubKey = (XMSSMTPublicKeyParameters)kp.getPublic();

        PrivateKeyInfo privInfo = underOID(PrivateKeyInfoFactory.createPrivateKeyInfo(privKey),
            IsaraObjectIdentifiers.id_alg_xmssmt);
        SubjectPublicKeyInfo pubInfo = underOID(
            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pubKey),
            IsaraObjectIdentifiers.id_alg_xmssmt);

        XMSSMTPrivateKeyParameters decodedPriv =
            (XMSSMTPrivateKeyParameters)PrivateKeyFactory.createKey(privInfo);
        XMSSMTPublicKeyParameters decodedPub =
            (XMSSMTPublicKeyParameters)PublicKeyFactory.createKey(pubInfo);

        assertEquals(privKey.getIndex(), decodedPriv.getIndex());
        assertTrue(Arrays.areEqual(privKey.getSecretKeySeed(), decodedPriv.getSecretKeySeed()));
        assertTrue(Arrays.areEqual(pubKey.getRoot(), decodedPub.getRoot()));
        assertTrue(Arrays.areEqual(decodedPriv.getRoot(), decodedPub.getRoot()));
    }
}
