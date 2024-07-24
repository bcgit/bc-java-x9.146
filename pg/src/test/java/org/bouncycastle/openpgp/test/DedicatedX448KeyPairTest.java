package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.X448PublicBCPGKey;
import org.bouncycastle.bcpg.X448SecretBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.X448KeyPairGenerator;
import org.bouncycastle.crypto.params.X448KeyGenerationParameters;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;

import java.io.IOException;
import java.security.*;
import java.util.Date;

public class DedicatedX448KeyPairTest
        extends AbstractPgpKeyPairTest
{
    @Override
    public String getName()
    {
        return "DedicatedX448KeyPairTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testConversionOfJcaKeyPair();
        testConversionOfBcKeyPair();
    }

    private void testConversionOfJcaKeyPair()
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, PGPException, IOException
    {
        Date date = currentTimeRounded();
        KeyPairGenerator gen = KeyPairGenerator.getInstance("XDH", new BouncyCastleProvider());
        gen.initialize(new XDHParameterSpec("X448"));
        KeyPair kp = gen.generateKeyPair();

        for (int version: new int[]{PublicKeyPacket.VERSION_4, PublicKeyPacket.VERSION_6})
        {
            JcaPGPKeyPair j1 = new JcaPGPKeyPair(version, PublicKeyAlgorithmTags.X448, kp, date);
            byte[] pubEnc = j1.getPublicKey().getEncoded();
            byte[] privEnc = j1.getPrivateKey().getPrivateKeyDataPacket().getEncoded();
            isTrue("Dedicated X448 public key MUST be instanceof X448PublicBCPGKey",
                j1.getPublicKey().getPublicKeyPacket().getKey() instanceof X448PublicBCPGKey);
            isTrue("Dedicated X448 secret key MUST be instanceof X448SecretBCPGKey",
                j1.getPrivateKey().getPrivateKeyDataPacket() instanceof X448SecretBCPGKey);

            BcPGPKeyPair b1 = toBcKeyPair(j1);
            isEncodingEqual(pubEnc, b1.getPublicKey().getEncoded());
            isEncodingEqual(privEnc, b1.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
            isTrue("Dedicated X448 public key MUST be instanceof X448PublicBCPGKey",
                b1.getPublicKey().getPublicKeyPacket().getKey() instanceof X448PublicBCPGKey);
            isTrue("Dedicated X448 secret key MUST be instanceof X448SecretBCPGKey",
                b1.getPrivateKey().getPrivateKeyDataPacket() instanceof X448SecretBCPGKey);

            JcaPGPKeyPair j2 = toJcaKeyPair(b1);
            isEncodingEqual(pubEnc, j2.getPublicKey().getEncoded());
            isEncodingEqual(privEnc, j2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
            isTrue("Dedicated X448 public key MUST be instanceof X448PublicBCPGKey",
                j2.getPublicKey().getPublicKeyPacket().getKey() instanceof X448PublicBCPGKey);
            isTrue("Dedicated X448 secret key MUST be instanceof X448SecretBCPGKey",
                j2.getPrivateKey().getPrivateKeyDataPacket() instanceof X448SecretBCPGKey);

            BcPGPKeyPair b2 = toBcKeyPair(j2);
            isEncodingEqual(pubEnc, b2.getPublicKey().getEncoded());
            isEncodingEqual(privEnc, b2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
            isTrue("Dedicated X448 public key MUST be instanceof X448PublicBCPGKey",
                b2.getPublicKey().getPublicKeyPacket().getKey() instanceof X448PublicBCPGKey);
            isTrue("Dedicated X448 secret key MUST be instanceof X448SecretBCPGKey",
                b2.getPrivateKey().getPrivateKeyDataPacket() instanceof X448SecretBCPGKey);

            isEquals("Creation time is preserved",
                date.getTime(), b2.getPublicKey().getCreationTime().getTime());
        }
    }

    private void testConversionOfBcKeyPair()
            throws PGPException, IOException
    {
        Date date = currentTimeRounded();
        X448KeyPairGenerator gen = new X448KeyPairGenerator();
        gen.init(new X448KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        for (int version: new int[]{PublicKeyPacket.VERSION_4, PublicKeyPacket.VERSION_6})
        {
            BcPGPKeyPair b1 = new BcPGPKeyPair(version, PublicKeyAlgorithmTags.X448, kp, date);
            byte[] pubEnc = b1.getPublicKey().getEncoded();
            byte[] privEnc = b1.getPrivateKey().getPrivateKeyDataPacket().getEncoded();
            isTrue("Dedicated X448 public key MUST be instanceof X448PublicBCPGKey",
                b1.getPublicKey().getPublicKeyPacket().getKey() instanceof X448PublicBCPGKey);
            isTrue("Dedicated X448 secret key MUST be instanceof X448SecretBCPGKey",
                b1.getPrivateKey().getPrivateKeyDataPacket() instanceof X448SecretBCPGKey);

            JcaPGPKeyPair j1 = toJcaKeyPair(b1);
            isEncodingEqual(pubEnc, j1.getPublicKey().getEncoded());
            isEncodingEqual(privEnc, j1.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
            isTrue("Dedicated X448 public key MUST be instanceof X448PublicBCPGKey",
                j1.getPublicKey().getPublicKeyPacket().getKey() instanceof X448PublicBCPGKey);
            isTrue("Dedicated X448 secret key MUST be instanceof X448SecretBCPGKey",
                j1.getPrivateKey().getPrivateKeyDataPacket() instanceof X448SecretBCPGKey);

            BcPGPKeyPair b2 = toBcKeyPair(j1);
            isEncodingEqual(pubEnc, b2.getPublicKey().getEncoded());
            isEncodingEqual(privEnc, b2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
            isTrue("Dedicated X448 public key MUST be instanceof X448PublicBCPGKey",
                b2.getPublicKey().getPublicKeyPacket().getKey() instanceof X448PublicBCPGKey);
            isTrue("Dedicated X448 secret key MUST be instanceof X448SecretBCPGKey",
                b2.getPrivateKey().getPrivateKeyDataPacket() instanceof X448SecretBCPGKey);

            JcaPGPKeyPair j2 = toJcaKeyPair(b2);
            isEncodingEqual(pubEnc, j2.getPublicKey().getEncoded());
            isEncodingEqual(privEnc, j2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
            isTrue("Dedicated X448 public key MUST be instanceof X448PublicBCPGKey",
                j2.getPublicKey().getPublicKeyPacket().getKey() instanceof X448PublicBCPGKey);
            isTrue("Dedicated X448 secret key MUST be instanceof X448SecretBCPGKey",
                j2.getPrivateKey().getPrivateKeyDataPacket() instanceof X448SecretBCPGKey);

            isEquals("Creation time is preserved",
                date.getTime(), j2.getPublicKey().getCreationTime().getTime());
        }
    }

    public static void main(String[] args)
    {
        runTest(new DedicatedX448KeyPairTest());
    }
}
