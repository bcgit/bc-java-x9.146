package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Optional;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * jdk1.11 multi-release twin of XDHKeys: produces the {@code XECKey}-implementing
 * {@code BC11XDHPublicKey} / {@code BC11XDHPrivateKey} classes and accepts incoming JDK
 * {@code XECPublicKey} / {@code XECPrivateKey} objects. Keep the method set in step with the
 * base copy.
 */
class XDHKeys
{
    static PublicKey publicKey(byte[] prefix, byte[] rawData)
        throws InvalidKeySpecException
    {
        return new BC11XDHPublicKey(prefix, rawData);
    }

    static PublicKey publicKey(SubjectPublicKeyInfo keyInfo)
    {
        return new BC11XDHPublicKey(keyInfo);
    }

    static PublicKey publicKey(AsymmetricKeyParameter params)
    {
        return new BC11XDHPublicKey(params);
    }

    static PrivateKey privateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        return new BC11XDHPrivateKey(keyInfo);
    }

    static PrivateKey privateKey(AsymmetricKeyParameter params)
    {
        return new BC11XDHPrivateKey(params);
    }

    static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey key)
        throws InvalidKeyException
    {
        if (key instanceof BCXDHPrivateKey)
        {
            return ((BCXDHPrivateKey)key).engineGetKeyParameters();
        }

        if (key instanceof XECPrivateKey)
        {
            XECPrivateKey jcePriv = (XECPrivateKey)key;

            Optional<byte[]> scalar = jcePriv.getScalar();
            if (!scalar.isPresent())
            {
                throw new InvalidKeyException("cannot use XEC private key without scalar");
            }

            String algorithm = jcePriv.getAlgorithm();

            if ("X25519".equalsIgnoreCase(algorithm))
            {
                return EdECUtil.getX25519PrivateKey(scalar.get());
            }

            if ("X448".equalsIgnoreCase(algorithm))
            {
                return EdECUtil.getX448PrivateKey(scalar.get());
            }

            if ("XDH".equalsIgnoreCase(algorithm))
            {
                AlgorithmParameterSpec params = jcePriv.getParams();
                if (params instanceof NamedParameterSpec)
                {
                    String name = ((NamedParameterSpec)params).getName();

                    if ("X25519".equalsIgnoreCase(name))
                    {
                        return EdECUtil.getX25519PrivateKey(scalar.get());
                    }

                    if ("X448".equalsIgnoreCase(name))
                    {
                        return EdECUtil.getX448PrivateKey(scalar.get());
                    }
                }
            }

            throw new InvalidKeyException("cannot use XEC private key with unknown algorithm");
        }

        // fall back to the shared handling (BC key classes, then getEncoded()) so third-party
        // provider keys are accepted on JDK 11+ exactly as they are on JDK 8.
        return EdECUtil.generatePrivateKeyParameter(key);
    }

    static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey key)
        throws InvalidKeyException
    {
        if (key instanceof BCXDHPublicKey)
        {
            return ((BCXDHPublicKey)key).engineGetKeyParameters();
        }

        if (key instanceof XECPublicKey)
        {
            XECPublicKey jcePub = (XECPublicKey)key;

            BigInteger u = jcePub.getU();
            if (u.signum() < 0)
            {
                throw new InvalidKeyException("cannot use XEC public key with negative U value");
            }

            String algorithm = jcePub.getAlgorithm();

            if ("X25519".equalsIgnoreCase(algorithm))
            {
                return EdECUtil.getX25519PublicKey(u);
            }

            if ("X448".equalsIgnoreCase(algorithm))
            {
                return EdECUtil.getX448PublicKey(u);
            }

            if ("XDH".equalsIgnoreCase(algorithm))
            {
                AlgorithmParameterSpec params = jcePub.getParams();
                if (params instanceof NamedParameterSpec)
                {
                    String name = ((NamedParameterSpec)params).getName();

                    if ("X25519".equalsIgnoreCase(name))
                    {
                        return EdECUtil.getX25519PublicKey(u);
                    }

                    if ("X448".equalsIgnoreCase(name))
                    {
                        return EdECUtil.getX448PublicKey(u);
                    }
                }
            }

            throw new InvalidKeyException("cannot use XEC public key with unknown algorithm");
        }

        // fall back to the shared handling (BC key classes, then getEncoded()) so third-party
        // provider keys are accepted on JDK 11+ exactly as they are on JDK 8.
        return EdECUtil.generatePublicKeyParameter(key);
    }

    /**
     * Return a KeySpec for a version-specific spec type - here the JDK 11+ XEC key specs - or
     * null when the request is not one this JDK version bridges. The key's own parameters are
     * carried across, so the curve the spec names is the one the key was built with.
     */
    static KeySpec getKeySpec(Key key, Class<?> spec)
        throws InvalidKeySpecException
    {
        if (spec.isAssignableFrom(XECPrivateKeySpec.class))
        {
            if (key instanceof XECPrivateKey)
            {
                XECPrivateKey xdhKey = (XECPrivateKey)key;

                Optional<byte[]> scalar = xdhKey.getScalar();
                if (scalar.isPresent())
                {
                    return new XECPrivateKeySpec(xdhKey.getParams(), scalar.get());
                }
                else
                {
                    throw new IllegalArgumentException("no scalar data associated with key");
                }
            }
        }
        else if (spec.isAssignableFrom(XECPublicKeySpec.class))
        {
            if (key instanceof XECPublicKey)
            {
                XECPublicKey xdhKey = (XECPublicKey)key;

                return new XECPublicKeySpec(xdhKey.getParams(), xdhKey.getU());
            }
        }

        return null;
    }

    /**
     * Generate a private key from a version-specific KeySpec - here the JDK 11+
     * XECPrivateKeySpec - or return null when the spec is not one this JDK version bridges.
     * RFC 7748 sec. 5 gives the scalar as a fixed-width little-endian octet string, which is
     * what the spec carries and what the lightweight key parameters take, so it is used as it
     * stands and only its length is checked.
     */
    static PrivateKey generatePrivate(KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof XECPrivateKeySpec)
        {
            XECPrivateKeySpec xdhSpec = (XECPrivateKeySpec)keySpec;
            String name = getCurveName(xdhSpec.getParams());

            try
            {
                AsymmetricKeyParameter parameters;
                if ("X448".equalsIgnoreCase(name))
                {
                    parameters = EdECUtil.getX448PrivateKey(xdhSpec.getScalar());
                }
                else if ("X25519".equalsIgnoreCase(name))
                {
                    parameters = EdECUtil.getX25519PrivateKey(xdhSpec.getScalar());
                }
                else
                {
                    throw new InvalidKeySpecException("unrecognized named parameters: " + name);
                }

                return privateKey(parameters);
            }
            catch (InvalidKeyException e)
            {
                throw new InvalidKeySpecException(e.getMessage(), e);
            }
        }

        return null;
    }

    /**
     * Generate a public key from a version-specific KeySpec - here the JDK 11+ XECPublicKeySpec
     * - or return null when the spec is not one this JDK version bridges. The u-coordinate
     * arrives as a BigInteger and is reduced and encoded little-endian by EdECUtil, the same
     * conversion an incoming JDK XECPublicKey goes through.
     */
    static PublicKey generatePublic(KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof XECPublicKeySpec)
        {
            XECPublicKeySpec xdhSpec = (XECPublicKeySpec)keySpec;
            String name = getCurveName(xdhSpec.getParams());

            try
            {
                AsymmetricKeyParameter parameters;
                if ("X448".equalsIgnoreCase(name))
                {
                    parameters = EdECUtil.getX448PublicKey(xdhSpec.getU());
                }
                else if ("X25519".equalsIgnoreCase(name))
                {
                    parameters = EdECUtil.getX25519PublicKey(xdhSpec.getU());
                }
                else
                {
                    throw new InvalidKeySpecException("unrecognized named parameters: " + name);
                }

                return publicKey(parameters);
            }
            catch (InvalidKeyException e)
            {
                throw new InvalidKeySpecException(e.getMessage(), e);
            }
        }

        return null;
    }

    /**
     * The XEC specs type their parameters as AlgorithmParameterSpec rather than
     * NamedParameterSpec, so the curve name has to be recovered; null for anything else, which
     * the callers report as an unrecognized parameter set.
     */
    private static String getCurveName(AlgorithmParameterSpec params)
    {
        if (params instanceof NamedParameterSpec)
        {
            return ((NamedParameterSpec)params).getName();
        }

        return null;
    }
}
