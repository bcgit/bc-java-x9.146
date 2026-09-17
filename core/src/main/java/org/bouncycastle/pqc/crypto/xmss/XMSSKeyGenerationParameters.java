package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * XMSS key-pair generation parameters.
 *
 * @deprecated use {@link org.bouncycastle.crypto.params.XMSSKeyGenerationParameters} instead.
 */
@Deprecated
public final class XMSSKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final XMSSParameters xmssParameters;

    /**
     * XMSSMT constructor...
     *
     * @param prng   Secure random to use.
     */
    public XMSSKeyGenerationParameters(XMSSParameters xmssParameters, SecureRandom prng)
    {
        super(prng,-1);

        this.xmssParameters = xmssParameters;
    }

    public XMSSParameters getParameters()
    {
        return xmssParameters;
    }
}
