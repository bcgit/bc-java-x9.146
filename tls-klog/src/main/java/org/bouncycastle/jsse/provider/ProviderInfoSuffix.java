package org.bouncycastle.jsse.provider;

/**
 * The build label the JSSE provider adds to its info string, as built into <code>bctls-klog</code>.
 * <p>
 * This class replaces the empty constant of the same name in the standard <code>bctls</code> build,
 * so that <code>Security.getProvider("BCJSSE").getInfo()</code> distinguishes the key-logging jar
 * from the standard one. The two are otherwise indistinguishable at the JCA boundary - same
 * provider name, version and services - while only this one can report connection secrets, so the
 * label is how an operator inspecting a running JVM can tell which is installed. See
 * <code>org.bouncycastle.tls.KeyLog</code> for the reporting itself.
 */
abstract class ProviderInfoSuffix
{
    static final String SUFFIX = " (Key Logger)";
}
