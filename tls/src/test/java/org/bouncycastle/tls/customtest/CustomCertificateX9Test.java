package org.bouncycastle.tls.customtest;

import junit.framework.TestCase;

import java.nio.file.Files;
import java.nio.file.Paths;

public class CustomCertificateX9Test
    extends TestCase

{
    public void testCustom()
            throws Exception
    {
        byte[] derBytes = Files.readAllBytes(Paths.get(""));
    }
}
