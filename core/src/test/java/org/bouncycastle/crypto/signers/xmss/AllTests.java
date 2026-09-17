package org.bouncycastle.crypto.signers.xmss;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

public class AllTests
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("XMSS engine tests");

        suite.addTestSuite(AddressTests.class);
        suite.addTestSuite(WOTSPlusTests.class);
        suite.addTestSuite(KeyParametersBuilderTests.class);
        suite.addTestSuite(ParameterBoundsTests.class);
        suite.addTestSuite(MalformedKeyInfoTests.class);
        suite.addTestSuite(OpaqueStateHandleTests.class);
        suite.addTestSuite(ExhaustedKeyTests.class);
        suite.addTestSuite(SignerStateHandoverTests.class);
        suite.addTestSuite(SignerMessageBufferTests.class);
        suite.addTestSuite(SignerInitParametersTests.class);
        suite.addTestSuite(SignerConcurrencyTests.class);
        suite.addTestSuite(BDSStateSerializationTests.class);
        suite.addTestSuite(CorruptedStateTests.class);
        suite.addTestSuite(BDSStateMapIndexEnumerationTests.class);
        suite.addTestSuite(PositionRecordCrossCheckTests.class);
        suite.addTestSuite(OneTimeKeyReuseTests.class);
        suite.addTestSuite(LargeIndexEncodingTests.class);
        suite.addTestSuite(CraftedLegacyStateTests.class);
        suite.addTestSuite(IsaraOidKeyTests.class);
        suite.addTestSuite(PrivateKeyEncodingLayoutTests.class);
        suite.addTestSuite(KeyEqualityTests.class);
        suite.addTestSuite(KeyDestructionTests.class);

        return new BCTestSetup(suite);
    }

    static class BCTestSetup
        extends TestSetup
    {
        public BCTestSetup(Test test)
        {
            super(test);
        }

        protected void setUp()
        {

        }

        protected void tearDown()
        {

        }
    }
}
