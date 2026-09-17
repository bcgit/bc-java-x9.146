package org.bouncycastle.pqc.crypto.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

public class AllTestsSnova
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight SNOVA Tests (ESK)");

        // the other SnovaTest KAT methods run from AllTestsSnovaSSK / AllTestsSnovaShake /
        // AllTestsSnovaShakeSSK so the four quarters, each minutes of KATs, run as separate (parallel) forks.
        suite.addTest(TestSuite.createTest(SnovaTest.class, "testTestVectorsESK"));

        return new AllTests.BCTestSetup(suite);
    }
}
