package org.bouncycastle.tls.test;

import junit.framework.TestCase;
import org.bouncycastle.tls.CertificateKeySelection;
import org.bouncycastle.tls.CertificateKeySelectionType;
import org.bouncycastle.tls.KeySelection;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.Vector;

public class TlsX9146ProtocolTest
    extends TestCase
{
    short[] CKS_TYPES = new short[]{
        CertificateKeySelectionType.cks_default,
        CertificateKeySelectionType.cks_native,
        CertificateKeySelectionType.cks_alternate,
        CertificateKeySelectionType.cks_both
    };

    MockX9146TlsServer.HybridExample[] DEMOS = new MockX9146TlsServer.HybridExample[]{
        MockX9146TlsServer.HybridExample.mldsa44p256,
        MockX9146TlsServer.HybridExample.mldsa65p384,
        MockX9146TlsServer.HybridExample.mldsa87p521,
        MockX9146TlsServer.HybridExample.mldsa44rsa3072
    };

//    public void testAll()
//        throws Exception
//    {
//        for (MockX9146TlsServer.HybridExample demo : DEMOS)
//        {
//            for (short cks : CKS_TYPES)
//            {
//                System.out.println("running: " + demo + " cks: " + cks);
//                runClientServer(cks, demo);
//            }
//        }
//    }

    public void test10000()
        throws Exception
    {
        double total = 0;
        int delay_amount = 100;
        short cks_code = CertificateKeySelectionType.cks_default;
        MockX9146TlsServer.HybridExample demo = MockX9146TlsServer.HybridExample.noPQC;
        CertificateKeySelection CKS = new CertificateKeySelection(new Vector<KeySelection>()
        {{
            add(KeySelection.Default);
            add(KeySelection.Chimera_Native);
            add(KeySelection.Chimera_Alternative);
            add(KeySelection.Chimera_Hybrid);
        }}
        );
        for (int i = 0; i < 10000 + delay_amount; i++)
        {
            PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
            PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
            PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
            PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

            TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
            TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

            ServerThread serverThread = new ServerThread(serverProtocol, demo, CKS);
            serverThread.start();

            MockX9146TlsClient client = new MockX9146TlsClient(null);

            client.setCKS(new CertificateKeySelection(new Vector<KeySelection>()
                {{
                    add(KeySelection.Default);
                    add(KeySelection.Chimera_Native);
                    add(KeySelection.Chimera_Alternative);
                    add(KeySelection.Chimera_Hybrid);
                }}
            ));

            long startTime = System.nanoTime();
            clientProtocol.connect(client);

            // NOTE: Because we write-all before we read-any, this length can't be more than the pipe capacity
            int length = 1000;

            byte[] data = new byte[length];
            client.getCrypto().getSecureRandom().nextBytes(data);

            OutputStream output = clientProtocol.getOutputStream();
            output.write(data);

            byte[] echo = new byte[data.length];
            int count = Streams.readFully(clientProtocol.getInputStream(), echo);

            assertEquals(count, data.length);
            assertTrue(Arrays.areEqual(data, echo));

            output.close();

            long endTime = System.nanoTime();
            double durationInNanos = (endTime - startTime) / 1000000.0;
            if (i > delay_amount)
            {
                total += durationInNanos;
            }

            serverThread.join();
        }
        System.out.println(total / 10000.0);
    }

    public void testSingle()
        throws Exception
    {
        runClientServer(CertificateKeySelectionType.cks_both,
            MockX9146TlsServer.HybridExample.mldsa44p256,
            new CertificateKeySelection(new Vector<KeySelection>()
            {{
                add(KeySelection.Chimera_Hybrid);
                add(KeySelection.Chimera_Alternative);
                add(KeySelection.Chimera_Native);
            }}
            )
        );
    }

    public void runClientServer(short cks_code, MockX9146TlsServer.HybridExample demo, CertificateKeySelection serverCKS)
        throws Exception
    {
        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        ServerThread serverThread = new ServerThread(serverProtocol, demo, serverCKS);
        serverThread.start();

        MockX9146TlsClient client = new MockX9146TlsClient(null);

        client.setCKS(new CertificateKeySelection(new Vector<KeySelection>()
        {{
            add(KeySelection.Default);
            add(KeySelection.Chimera_Native);
            add(KeySelection.Chimera_Alternative);
            add(KeySelection.Chimera_Hybrid);
            add(KeySelection.Composite_Hybrid);
            add(KeySelection.Related_Certificates_Pair_Hybrid);
        }}
        ));

        clientProtocol.connect(client);

        // NOTE: Because we write-all before we read-any, this length can't be more than the pipe capacity
        int length = 1000;

        byte[] data = new byte[length];
        client.getCrypto().getSecureRandom().nextBytes(data);

        OutputStream output = clientProtocol.getOutputStream();
        output.write(data);

        byte[] echo = new byte[data.length];
        int count = Streams.readFully(clientProtocol.getInputStream(), echo);

        assertEquals(count, data.length);
        assertTrue(Arrays.areEqual(data, echo));

        output.close();

        serverThread.join();
    }

    static class ServerThread
        extends Thread
    {
        private final TlsServerProtocol serverProtocol;
        private final MockX9146TlsServer.HybridExample hybridExample;
        private final CertificateKeySelection CKS;

        ServerThread(TlsServerProtocol serverProtocol, MockX9146TlsServer.HybridExample hybridExample, CertificateKeySelection CKS)
        {
            this.serverProtocol = serverProtocol;
            this.hybridExample = hybridExample;
            this.CKS = CKS;
        }

        public void run()
        {
            try
            {
                MockX9146TlsServer server = new MockX9146TlsServer();
                server.setSelectedHybridTest(hybridExample);
                server.setCKS(CKS);
                serverProtocol.accept(server);
                Streams.pipeAll(serverProtocol.getInputStream(), serverProtocol.getOutputStream());
                serverProtocol.close();
            }
            catch (Exception e)
            {
            }
        }
    }
}
