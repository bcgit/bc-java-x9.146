package org.bouncycastle.tls.test;

import junit.framework.TestCase;
import org.bouncycastle.tls.CertificateKeySelectionType;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

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

    public void testAll() throws Exception
    {
        for (MockX9146TlsServer.HybridExample demo : DEMOS)
        {
            for (short cks : CKS_TYPES)
            {
                System.out.println("running: " + demo + " cks: " + cks);
                runClientServer(cks, demo);
            }
        }
    }

    public void testSingle() throws Exception
    {
        runClientServer(CertificateKeySelectionType.cks_both, MockX9146TlsServer.HybridExample.mldsa44p256);
    }

    public void runClientServer(short cks_code, MockX9146TlsServer.HybridExample demo) throws Exception
    {
        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        ServerThread serverThread = new ServerThread(serverProtocol, demo);
        serverThread.start();

        MockX9146TlsClient client = new MockX9146TlsClient(null);

        // Adds the CKS Code to the Hello Message
        client.setCksCode(cks_code);

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

        ServerThread(TlsServerProtocol serverProtocol, MockX9146TlsServer.HybridExample hybridExample)
        {
            this.serverProtocol = serverProtocol;
            this.hybridExample = hybridExample;
        }

        public void run()
        {
            try
            {
                MockX9146TlsServer server = new MockX9146TlsServer();
                server.setSelectedHybridTest(hybridExample);
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
