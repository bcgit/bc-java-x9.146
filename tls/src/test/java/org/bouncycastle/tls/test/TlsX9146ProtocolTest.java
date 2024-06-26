package org.bouncycastle.tls.test;

import junit.framework.TestCase;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

public class TlsX9146ProtocolTest
    extends TestCase
{
    public static short cks_default = 0;    // native only (alternate not present)
    public static short cks_native = 1;     // ignore alternate
    public static short cks_alternate = 2;  // ignore native
    public static short cks_both = 3;       // native and alternate
    public static short cks_external = 4;   // codes are external to tls protocol ???

    public void testClientWithWolfServer() throws Exception
    {
        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);


        MockX9146TlsClient client = new MockX9146TlsClient(null);

        // Adds the CKS Code to the Hello Message
        client.setCksCode(cks_alternate);

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

    }


    public void testClientServer() throws Exception
    {
        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        ServerThread serverThread = new ServerThread(serverProtocol);
        serverThread.start();

        MockX9146TlsClient client = new MockX9146TlsClient(null);

        // Adds the CKS Code to the Hello Message
        client.setCksCode(cks_alternate);

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

        ServerThread(TlsServerProtocol serverProtocol)
        {
            this.serverProtocol = serverProtocol;
        }

        public void run()
        {
            try
            {
                MockX9146TlsServer server = new MockX9146TlsServer();
                serverProtocol.accept(server);
                Streams.pipeAll(serverProtocol.getInputStream(), serverProtocol.getOutputStream());
                serverProtocol.close();
            }
            catch (Exception e)
            {
//                throw new RuntimeException(e);
            }
        }
    }
}
