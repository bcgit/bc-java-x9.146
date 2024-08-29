package org.bouncycastle.tls.test;

import junit.framework.TestCase;
import org.bouncycastle.tls.CertificateKeySelectionType;
import org.bouncycastle.tls.TlsClient;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class TlsX9146ProtocolTest
    extends TestCase
{
    static TlsClientProtocol openTlsConnection(String address, int port, TlsClient client) throws IOException
    {
        Socket s = new Socket(address, port);
        System.out.println(s.getPort());
        System.out.println(s.getInetAddress());
        System.out.println(s.getLocalAddress());
        TlsClientProtocol protocol = new TlsClientProtocol(s.getInputStream(), s.getOutputStream());
        protocol.connect(client);
        return protocol;
    }
    public void testClientWithWolfServer() throws Exception
    {
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();


        // hash:  0xFE (254)
        // sig:   0xA0 (160)


        MockX9146TlsClient client = new MockX9146TlsClient(null);
//        client.setCksCode(CertificateKeySelectionType.cks_default);
//        client.setCksCode(CertificateKeySelectionType.cks_native);
//        client.setCksCode(CertificateKeySelectionType.cks_alternate);
        client.setCksCode(CertificateKeySelectionType.cks_both);

        TlsClientProtocol clientProtocol = openTlsConnection("127.0.0.1", 11111, client);

        // Adds the CKS Code to the Hello Message

//        clientProtocol.connect(client);

        byte[] data = "hello wolfssl!".getBytes();
//        client.getCrypto().getSecureRandom().nextBytes(data);

        OutputStream output = clientProtocol.getOutputStream();
        output.write(data);

        byte[] echoBuf = new byte[1000];
        int count = Streams.readFully(clientProtocol.getInputStream(), echoBuf);
        byte[] echo = Arrays.copyOf(echoBuf, count);

        System.out.println("data: " + Hex.toHexString(data));
        System.out.println("echo: " + Hex.toHexString(echo));


        assertTrue(Arrays.areEqual("I hear you fa shizzle!".getBytes(), echo));

        output.close();

    }


    public void testServerWithWolfClient() throws Exception
    {
        ServerSocket ss = new ServerSocket(11111);
    
        System.out.println("ServerSocket port: " + ss.getLocalPort());
        System.out.println("ServerSocket ip: " + ss.getInetAddress());
    
        try {
            Socket s = ss.accept();
            TlsServerProtocol tlsServerProtocol = new TlsServerProtocol();
            try {
                tlsServerProtocol = new TlsServerProtocol(s.getInputStream(), s.getOutputStream());
                MockX9146TlsServer server = new MockX9146TlsServer();
                server.setCksCode(3);
                tlsServerProtocol.accept(server);
            } finally {
                tlsServerProtocol.close();
                s.close();
            }
        } finally {
            ss.close();
        }
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
//        client.setCksCode(CertificateKeySelectionType.cks_default);
        client.setCksCode(CertificateKeySelectionType.cks_native);
//        client.setCksCode(CertificateKeySelectionType.cks_alternate);
//        client.setCksCode(CertificateKeySelectionType.cks_both);

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
            }
        }
    }
}
