package org.bouncycastle.tls.test;

import junit.framework.TestCase;
import org.bouncycastle.tls.CertificateKeySelectionType;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.TlsClient;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

import static java.lang.Thread.sleep;

public class TlsX9146ProtocolEnumeratedTest
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

    public void setBcClientCKSCode(MockX9146TlsClient bcClient, int cks)
    {
        switch (cks)
        {
            case 0:
                bcClient.setCksCode(CertificateKeySelectionType.cks_default);
                break;
            case 1:
                bcClient.setCksCode(CertificateKeySelectionType.cks_native);
                break;
            case 2:
                bcClient.setCksCode(CertificateKeySelectionType.cks_alternate);
                break;
            case 3:
                bcClient.setCksCode(CertificateKeySelectionType.cks_both);
                break;
        }
    }

    public void setBcServerCKSCode(MockX9146TlsServer bcServer, int cks)
    {
        switch (cks)
        {
            case 0:
                bcServer.setCksCode(CertificateKeySelectionType.cks_default);
                break;
            case 1:
                bcServer.setCksCode(CertificateKeySelectionType.cks_native);
                break;
            case 2:
                bcServer.setCksCode(CertificateKeySelectionType.cks_alternate);
                break;
            case 3:
                bcServer.setCksCode(CertificateKeySelectionType.cks_both);
                break;
        }
    }

    public void setBcClientTls(MockX9146TlsClient bcClient, int tls)
    {
        switch (tls)
        {
            case 1:
                bcClient.setSelectedCipherSuites(new int[]{CipherSuite.TLS_AES_128_GCM_SHA256});
                break;
            case 2:
                bcClient.setSelectedCipherSuites(new int[]{CipherSuite.TLS_AES_256_GCM_SHA384});
                break;
            case 3:
                bcClient.setSelectedCipherSuites(new int[]{CipherSuite.TLS_CHACHA20_POLY1305_SHA256});
                break;
            case 4:
                bcClient.setSelectedCipherSuites(new int[]{CipherSuite.TLS_AES_128_CCM_SHA256});
                break;
            case 5:
                bcClient.setSelectedCipherSuites(new int[]{CipherSuite.TLS_AES_128_CCM_8_SHA256});
                break;
        }
    }

    public void setBcServerTls(MockX9146TlsServer bcServer, int tls)
    {
        switch (tls)
        {
            case 1:
                bcServer.setSelectedCipherSuites(new int[]{CipherSuite.TLS_AES_128_GCM_SHA256});
                break;
            case 2:
                bcServer.setSelectedCipherSuites(new int[]{CipherSuite.TLS_AES_256_GCM_SHA384});
                break;
            case 3:
                bcServer.setSelectedCipherSuites(new int[]{CipherSuite.TLS_CHACHA20_POLY1305_SHA256});
                break;
            case 4:
                bcServer.setSelectedCipherSuites(new int[]{CipherSuite.TLS_AES_128_CCM_SHA256});
                break;
            case 5:
                bcServer.setSelectedCipherSuites(new int[]{CipherSuite.TLS_AES_128_CCM_8_SHA256});
                break;
        }
    }


    public static void runWolfSSLServer(int nativeCode)
    {
        //TODO have km security level
        String nativeServer = "";
        if (nativeCode == 1)
        {
            nativeServer = "rsa3072";
        }
        else if (nativeCode == 2)
        {
            nativeServer = "P256";
        }

        String workingDirectory = "/home/roy/Projects/wolfSSL/wolfssl/";
        String serverExecutable = "/home/roy/Projects/wolfSSL/wolfssl/examples/server/server";
        String certFile = "/home/roy/Projects/wolfSSL/wolfssl-examples/X9.146/server-" + nativeServer + "-mldsa44-cert.pem";
        String privateKeyFile = "/home/roy/Projects/wolfSSL/wolfssl-examples/X9.146/server-" + nativeServer + "-key.pem";
        String altPrivateKeyFile = "/home/roy/Projects/wolfSSL/wolfssl-examples/X9.146/server-mldsa44-key-pq.pem";

        ProcessBuilder processBuilder = new ProcessBuilder(serverExecutable, "-d", "-v", "4",
                "-c", certFile, "-k", privateKeyFile, "--altPrivKey", altPrivateKeyFile);
        processBuilder.directory(new java.io.File(workingDirectory));

        try
        {
            Process process = processBuilder.start();

            // Read output from the process
            BufferedReader stdoutReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = stdoutReader.readLine()) != null)
            {
                System.out.println(line);
            }

            // Read any errors from the attempted command
            BufferedReader stderrReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            while ((line = stderrReader.readLine()) != null)
            {
                System.err.println(line);
            }

            // Wait for the process to complete
            int exitCode = process.waitFor();
            System.out.println("Process exited with code: " + exitCode);

        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
        catch (InterruptedException e)
        {
            e.printStackTrace();
            Thread.currentThread().interrupt();
        }
    }

    public void runWolfSSLClient(int nativeCode, int alt, int km, int tls)
    {
        //TODO have km security level
        String nativeCA = "";
        if (nativeCode == 1)
        {
            nativeCA = "rsa3072";
        }
        else if (nativeCode == 2)
        {
            nativeCA = "P256";
        }
        String workingDirectory = "/home/roy/Projects/wolfSSL/wolfssl/";
        String clientExecutable = "/home/roy/Projects/wolfSSL/wolfssl/examples/client/client";
        String caCertificatePath = "/home/roy/Projects/wolfSSL/wolfssl-examples/X9.146/ca-" + nativeCA + "-mldsa44-cert.pem";

        ProcessBuilder processBuilder = new ProcessBuilder(
                clientExecutable,
                "-v", "4",
                "-A", caCertificatePath
        );
        processBuilder.directory(new java.io.File(workingDirectory));


        try {
            Process process = processBuilder.start();

            // Read output from the process
            BufferedReader stdoutReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = stdoutReader.readLine()) != null) {
                System.out.println(line);
            }

            // Read any errors from the attempted command
            BufferedReader stderrReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            while ((line = stderrReader.readLine()) != null) {
                System.err.println(line);
            }

            // Wait for the process to complete
            int exitCode = process.waitFor();
            System.out.println("Process exited with code: " + exitCode);

        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
            Thread.currentThread().interrupt();
        }
    }

    public void testAll() throws Exception
    {
        /* Client & Server
        1 - WolfSSL
        2 - OpenSSL
        3 - BC
         */
        int[] test_clients = new int[]{1, 2, 3};
        int[] test_servers = new int[]{1, 2, 3};

        /* CKS
        0 - Default
        1 - Native
        2 - Alternative
        3 - Both
         */
        int[] test_cks = new int[]{0, 1, 2, 3};

        /* Native
        1 - RSA
        2 - ECDSA
         */
        int[] test_native = new int[]{1, 2};

        /* Alt
        3 - ML-DSA
        4 - SLH-DSA
         */
        int[] test_alt = new int[]{3, 4};

        /* KM
        1 - ECDHE
        2 - ML-KEM
         */
        int[] test_km = new int[]{1, 2};

        /* TLS
        1 - TLS_AES_128_GCM_SHA256
        2 - TLS_AES_256_GCM_SHA384
        3 - TLS_CHACHA20_POLY1305_SHA256
        4 - TLS_AES_128_CCM_SHA256
        5 - TLS_AES_128_CCM_8_SHA256
         */
        int[] test_tls = new int[]{1, 2, 3, 4, 5};

         for (int client : test_clients)
         {
             if (client == 2) continue;
             for (int server : test_servers)
             {
                 if (server == 2) continue;
                 for (int cks : test_cks)
                 {
                     for (int nativeType : test_native)
                     {
                         if (nativeType == 1) continue;
                         for (int alt : test_alt)
                         {
                             if (alt == 4) continue;
                             for (int km : test_km)
                             {
                                 if (km == 2) continue;
                                 for (int tls : test_tls)
                                 {
                                     String combination = client +
                                             "." + server +
                                             "." + cks +
                                             "." + nativeType +
                                             "." + alt +
                                             "." + km +
                                             "." + tls;
                                     try
                                     {
                                         if (client == 3 && server == 3)
                                         {
                                             clientServer(cks, nativeType, alt, km, tls);
                                         }
                                         else if (client == 3 && server == 1)
                                         {
                                             // Using a Runnable to wrap the server execution logic
                                             Runnable serverTask = new Runnable() {
                                                 public void run() {
                                                     try {
                                                         runWolfSSLServer(nativeType);
                                                     } catch (Exception e) {
                                                         // Handle exceptions thrown by the server
                                                         e.printStackTrace();
                                                     }
                                                 }
                                             };

                                             // Create and start the server thread
                                             Thread serverThread = new Thread(serverTask);
                                             serverThread.start();

                                             // Optionally, wait for the server thread to be ready or sleep for some time
                                             Thread.sleep(5000); // For example, wait 1 second

                                             // Run client logic after starting the server
                                             clientWithWolfServer(cks, nativeType, alt, km, tls);
                                             Thread.sleep(5000); // For example, wait 1 second

                                             // Optionally, wait for the server to finish or forcibly terminate it
                                              serverThread.join(); // Wait for the server thread to finish

//
//
//                                             WolfServerThread wolfServerThread = new WolfServerThread(nativeType);
//                                             wolfServerThread.start();
//
//                                             sleep(3000);
//
//                                             wolfServerThread.join();

                                         }
//                                         else if (client == 1 && server == 3)
//                                         {
//                                             serverWithWolfClient(cks, nativeType, alt, km, tls);
//                                         }
                                         else
                                         {
                                             throw new Exception("Not implemented!");
                                         }
                                         System.out.print(combination);
                                         System.out.println(" -> PASS");


                                     }
                                     catch (Exception e)
                                     {
                                         System.out.print(combination);
                                         System.out.println(" -> FAILED ( " + e + " )");
                                     }
                                 }
                             }
                         }
                     }
                 }
             }
         }

    }

    public void testCustom()
        throws Exception
    {

        // Using a Runnable to wrap the server execution logic
        Runnable serverTask = new Runnable() {
            public void run() {
                try {
                    runWolfSSLServer(2);
                } catch (Exception e) {
                    // Handle exceptions thrown by the server
                    e.printStackTrace();
                }
            }
        };

        // Create and start the server thread
        Thread serverThread = new Thread(serverTask);
        serverThread.start();

        // Optionally, wait for the server thread to be ready or sleep for some time
         Thread.sleep(1000); // For example, wait 1 second

        // Run client logic after starting the server
        clientWithWolfServer(2, 2, 3, 1, 1);

        // Optionally, wait for the server to finish or forcibly terminate it
        // serverThread.join(); // Wait for the server thread to finish


    }

    public void clientWithWolfServer(int cks, int nativeCode, int alt, int km, int tls) throws Exception
    {
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();

        MockX9146TlsClient client = new MockX9146TlsClient(null);
        setBcClientCKSCode(client, cks);
        setBcClientTls(client, tls);

        TlsClientProtocol clientProtocol = openTlsConnection("127.0.0.1", 11111, client);



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


    public void serverWithWolfClient(int cks, int nativeCode, int alt, int km, int tls) throws Exception
    {
        ServerSocket ss = new ServerSocket(11111);
    
        System.out.println("ServerSocket port: " + ss.getLocalPort());
        System.out.println("ServerSocket ip: " + ss.getInetAddress());
    
        try {
            Socket s = ss.accept();
            TlsServerProtocol tlsServerProtocol = new TlsServerProtocol();
            try {
                tlsServerProtocol = new TlsServerProtocol(s.getInputStream(), s.getOutputStream());
                MockX9146TlsServer bcServer = new MockX9146TlsServer();
                setBcServerCKSCode(bcServer, cks);
                setBcServerTls(bcServer, tls);

                tlsServerProtocol.accept(bcServer);
            } finally {
                tlsServerProtocol.close();
//                s.close();
            }
        } finally {
            ss.close();
        }
    }

    public void clientServer(int cks, int nativeCode, int alt, int km, int tls) throws Exception
    {
        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        MockX9146TlsServer bcServer = new MockX9146TlsServer();
        setBcServerCKSCode(bcServer, cks);
        setBcServerTls(bcServer, tls);

        ServerThread serverThread = new ServerThread(serverProtocol, bcServer);
        serverThread.start();

        MockX9146TlsClient client = new MockX9146TlsClient(null);
        setBcClientCKSCode(client, cks);
        setBcClientTls(client, tls);



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

    static class WolfServerThread
    extends Thread
    {
        private final int nativeCode;
        WolfServerThread(int nativeCode)
        {
            this.nativeCode = nativeCode;
        }

        public void run()
        {
            try
            {
                runWolfSSLServer(nativeCode);
            }
            catch (Exception e)
            {
            }
        }
    }
    static class ServerThread
        extends Thread
    {
        private final TlsServerProtocol serverProtocol;
        private final MockX9146TlsServer server;

        ServerThread(TlsServerProtocol serverProtocol, MockX9146TlsServer server)
        {
            this.serverProtocol = serverProtocol;
            this.server = server;
        }

        public void run()
        {
            try
            {
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
