package org.bouncycastle.tls.test;

import junit.framework.TestCase;
import org.bouncycastle.tls.CertificateKeySelectionType;
import org.bouncycastle.tls.TlsClient;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.util.Arrays;

import org.bouncycastle.util.io.Streams;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.net.ServerSocket;
import java.net.Socket;

import static java.lang.Thread.sleep;

public class TlsX9146InteroptTest
    extends TestCase
{
    static short CKS_TYPE = CertificateKeySelectionType.cks_both;
    // 0x00 = default
    // 0x01 = native
    // 0x02 = alternative
    // 0x03 = both

    static MockX9146TlsServer.HybridExample DEMO = MockX9146TlsServer.HybridExample.mldsa44p256;
    // 0 = ML-DSA 44 & P256
    // 1 = ML-DSA 65 & P384
    // 2 = ML-DSA 87 & P512
    // 3 = ML-DSA 44 & RSA3072

    static String wolfSSLWorkingDirectory = "/home/roy/Projects/wolfSSL/wolfssl/";
    //TODO: !!! CHANGE TO WOLFSSL DIR !!!
    static String pemDirectory = System.getProperty("user.dir") + "/src/test/resources/org/bouncycastle/tls/test/x9146/";

    // BC Client <--> WolfSSL Server
    public void testOneShotBCClientWithWolfServer() throws IOException, InterruptedException
    {
        // Run WolfSSL Server
        Runnable serverTask = new Runnable() {
            public void run() {
                try
                {
                    runWolfSSLServer();
                }
                catch (Exception e)
                {
                    // Handle exceptions thrown by the server
                    e.printStackTrace();
                }
            }
        };

        // Create and start the server thread
        Thread serverThread = new Thread(serverTask);
        serverThread.start();
        Thread.sleep(5000); // Might need to adjust this for different setups

        // Run BC Client
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();

        MockX9146TlsClient client = new MockX9146TlsClient(null);
        client.setCksCode(CKS_TYPE);

        TlsClientProtocol clientProtocol = openTlsConnection("127.0.0.1", 11111, client);

        byte[] data = "hello wolfssl!".getBytes();

        OutputStream output = clientProtocol.getOutputStream();
        output.write(data);

        byte[] echoBuf = new byte[1000];
        int count = Streams.readFully(clientProtocol.getInputStream(), echoBuf);
        byte[] echo = Arrays.copyOf(echoBuf, count);

//        System.out.println("data: " + Hex.toHexString(data));
//        System.out.println("echo: " + Hex.toHexString(echo));

        assertTrue(Arrays.areEqual("I hear you fa shizzle!".getBytes(), echo));

        output.close();

    }

    // WolfSSL Client <--> BC Server
    public void testOneShotWolfClientWithBCServer() throws InterruptedException
    {
        // Run BC Server
        Runnable serverTask = new Runnable()
        {
            public void run()
            {
                try
                {
                    runBouncyCastleServer();
                }
                catch (Exception e)
                {
                    // Handle exceptions thrown by the server
                    e.printStackTrace();
                }
            }
        };

        // Create and start the server thread
        Thread serverThread = new Thread(serverTask);
        serverThread.start();
        sleep(1000); // Might need to adjust this for different setups

        // Run WolfSSL Client
        runWolfSSLClient();
    }

    public void testClientWithWolfServer() throws Exception
    {
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();

        // hash:  0xFE (254)
        // sig:   0xA0 (160)

        MockX9146TlsClient client = new MockX9146TlsClient(null);
        client.setCksCode(CKS_TYPE);

        TlsClientProtocol clientProtocol = openTlsConnection("127.0.0.1", 11111, client);

        byte[] data = "hello wolfssl!".getBytes();

        OutputStream output = clientProtocol.getOutputStream();
        output.write(data);

        byte[] echoBuf = new byte[1000];
        int count = Streams.readFully(clientProtocol.getInputStream(), echoBuf);
        byte[] echo = Arrays.copyOf(echoBuf, count);

        System.out.println("data: " + new String(data, "UTF-8"));
        System.out.println("echo: " + new String(echo, "UTF-8"));

        assertTrue(Arrays.areEqual("I hear you fa shizzle!".getBytes(), echo));

        output.close();

    }

    public void testServerWithWolfClient() throws Exception
    {
        ServerSocket ss = new ServerSocket(11111);

        System.out.println("ServerSocket port: " + ss.getLocalPort());
        System.out.println("ServerSocket ip: " + ss.getInetAddress());

        try
        {
            Socket s = ss.accept();
            TlsServerProtocol tlsServerProtocol = new TlsServerProtocol();
            try
            {
                tlsServerProtocol = new TlsServerProtocol(s.getInputStream(), s.getOutputStream());
                MockX9146TlsServer server = new MockX9146TlsServer();
                server.setSupportedCksCode(CKS_TYPE);
                server.setSelectedHybridTest(DEMO);

                tlsServerProtocol.accept(server);
            }
            finally
            {
                tlsServerProtocol.close();
//                s.close();
            }
        }
        finally
        {
            ss.close();
        }
    }

    public static void runWolfSSLServer()
    {

        String certFile = pemDirectory;
        String privateKeyFile = pemDirectory;
        String altPrivateKeyFile = pemDirectory;
        // Run WolfSSL Server
        switch (DEMO)
        {
            case mldsa44p256:
                certFile += "server-P256-mldsa44-cert.pem";
                privateKeyFile += "server-P256-key.pem";
                altPrivateKeyFile += "server-mldsa44-key-pq.pem";
                break;
            case mldsa65p384:
                certFile += "server-P384-mldsa65-cert.pem";
                privateKeyFile += "server-P384-key.pem";
                altPrivateKeyFile += "server-mldsa65-key-pq.pem";
                break;
            case mldsa87p521:
                certFile += "server-P521-mldsa87-cert.pem";
                privateKeyFile += "server-P521-key.pem";
                altPrivateKeyFile += "server-mldsa87-key-pq.pem";
                break;
            case mldsa44rsa3072:
                certFile += "server-rsa3072-mldsa44-cert.pem";
                privateKeyFile += "server-rsa3072-key.pem";
                altPrivateKeyFile += "server-mldsa44-key-pq.pem";
                break;
        }

        ProcessBuilder processBuilder = new ProcessBuilder(wolfSSLWorkingDirectory + "examples/server/server", "-d", "-v", "4",
                "-c", certFile, "-k", privateKeyFile, "--altPrivKey", altPrivateKeyFile);
        processBuilder.directory(new java.io.File(wolfSSLWorkingDirectory));
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

    public static void runWolfSSLClient()
    {

        String caFile = pemDirectory;
        // Run WolfSSL Server
        switch (DEMO)
        {
            case mldsa44p256:
                caFile += "ca-P256-mldsa44-cert.pem";
                break;
            case mldsa65p384:
                caFile += "ca-P384-mldsa65-cert.pem";
                break;
            case mldsa87p521:
                caFile += "ca-P521-mldsa87-cert.pem";
                break;
            case mldsa44rsa3072:
                caFile += "ca-rsa3072-mldsa44-cert.pem";
                break;
        }

        ProcessBuilder processBuilder = new ProcessBuilder(wolfSSLWorkingDirectory + "examples/client/client",
                "-v", "4", "-A", caFile
        );
        processBuilder.directory(new java.io.File(wolfSSLWorkingDirectory));
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
            System.out.println("CAUGHT ERROR: ");
            e.printStackTrace();
        }
        catch (InterruptedException e)
        {
            System.out.println("CAUGHT ERROR: ");
            e.printStackTrace();
            Thread.currentThread().interrupt();
        }
    }

    public static void runBouncyCastleServer() throws IOException, InterruptedException
    {
        ServerSocket ss = new ServerSocket(11111);

        System.out.println("ServerSocket port: " + ss.getLocalPort());
        System.out.println("ServerSocket ip: " + ss.getInetAddress());

        sleep(1000); // Might need to adjust this for different setups
        try
        {
            Socket s = ss.accept();
            TlsServerProtocol tlsServerProtocol = new TlsServerProtocol();
            try
            {
                tlsServerProtocol = new TlsServerProtocol(s.getInputStream(), s.getOutputStream());
                MockX9146TlsServer bcServer = new MockX9146TlsServer();
                bcServer.setSupportedCksCode(CKS_TYPE);
                bcServer.setSelectedHybridTest(DEMO);

                tlsServerProtocol.accept(bcServer);
            }
            finally
            {
                tlsServerProtocol.close();
//                s.close();
            }
        }
        finally
        {
            ss.close();
        }
    }
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
}
