package org.bouncycastle.tls.test;

import junit.framework.TestCase;
import org.bouncycastle.tls.CertificateKeySelection;
import org.bouncycastle.tls.CertificateKeySelectionType;
import org.bouncycastle.tls.KeySelection;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
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

    public void testAll()
        throws Exception
    {
        for (MockX9146TlsServer.HybridExample demo : DEMOS)
        {
            for (short cks : CKS_TYPES)
            {
                runClientServer(cks, demo,
                    new CertificateKeySelection(new Vector<KeySelection>()
                    {{
                        add(KeySelection.Default);
                        add(KeySelection.Chimera_Native);
                        add(KeySelection.Chimera_Alternative);
                        add(KeySelection.Chimera_Hybrid);
                    }}
                    )
                );
            }
        }
    }

    // Handshake timing benchmark - not named 'test*' so it is not picked up by the AllTests suite;
    // run manually when needed.
    public void manualTest10000()
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

    // X9.146 sec. 6.1/8.6/8.7: mutual authentication. The server requests client auth and advertises a
    // KeySelection list in the CertificateRequest; the client authenticates with a chimera credential and
    // signals its used CKS in the client Certificate. Both endpoints must agree on the client-auth CKS,
    // which for a chimera client whose native+alternate algorithms the server both accepts is cks_both(3)
    // (ExtendedCertificateVerify). Regression guard for the previously-hardcoded cks_default on the verify
    // path (a BC client signing with cks 1/2/3 would otherwise fail against a BC server).
    public void testMutualAuth()
        throws Exception
    {
        // Server offers both the chimera native (ECDSA) and alternate (ML-DSA) algorithms for client auth,
        // so the client's deterministic selection is cks_both(3) -> ExtendedCertificateVerify.
        runMutualAuth(null, CertificateKeySelectionType.cks_both);
    }

    public void testMutualAuthAlternate()
        throws Exception
    {
        // Server offers ONLY the alternate (ML-DSA) algorithm for client auth, so the chimera client
        // downgrades to cks_alternate(2) and signs a single CertificateVerify with the alternate key. This
        // is the regression guard for the verify13CertificateVerifyClient fix: verified against the client's
        // asserted CKS (2 -> alternate key), a hardcoded cks_default(0) would check the ML-DSA signature
        // against the ECDSA native key and fail.
        Vector altOnly = new Vector();
        altOnly.add(SignatureAndHashAlgorithm.DRAFT_mldsa44);
        runMutualAuth(altOnly, CertificateKeySelectionType.cks_alternate);
    }

    // X9.146 sec. 10 / RFC 8773: PSK hybrid (CKS 6). The client offers an external PSK plus the
    // tls_cert_with_extern_psk extension; the server selects the PSK AND authenticates with a certificate.
    // The negotiated server-auth CKS is cks_psk_with_certificate_validation(6): a plain CertificateVerify
    // with the certificate's primary key, with the external PSK bound via the key schedule.
    public void testPskHybrid()
        throws Exception
    {
        CertificateKeySelection pskCks = new CertificateKeySelection(new Vector<KeySelection>()
        {{
            add(KeySelection.Default);
            add(KeySelection.PSK_with_Certificate_Validation);
        }});

        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        ServerThread serverThread = new ServerThread(serverProtocol,
            MockX9146TlsServer.HybridExample.mldsa44p256, pskCks);
        serverThread.usePskHybrid = true;
        serverThread.start();

        MockX9146TlsClient client = new MockX9146TlsClient(null);
        client.setUsePskHybrid(true);
        client.setCKS(pskCks);

        clientProtocol.connect(client);

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

        if (serverThread.failure != null)
        {
            throw new RuntimeException("server handshake failed", serverThread.failure);
        }

        // The RFC 8773 extension must be negotiated on both endpoints...
        assertTrue("client did not negotiate cert+extern-PSK", client.isNegotiatedCertWithExternPSK());
        assertTrue("server did not negotiate cert+extern-PSK", serverThread.server.isNegotiatedCertWithExternPSK());

        // ...and the server-authentication CKS must be cks_psk_with_certificate_validation(6) on both ends.
        assertEquals("unexpected PSK-hybrid CKS (client)",
            CertificateKeySelectionType.cks_psk_with_certificate_validation, client.getNegotiatedCksCode());
        assertEquals("unexpected PSK-hybrid CKS (server)",
            CertificateKeySelectionType.cks_psk_with_certificate_validation,
            serverThread.server.getNegotiatedCksCode());
    }

    // X9.146 sec. 6.3 / 9 (RFC 9763): Related Certificates Pair (CKS 5). The server authenticates with two
    // independent end-entity certificates (Related first, Main second, the Main carrying the
    // RelatedCertificate extension binding the Related by digest) and an ExtendedCertificateVerify whose
    // primary signature is from the Related certificate's key and alternate from the Main's. The client
    // verifies the relation digest and both signatures. Both endpoints must negotiate cks 5.
    public void testRelatedPair()
        throws Exception
    {
        CertificateKeySelection relatedCks = new CertificateKeySelection(new Vector<KeySelection>()
        {{
            add(KeySelection.Default);
            add(KeySelection.Related_Certificates_Pair_Hybrid);
        }});

        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        ServerThread serverThread = new ServerThread(serverProtocol,
            MockX9146TlsServer.HybridExample.mldsa44p256, relatedCks);
        serverThread.useRelatedPair = true;
        serverThread.start();

        MockX9146TlsClient client = new MockX9146TlsClient(null);
        client.setUseRelatedPair(true);
        client.setCKS(relatedCks);

        clientProtocol.connect(client);

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

        if (serverThread.failure != null)
        {
            throw new RuntimeException("server handshake failed", serverThread.failure);
        }

        assertEquals("unexpected Related-pair CKS (client)",
            CertificateKeySelectionType.cks_related_certificates_pair_hybrid, client.getNegotiatedCksCode());
        assertEquals("unexpected Related-pair CKS (server)",
            CertificateKeySelectionType.cks_related_certificates_pair_hybrid,
            serverThread.server.getNegotiatedCksCode());
    }

    // X9.146 Fig. 3 downgrade: a Chimera server credential negotiates down from cks_both(3) when the client
    // supports only one of the two algorithms in its CertificateVerify signature_algorithms. Withholding the
    // ML-DSA (alternate) leaves only the native -> cks_native(1); withholding the ECDSA (native) leaves only
    // the alternate -> cks_alternate(2). signature_algorithms_cert stays full so the ECDSA-signed server
    // certificate chain still validates. These rows also exercise the WI-12 CKS-aware chain validation
    // (cks 1 skips the alternate-signature check; cks 2 skips the native).
    public void testServerAuthDowngradeToNative()
        throws Exception
    {
        runServerAuthDowngrade(SignatureScheme.DRAFT_mldsa44, CertificateKeySelectionType.cks_native);
    }

    public void testServerAuthDowngradeToAlternate()
        throws Exception
    {
        runServerAuthDowngrade(SignatureScheme.ecdsa_secp256r1_sha256, CertificateKeySelectionType.cks_alternate);
    }

    private void runServerAuthDowngrade(int omitCvScheme, short expectedCks)
        throws Exception
    {
        CertificateKeySelection allCks = new CertificateKeySelection(new Vector<KeySelection>()
        {{
            add(KeySelection.Default);
            add(KeySelection.Chimera_Native);
            add(KeySelection.Chimera_Alternative);
            add(KeySelection.Chimera_Hybrid);
        }});

        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        ServerThread serverThread = new ServerThread(serverProtocol,
            MockX9146TlsServer.HybridExample.mldsa44p256, allCks);
        serverThread.fixedDualAlgs = true;
        serverThread.start();

        MockX9146TlsClient client = new MockX9146TlsClient(null);
        client.setCKS(allCks);
        client.setOmitCvScheme(omitCvScheme);

        clientProtocol.connect(client);

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

        if (serverThread.failure != null)
        {
            throw new RuntimeException("server handshake failed", serverThread.failure);
        }

        assertEquals("downgrade CKS mismatch (client)", expectedCks, client.getNegotiatedCksCode());
        assertEquals("downgrade CKS mismatch (server)", expectedCks, serverThread.server.getNegotiatedCksCode());
    }

    private void runMutualAuth(Vector clientAuthSigAlgs, short expectedClientCks)
        throws Exception
    {
        CertificateKeySelection allCks = new CertificateKeySelection(new Vector<KeySelection>()
        {{
            add(KeySelection.Default);
            add(KeySelection.Chimera_Native);
            add(KeySelection.Chimera_Alternative);
            add(KeySelection.Chimera_Hybrid);
        }});

        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        ServerThread serverThread = new ServerThread(serverProtocol,
            MockX9146TlsServer.HybridExample.mldsa44p256, allCks);
        serverThread.clientAuthCKS = allCks;
        serverThread.clientAuthSigAlgs = clientAuthSigAlgs;
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
        }}));

        clientProtocol.connect(client);

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

        if (serverThread.failure != null)
        {
            throw new RuntimeException("server handshake failed", serverThread.failure);
        }

        // Server authentication CKS is cks_both(3) in both cases (client advertises + supports both algs).
        assertEquals("server-auth CKS mismatch", CertificateKeySelectionType.cks_both,
            client.getNegotiatedCksCode());
        assertEquals("server-auth CKS mismatch", CertificateKeySelectionType.cks_both,
            serverThread.server.getNegotiatedCksCode());

        // Client authentication CKS: both endpoints must agree on the expected value.
        short clientLegOnClient = client.getNegotiatedClientCksCode();
        short clientLegOnServer = serverThread.server.getNegotiatedClientCksCode();
        assertEquals("client and server disagree on client-auth CKS", clientLegOnServer, clientLegOnClient);
        assertEquals("unexpected client-auth CKS", expectedClientCks, clientLegOnClient);
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

        // Surface a server-side handshake failure (the thread otherwise swallows it) so fatal-alert
        // regressions are assertable rather than silently passing.
        if (serverThread.failure != null)
        {
            throw new RuntimeException("server handshake failed", serverThread.failure);
        }

        /*
         * X9.146: both endpoints must agree on the negotiated CKS value, and for these chimera
         * credentials with a client that advertises all KeySelection values and supports both the
         * native and alternate signature algorithms the deterministic selection (draft Figure 3) is
         * cks_both(3) -> ExtendedCertificateVerify. Asserting the value locks in the selection so a
         * regression in the CKS negotiation is caught rather than passing silently.
         */
        short clientCks = client.getNegotiatedCksCode();
        short serverCks = serverThread.server.getNegotiatedCksCode();
        assertEquals("client and server negotiated different CKS values", serverCks, clientCks);
        assertEquals("unexpected negotiated CKS", CertificateKeySelectionType.cks_both, clientCks);
    }

    static class ServerThread
        extends Thread
    {
        private final TlsServerProtocol serverProtocol;
        private final MockX9146TlsServer.HybridExample hybridExample;
        private final CertificateKeySelection CKS;
        // When non-null, the server requests client authentication advertising this KeySelection list.
        CertificateKeySelection clientAuthCKS;
        // Optional override of the signature algorithms the server offers for client authentication.
        Vector clientAuthSigAlgs;
        // When true, the server accepts an external PSK (RFC 8773 / X9.146 CKS 6 cert+PSK hybrid).
        boolean usePskHybrid;
        // When true, the server authenticates with a Related Certificates Pair credential (X9.146 CKS 5).
        boolean useRelatedPair;
        // When true, the server's chimera credential loads with fixed native/alternate schemes (downgrade tests).
        boolean fixedDualAlgs;
        volatile MockX9146TlsServer server;
        volatile Exception failure;

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
                this.server = server;
                server.setSelectedHybridTest(hybridExample);
                server.setCKS(CKS);
                if (usePskHybrid)
                {
                    server.setUsePskHybrid(true);
                }
                if (useRelatedPair)
                {
                    server.setUseRelatedPair(true);
                }
                if (fixedDualAlgs)
                {
                    server.setFixedDualAlgs(true);
                }
                if (clientAuthCKS != null)
                {
                    server.setRequestClientAuth(clientAuthCKS);
                    if (clientAuthSigAlgs != null)
                    {
                        server.setClientAuthSigAlgs(clientAuthSigAlgs);
                    }
                }
                serverProtocol.accept(server);
            }
            catch (Exception e)
            {
                // A genuine server-side handshake failure -- surface it (runClientServer rethrows).
                this.failure = e;
                return;
            }

            try
            {
                Streams.pipeAll(serverProtocol.getInputStream(), serverProtocol.getOutputStream());
                serverProtocol.close();
            }
            catch (Exception e)
            {
                // Post-handshake echo/teardown over the PipedStream harness races the client's close()
                // (e.g. "Pipe closed" when writing the close_notify); this is a benign teardown artifact,
                // not a handshake failure, and is ignored here as in the other TLS protocol tests.
            }
        }
    }
}
