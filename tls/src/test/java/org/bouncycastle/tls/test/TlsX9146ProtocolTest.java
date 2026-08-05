package org.bouncycastle.tls.test;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.CertificateKeySelection;
import org.bouncycastle.tls.CertificateKeySelectionType;
import org.bouncycastle.tls.KeySelection;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsFatalAlertReceived;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Vector;

public class TlsX9146ProtocolTest
    extends TestCase
{
    short[] CKS_TYPES = new short[]{
        CertificateKeySelectionType.cks_default,
        CertificateKeySelectionType.cks_chimera_native,
        CertificateKeySelectionType.cks_chimera_alternative,
        CertificateKeySelectionType.cks_chimera_hybrid
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
        runClientServer(CertificateKeySelectionType.cks_chimera_hybrid,
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
    // which for a chimera client whose native+alternate algorithms the server both accepts is cks_chimera_hybrid(3)
    // (ExtendedCertificateVerify). Regression guard for the previously-hardcoded cks_default on the verify
    // path (a BC client signing with cks 1/2/3 would otherwise fail against a BC server).
    public void testMutualAuth()
        throws Exception
    {
        // Server offers both the chimera native (ECDSA) and alternate (ML-DSA) algorithms for client auth,
        // so the client's deterministic selection is cks_chimera_hybrid(3) -> ExtendedCertificateVerify.
        runMutualAuth(null, CertificateKeySelectionType.cks_chimera_hybrid);
    }

    public void testMutualAuthAlternate()
        throws Exception
    {
        // Server offers ONLY the alternate (ML-DSA) algorithm for client auth, so the chimera client
        // downgrades to cks_chimera_alternative(2) and signs a single CertificateVerify with the alternate key. This
        // is the regression guard for the verify13CertificateVerifyClient fix: verified against the client's
        // asserted CKS (2 -> alternate key), a hardcoded cks_default(0) would check the ML-DSA signature
        // against the ECDSA native key and fail.
        Vector altOnly = new Vector();
        altOnly.add(SignatureAndHashAlgorithm.DRAFT_mldsa44);
        runMutualAuth(altOnly, CertificateKeySelectionType.cks_chimera_alternative);
    }

    // X9.146 sec. 6.1/11 / RFC 8773 (draft 2026-07-21): Chimera certificate + external PSK negotiates the
    // per-type PSK-hybrid value cks_addpsk_with_chimera_native(7) -- a plain CertificateVerify with the
    // chimera NATIVE key, with the external PSK bound via the key schedule (Figure 2: Chimera + PSK -> 7).
    public void testPskHybrid()
        throws Exception
    {
        CertificateKeySelection pskCks = new CertificateKeySelection(new Vector<KeySelection>()
        {{
            add(KeySelection.Default);
            add(KeySelection.AddPSK_with_Default);
            add(KeySelection.AddPSK_with_Chimera_Native);
            add(KeySelection.AddPSK_with_Chimera_Alternative);
        }});

        HandshakeResult result = runX9146Handshake(config(MockX9146TlsServer.HybridExample.mldsa44p256,
            pskCks, pskCks).withPskHybrid());

        // The RFC 8773 extension must be negotiated on both endpoints...
        assertTrue("client did not negotiate cert+extern-PSK", result.client.isNegotiatedCertWithExternPSK());
        assertTrue("server did not negotiate cert+extern-PSK", result.server.isNegotiatedCertWithExternPSK());

        // ...and the server-authentication CKS must be cks_addpsk_with_chimera_native(7) on both ends.
        assertEquals("unexpected PSK-hybrid CKS (client)",
            CertificateKeySelectionType.cks_addpsk_with_chimera_native, result.client.getNegotiatedCksCode());
        assertEquals("unexpected PSK-hybrid CKS (server)",
            CertificateKeySelectionType.cks_addpsk_with_chimera_native, result.server.getNegotiatedCksCode());
    }

    // X9.146 Fig 3 [19]-[30]: when the client does not advertise cks_addpsk_with_chimera_native(7), the
    // server rewrites to cks_addpsk_with_chimera_alternative(8) and signs the CertificateVerify with the
    // chimera ALTERNATE key, keeping the PSK as the second hybrid component (never downgrading to a
    // certificate-only mode).
    public void testPskHybridRewriteToAlternate()
        throws Exception
    {
        CertificateKeySelection clientCks = new CertificateKeySelection(new Vector<KeySelection>()
        {{
            add(KeySelection.Default);
            add(KeySelection.AddPSK_with_Default);
            add(KeySelection.AddPSK_with_Chimera_Alternative);
        }});
        CertificateKeySelection serverCks = new CertificateKeySelection(new Vector<KeySelection>()
        {{
            add(KeySelection.Default);
            add(KeySelection.AddPSK_with_Default);
            add(KeySelection.AddPSK_with_Chimera_Native);
            add(KeySelection.AddPSK_with_Chimera_Alternative);
        }});

        HandshakeResult result = runX9146Handshake(config(MockX9146TlsServer.HybridExample.mldsa44p256,
            serverCks, clientCks).withPskHybrid());

        assertTrue("client did not negotiate cert+extern-PSK", result.client.isNegotiatedCertWithExternPSK());
        assertEquals("expected rewrite to cks_addpsk_with_chimera_alternative (client)",
            CertificateKeySelectionType.cks_addpsk_with_chimera_alternative, result.client.getNegotiatedCksCode());
        assertEquals("expected rewrite to cks_addpsk_with_chimera_alternative (server)",
            CertificateKeySelectionType.cks_addpsk_with_chimera_alternative, result.server.getNegotiatedCksCode());
    }

    // X9.146 sec. 6.1/11: Standard certificate + external PSK is the only cks_addpsk_with_default(6) case
    // under the 2026-07-21 draft (Figure 2: Standard + PSK -> 6). The credential is the chimera certificate
    // used as a classic one (native signer only), which sec. 6.1 explicitly permits.
    public void testPskStandard()
        throws Exception
    {
        CertificateKeySelection pskCks = new CertificateKeySelection(new Vector<KeySelection>()
        {{
            add(KeySelection.Default);
            add(KeySelection.AddPSK_with_Default);
        }});

        HandshakeResult result = runX9146Handshake(config(MockX9146TlsServer.HybridExample.mldsa44p256,
            pskCks, pskCks).withPskHybrid().withStandardOnly());

        assertTrue("client did not negotiate cert+extern-PSK", result.client.isNegotiatedCertWithExternPSK());
        assertTrue("server did not negotiate cert+extern-PSK", result.server.isNegotiatedCertWithExternPSK());
        assertEquals("unexpected Standard+PSK CKS (client)",
            CertificateKeySelectionType.cks_addpsk_with_default, result.client.getNegotiatedCksCode());
        assertEquals("unexpected Standard+PSK CKS (server)",
            CertificateKeySelectionType.cks_addpsk_with_default, result.server.getNegotiatedCksCode());
    }

    // X9.146 selection table: Standard certificate without PSK negotiates cks_default(0), signalled
    // explicitly in the Certificate message when both endpoints advertised the extension.
    public void testStandardNoPsk()
        throws Exception
    {
        CertificateKeySelection cks = new CertificateKeySelection(new Vector<KeySelection>()
        {{
            add(KeySelection.Default);
            add(KeySelection.Chimera_Hybrid);
        }});

        HandshakeResult result = runX9146Handshake(config(MockX9146TlsServer.HybridExample.mldsa44p256,
            cks, cks).withStandardOnly());

        assertEquals("unexpected Standard CKS (client)",
            CertificateKeySelectionType.cks_default, result.client.getNegotiatedCksCode());
        assertEquals("unexpected Standard CKS (server)",
            CertificateKeySelectionType.cks_default, result.server.getNegotiatedCksCode());
    }

    // X9.146 Fig 2 [09]-[11] (draft 2026-07-21): PSK-hybrid enabled but the PSK is NOT successfully
    // negotiated (unknown identity) -- the endpoint retains the certificate-only CKS value (Chimera -> 3)
    // instead of the 0707 draft's fatal inappropriate_fallback.
    public void testPskHybridNotNegotiated()
        throws Exception
    {
        CertificateKeySelection cks = new CertificateKeySelection(new Vector<KeySelection>()
        {{
            add(KeySelection.Default);
            add(KeySelection.Chimera_Native);
            add(KeySelection.Chimera_Alternative);
            add(KeySelection.Chimera_Hybrid);
            add(KeySelection.AddPSK_with_Chimera_Native);
            add(KeySelection.AddPSK_with_Chimera_Alternative);
        }});

        HandshakeResult result = runX9146Handshake(config(MockX9146TlsServer.HybridExample.mldsa44p256,
            cks, cks).withPskHybrid().withBadPskIdentity());

        assertFalse("cert+extern-PSK unexpectedly negotiated (client)", result.client.isNegotiatedCertWithExternPSK());
        assertFalse("cert+extern-PSK unexpectedly negotiated (server)", result.server.isNegotiatedCertWithExternPSK());
        assertEquals("expected certificate-only CKS retained (client)",
            CertificateKeySelectionType.cks_chimera_hybrid, result.client.getNegotiatedCksCode());
        assertEquals("expected certificate-only CKS retained (server)",
            CertificateKeySelectionType.cks_chimera_hybrid, result.server.getNegotiatedCksCode());
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
            add(KeySelection.Related_Certs_Hybrid);
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
            CertificateKeySelectionType.cks_related_certs_hybrid, client.getNegotiatedCksCode());
        assertEquals("unexpected Related-pair CKS (server)",
            CertificateKeySelectionType.cks_related_certs_hybrid,
            serverThread.server.getNegotiatedCksCode());
    }

    // X9.146 Fig. 3 downgrade: a Chimera server credential negotiates down from cks_chimera_hybrid(3) when the client
    // supports only one of the two algorithms in its CertificateVerify signature_algorithms. Withholding the
    // ML-DSA (alternate) leaves only the native -> cks_chimera_native(1); withholding the ECDSA (native) leaves only
    // the alternate -> cks_chimera_alternative(2). signature_algorithms_cert stays full so the ECDSA-signed server
    // certificate chain still validates. These rows also exercise the WI-12 CKS-aware chain validation
    // (cks 1 skips the alternate-signature check; cks 2 skips the native).
    public void testServerAuthDowngradeToNative()
        throws Exception
    {
        runServerAuthDowngrade(SignatureScheme.DRAFT_mldsa44, CertificateKeySelectionType.cks_chimera_native);
    }

    public void testServerAuthDowngradeToAlternate()
        throws Exception
    {
        runServerAuthDowngrade(SignatureScheme.ecdsa_secp256r1_sha256, CertificateKeySelectionType.cks_chimera_alternative);
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
            add(KeySelection.Related_Certs_Hybrid);
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

        // Server authentication CKS is cks_chimera_hybrid(3) in both cases (client advertises + supports both algs).
        assertEquals("server-auth CKS mismatch", CertificateKeySelectionType.cks_chimera_hybrid,
            client.getNegotiatedCksCode());
        assertEquals("server-auth CKS mismatch", CertificateKeySelectionType.cks_chimera_hybrid,
            serverThread.server.getNegotiatedCksCode());

        // Client authentication CKS: both endpoints must agree on the expected value.
        short clientLegOnClient = client.getNegotiatedClientCksCode();
        short clientLegOnServer = serverThread.server.getNegotiatedClientCksCode();
        assertEquals("client and server disagree on client-auth CKS", clientLegOnServer, clientLegOnClient);
        assertEquals("unexpected client-auth CKS", expectedClientCks, clientLegOnClient);
    }

    // X9.146 sec. 9 / Fig 2: Related Certificates Pair + external PSK negotiates
    // cks_addpsk_with_related_main(10) -- a plain CertificateVerify signed by the MAIN certificate's key,
    // both chains still carried in the Certificate message (sec. 9.3), relation digest validated, PSK in
    // the key schedule.
    public void testRelatedPairPsk()
        throws Exception
    {
        HandshakeResult result = runX9146Handshake(config(MockX9146TlsServer.HybridExample.mldsa44p256,
            relatedPskCks(), relatedPskCks()).withRelatedPair().withPskHybrid());

        assertTrue("client did not negotiate cert+extern-PSK", result.client.isNegotiatedCertWithExternPSK());
        assertEquals("unexpected Related+PSK CKS (client)",
            CertificateKeySelectionType.cks_addpsk_with_related_main, result.client.getNegotiatedCksCode());
        assertEquals("unexpected Related+PSK CKS (server)",
            CertificateKeySelectionType.cks_addpsk_with_related_main, result.server.getNegotiatedCksCode());
    }

    // X9.146 Fig 3 [35]-[44]: when the peer cannot validate the Main certificate's algorithm (P-384
    // withheld from signature_algorithms), the server rewrites 10 -> cks_addpsk_with_related_related(11)
    // and the RELATED certificate's key signs the CertificateVerify instead.
    public void testRelatedPairPskRewriteToRelated()
        throws Exception
    {
        Config cfg = config(MockX9146TlsServer.HybridExample.mldsa44p256, relatedPskCks(), relatedPskCks())
            .withRelatedPair().withPskHybrid();
        cfg.omitCvScheme = SignatureScheme.ecdsa_secp384r1_sha384;

        HandshakeResult result = runX9146Handshake(cfg);

        assertTrue("client did not negotiate cert+extern-PSK", result.client.isNegotiatedCertWithExternPSK());
        assertEquals("expected rewrite to cks_addpsk_with_related_related (client)",
            CertificateKeySelectionType.cks_addpsk_with_related_related, result.client.getNegotiatedCksCode());
        assertEquals("expected rewrite to cks_addpsk_with_related_related (server)",
            CertificateKeySelectionType.cks_addpsk_with_related_related, result.server.getNegotiatedCksCode());
    }

    // X9.146 sec. 9.5 negative row: a Related pair whose RelatedCertificate digest does not match the
    // presented Related certificate is rejected by the relying party with fatal unrelated_certificates.
    public void testRelatedPairUnrelated()
        throws Exception
    {
        CertificateKeySelection cks = new CertificateKeySelection(new Vector<KeySelection>()
        {{
            add(KeySelection.Default);
            add(KeySelection.Related_Certs_Hybrid);
        }});

        short alert = runX9146ExpectClientFatal(config(MockX9146TlsServer.HybridExample.mldsa44p256,
            cks, cks).withRelatedPair().withCorruptRelation());

        assertEquals("expected unrelated_certificates", AlertDescription.unrelated_certificates, alert);
    }

    // X9.146 Fig 3 [62]-[69] (draft 2026-07-21): when the peer supports both chimera algorithms but did
    // NOT advertise cks_chimera_hybrid(3), the downgrade follows the PEER's advertised list order --
    // whichever of {2, 1} the peer listed first wins (sec. 6.1: the order indicates preference).
    public void testChimeraDowngradePeerPrefersNative()
        throws Exception
    {
        // Client advertises 1 before 2 (and no 3): Peer_Prioritized(2,1) selects 1.
        CertificateKeySelection clientCks = new CertificateKeySelection(new Vector<KeySelection>()
        {{
            add(KeySelection.Default);
            add(KeySelection.Chimera_Native);
            add(KeySelection.Chimera_Alternative);
        }});

        HandshakeResult result = runX9146Handshake(config(MockX9146TlsServer.HybridExample.mldsa44p256,
            fullChimeraCks(), clientCks).withFixedDualAlgs());

        assertEquals("expected peer-preferred downgrade to native (client)",
            CertificateKeySelectionType.cks_chimera_native, result.client.getNegotiatedCksCode());
        assertEquals("expected peer-preferred downgrade to native (server)",
            CertificateKeySelectionType.cks_chimera_native, result.server.getNegotiatedCksCode());
    }

    public void testChimeraDowngradePeerPrefersAlternate()
        throws Exception
    {
        // Client advertises 2 before 1 (and no 3): Peer_Prioritized(2,1) selects 2.
        CertificateKeySelection clientCks = new CertificateKeySelection(new Vector<KeySelection>()
        {{
            add(KeySelection.Default);
            add(KeySelection.Chimera_Alternative);
            add(KeySelection.Chimera_Native);
        }});

        HandshakeResult result = runX9146Handshake(config(MockX9146TlsServer.HybridExample.mldsa44p256,
            fullChimeraCks(), clientCks).withFixedDualAlgs());

        assertEquals("expected peer-preferred downgrade to alternate (client)",
            CertificateKeySelectionType.cks_chimera_alternative, result.client.getNegotiatedCksCode());
        assertEquals("expected peer-preferred downgrade to alternate (server)",
            CertificateKeySelectionType.cks_chimera_alternative, result.server.getNegotiatedCksCode());
    }

    // X9.146 Fig 3 [71]: both chimera algorithms usable but the peer advertised neither 3 nor a
    // single-algorithm fallback value -- fatal unsupported_cks_value.
    public void testChimeraNoUsableCksValue()
        throws Exception
    {
        CertificateKeySelection clientCks = new CertificateKeySelection(new Vector<KeySelection>()
        {{
            add(KeySelection.Default);
        }});

        short alert = runX9146ExpectClientFatal(config(MockX9146TlsServer.HybridExample.mldsa44p256,
            fullChimeraCks(), clientCks).withFixedDualAlgs());

        assertEquals("expected unsupported_cks_value", AlertDescription.unsupported_cks_value, alert);
    }

    // X9.146 Fig 2 [37]-[39]: a setup value outside {3, 7, 10} (here cks_default(0), Standard credential)
    // MUST be advertised by the peer -- a client list without 0 is a fatal unsupported_cks_value at setup.
    public void testStandardSetupGate()
        throws Exception
    {
        CertificateKeySelection clientCks = new CertificateKeySelection(new Vector<KeySelection>()
        {{
            add(KeySelection.Chimera_Native);
            add(KeySelection.Chimera_Alternative);
            add(KeySelection.Chimera_Hybrid);
        }});

        short alert = runX9146ExpectClientFatal(config(MockX9146TlsServer.HybridExample.mldsa44p256,
            fullChimeraCks(), clientCks).withStandardOnly());

        assertEquals("expected unsupported_cks_value", AlertDescription.unsupported_cks_value, alert);
    }

    // Backward compatibility (sec. 5 Introduction): a client that sends no CKS extension gets a classic
    // RFC 8446 handshake -- no alert, no CKS extension in the Certificate message (code stays 0).
    public void testNoCksExtensionClassic()
        throws Exception
    {
        HandshakeResult result = runX9146Handshake(config(MockX9146TlsServer.HybridExample.mldsa44p256,
            fullChimeraCks(), null));

        assertEquals("expected classic handshake (client)",
            CertificateKeySelectionType.cks_default, result.client.getNegotiatedCksCode());
        assertEquals("expected classic handshake (server)",
            CertificateKeySelectionType.cks_default, result.server.getNegotiatedCksCode());
    }

    // X9.146 sec. 10 / draft-reddy-tls-composite-mldsa: a server with a composite
    // (ML-DSA-44 + ECDSA-P256-SHA256) certificate negotiates cks_composite_hybrid(4) -- a single
    // CertificateVerify whose signature is the whole composite (both components), verified against the
    // composite SubjectPublicKeyInfo. Runs on JcaTlsCrypto: the composite sign/verify bridge is JCA-only.
    public void testComposite()
        throws Exception
    {
        CertificateKeySelection cks = new CertificateKeySelection(new Vector<KeySelection>()
        {{
            add(KeySelection.Default);
            add(KeySelection.Composite_Hybrid);
        }});

        HandshakeResult result = runX9146Handshake(config(MockX9146TlsServer.HybridExample.composite,
            cks, cks).withComposite());

        assertEquals("unexpected Composite CKS (client)",
            CertificateKeySelectionType.cks_composite_hybrid, result.client.getNegotiatedCksCode());
        assertEquals("unexpected Composite CKS (server)",
            CertificateKeySelectionType.cks_composite_hybrid, result.server.getNegotiatedCksCode());
    }

    // X9.146 Fig 2 [17]-[19]: Composite certificate + external PSK negotiates
    // cks_addpsk_with_composite(9) -- the composite CertificateVerify plus the PSK in the early secret,
    // the draft's three-way hybrid (PSK + both composite components).
    public void testCompositePsk()
        throws Exception
    {
        CertificateKeySelection cks = new CertificateKeySelection(new Vector<KeySelection>()
        {{
            add(KeySelection.Default);
            add(KeySelection.Composite_Hybrid);
            add(KeySelection.AddPSK_with_Default);
            add(KeySelection.AddPSK_with_Composite);
        }});

        HandshakeResult result = runX9146Handshake(config(MockX9146TlsServer.HybridExample.composite,
            cks, cks).withComposite().withPskHybrid());

        assertTrue("client did not negotiate cert+extern-PSK", result.client.isNegotiatedCertWithExternPSK());
        assertTrue("server did not negotiate cert+extern-PSK", result.server.isNegotiatedCertWithExternPSK());
        assertEquals("unexpected Composite+PSK CKS (client)",
            CertificateKeySelectionType.cks_addpsk_with_composite, result.client.getNegotiatedCksCode());
        assertEquals("unexpected Composite+PSK CKS (server)",
            CertificateKeySelectionType.cks_addpsk_with_composite, result.server.getNegotiatedCksCode());
    }

    // ---- X9.146 handshake harness ----

    private static CertificateKeySelection fullChimeraCks()
    {
        return new CertificateKeySelection(new Vector<KeySelection>()
        {{
            add(KeySelection.Default);
            add(KeySelection.Chimera_Native);
            add(KeySelection.Chimera_Alternative);
            add(KeySelection.Chimera_Hybrid);
        }});
    }

    private static CertificateKeySelection relatedPskCks()
    {
        return new CertificateKeySelection(new Vector<KeySelection>()
        {{
            add(KeySelection.Default);
            add(KeySelection.Related_Certs_Hybrid);
            add(KeySelection.AddPSK_with_Related_Main);
            add(KeySelection.AddPSK_with_Related_Related);
        }});
    }

    private static Config config(MockX9146TlsServer.HybridExample demo, CertificateKeySelection serverCks,
        CertificateKeySelection clientCks)
    {
        Config cfg = new Config();
        cfg.demo = demo;
        cfg.serverCks = serverCks;
        cfg.clientCks = clientCks;
        return cfg;
    }

    private static final class Config
    {
        MockX9146TlsServer.HybridExample demo;
        CertificateKeySelection serverCks;
        // null = the client sends no certificate_key_selection extension.
        CertificateKeySelection clientCks;
        boolean pskHybrid;
        boolean badPskIdentity;
        boolean relatedPair;
        boolean corruptRelation;
        boolean standardOnly;
        boolean fixedDualAlgs;
        // Composite server credential: runs both endpoints on JcaTlsCrypto (the composite sign/verify
        // bridge is JCA-only) and has the client advertise + trust the composite scheme/fixture.
        boolean composite;
        int omitCvScheme = -1;

        Config withPskHybrid()
        {
            this.pskHybrid = true;
            return this;
        }

        Config withComposite()
        {
            this.composite = true;
            return this;
        }

        Config withBadPskIdentity()
        {
            this.badPskIdentity = true;
            return this;
        }

        Config withRelatedPair()
        {
            this.relatedPair = true;
            return this;
        }

        Config withCorruptRelation()
        {
            this.corruptRelation = true;
            return this;
        }

        Config withStandardOnly()
        {
            this.standardOnly = true;
            return this;
        }

        Config withFixedDualAlgs()
        {
            this.fixedDualAlgs = true;
            return this;
        }
    }

    private static final class HandshakeResult
    {
        MockX9146TlsClient client;
        MockX9146TlsServer server;
    }

    private HandshakeResult runX9146Handshake(Config cfg)
        throws Exception
    {
        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        ServerThread serverThread = newServerThread(serverProtocol, cfg);
        serverThread.start();

        MockX9146TlsClient client = newClient(cfg);

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

        HandshakeResult result = new HandshakeResult();
        result.client = client;
        result.server = serverThread.server;
        return result;
    }

    /**
     * Run a handshake that must FAIL with a fatal alert observed on the client side -- either received
     * from the server ({@link TlsFatalAlertReceived}) or raised locally by the client's own validation
     * ({@link TlsFatalAlert}). Returns the alert description for the caller to assert on.
     */
    private short runX9146ExpectClientFatal(Config cfg)
        throws Exception
    {
        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        ServerThread serverThread = newServerThread(serverProtocol, cfg);
        serverThread.start();

        MockX9146TlsClient client = newClient(cfg);

        short alertDescription;
        try
        {
            clientProtocol.connect(client);
            fail("handshake unexpectedly completed");
            return -1;    // unreachable
        }
        catch (TlsFatalAlertReceived e)
        {
            alertDescription = e.getAlertDescription();
        }
        catch (TlsFatalAlert e)
        {
            alertDescription = e.getAlertDescription();
        }
        finally
        {
            serverThread.join();
        }
        return alertDescription;
    }

    private static ServerThread newServerThread(TlsServerProtocol serverProtocol, Config cfg)
    {
        ServerThread serverThread = new ServerThread(serverProtocol, cfg.demo, cfg.serverCks);
        serverThread.usePskHybrid = cfg.pskHybrid;
        serverThread.useRelatedPair = cfg.relatedPair;
        serverThread.corruptRelation = cfg.corruptRelation;
        serverThread.standardOnly = cfg.standardOnly;
        serverThread.fixedDualAlgs = cfg.fixedDualAlgs;
        if (cfg.composite)
        {
            serverThread.crypto = newJcaCrypto();
        }
        return serverThread;
    }

    private static MockX9146TlsClient newClient(Config cfg)
    {
        MockX9146TlsClient client = cfg.composite
            ? new MockX9146TlsClient(null, newJcaCrypto())
            : new MockX9146TlsClient(null);
        client.setCKS(cfg.clientCks);
        if (cfg.composite)
        {
            client.setUseComposite(true);
        }
        if (cfg.pskHybrid)
        {
            client.setUsePskHybrid(true);
        }
        if (cfg.badPskIdentity)
        {
            client.setBadPskIdentity(true);
        }
        if (cfg.relatedPair)
        {
            client.setUseRelatedPair(true);
        }
        if (cfg.omitCvScheme >= 0)
        {
            client.setOmitCvScheme(cfg.omitCvScheme);
        }
        return client;
    }

    private static TlsCrypto newJcaCrypto()
    {
        // BC's composite-signature SPI resolves its component algorithms by the "BC" provider name, so
        // the provider must be registered (not merely passed as an instance).
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        return new JcaTlsCryptoProvider().setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .create(new SecureRandom());
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
            add(KeySelection.Related_Certs_Hybrid);
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
         * cks_chimera_hybrid(3) -> ExtendedCertificateVerify. Asserting the value locks in the selection so a
         * regression in the CKS negotiation is caught rather than passing silently.
         */
        short clientCks = client.getNegotiatedCksCode();
        short serverCks = serverThread.server.getNegotiatedCksCode();
        assertEquals("client and server negotiated different CKS values", serverCks, clientCks);
        assertEquals("unexpected negotiated CKS", CertificateKeySelectionType.cks_chimera_hybrid, clientCks);
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
        // When true, the server accepts an external PSK (RFC 8773 / X9.146 addpsk cert+PSK hybrids).
        boolean usePskHybrid;
        // When true, the server authenticates with a Related Certificates Pair credential (X9.146 CKS 5/10/11).
        boolean useRelatedPair;
        // When true, the Related pair's RelatedCertificate digest is corrupted (sec. 9.5 negative row).
        boolean corruptRelation;
        // When true, the server's chimera credential loads with fixed native/alternate schemes (downgrade tests).
        boolean fixedDualAlgs;
        // When true, the server authenticates with a Standard (single-signer) credential (CKS 0 / 6 rows).
        boolean standardOnly;
        // Non-null: construct the server on this crypto instead of the default BcTlsCrypto (composite rows).
        TlsCrypto crypto;
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
                MockX9146TlsServer server =
                    (crypto != null) ? new MockX9146TlsServer(crypto) : new MockX9146TlsServer();
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
                if (corruptRelation)
                {
                    server.setCorruptRelation(true);
                }
                if (fixedDualAlgs)
                {
                    server.setFixedDualAlgs(true);
                }
                if (standardOnly)
                {
                    server.setStandardOnly(true);
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
