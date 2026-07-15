package org.bouncycastle.tls.test;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.BasicTlsPSKExternal;
import org.bouncycastle.tls.PRFAlgorithm;
import org.bouncycastle.tls.PskIdentity;
import org.bouncycastle.tls.TlsPSKExternal;
import org.bouncycastle.tls.CertificateKeySelection;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.KeySelection;
import org.bouncycastle.tls.ChannelBinding;
import org.bouncycastle.tls.DefaultTlsServer;
import org.bouncycastle.tls.ProtocolName;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsCredentialedDecryptor;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.io.PrintStream;
import java.util.Hashtable;
import java.util.Vector;


class MockX9146TlsServer
    extends DefaultTlsServer
{
    public enum HybridExample
    {
        mldsa44p256,
        mldsa65p384,
        mldsa87p521,
        mldsa44rsa3072,
        noPQC

    }
    HybridExample selectedHybridTest = HybridExample.mldsa44p256;
    int[] selectedCipherSuites = null;

    CertificateKeySelection CKS = null;
    boolean DEBUG = true;

    // X9.146: the CKS value actually negotiated for server authentication, captured at handshake completion.
    short negotiatedCksCode = -1;
    // X9.146: the CKS value the client used for client authentication (mutual auth), captured likewise.
    short negotiatedClientCksCode = -1;
    // X9.146 CKS 6 / RFC 8773: accept an external PSK to combine with certificate authentication.
    boolean usePskHybrid = false;
    boolean negotiatedCertWithExternPSK = false;
    // X9.146 CKS 5: authenticate with a Related Certificates Pair credential.
    boolean useRelatedPair = false;
    // X9.146 downgrade tests: load the mldsa44p256 chimera credential with FIXED native/alternate schemes
    // (independent of the client's advertised signature_algorithms) so the client can withhold one algorithm
    // and drive a server-auth CKS downgrade (3 -> 1 / 3 -> 2).
    boolean fixedDualAlgs = false;

    public void setUseRelatedPair(boolean useRelatedPair)
    {
        this.useRelatedPair = useRelatedPair;
    }

    public void setFixedDualAlgs(boolean fixedDualAlgs)
    {
        this.fixedDualAlgs = fixedDualAlgs;
    }

    public void setUsePskHybrid(boolean usePskHybrid)
    {
        this.usePskHybrid = usePskHybrid;
    }

    public boolean isNegotiatedCertWithExternPSK()
    {
        return negotiatedCertWithExternPSK;
    }

    public TlsPSKExternal getExternalPSK(Vector identities) throws IOException
    {
        if (!usePskHybrid)
        {
            return null;
        }

        byte[] identity = org.bouncycastle.util.Strings.toUTF8ByteArray("x9146-client");
        PskIdentity matchIdentity = new PskIdentity(identity, 0L);
        for (int i = 0, count = identities.size(); i < count; ++i)
        {
            if (matchIdentity.equals(identities.elementAt(i)))
            {
                org.bouncycastle.tls.crypto.TlsSecret key = getCrypto().createSecret(new byte[32]);
                return new BasicTlsPSKExternal(identity, key, PRFAlgorithm.tls13_hkdf_sha256);
            }
        }
        return null;
    }
    // When true, request client authentication and advertise a KeySelection list in the CertificateRequest.
    boolean requestClientAuth = false;
    CertificateKeySelection clientAuthCKS = null;
    // Optional override of the signature algorithms offered for client authentication (null = default set
    // including both the chimera native and alternate schemes). Set to a single-scheme list to drive a
    // client-auth CKS downgrade in tests.
    Vector clientAuthSigAlgs = null;

    public short getNegotiatedCksCode()
    {
        return negotiatedCksCode;
    }

    public short getNegotiatedClientCksCode()
    {
        return negotiatedClientCksCode;
    }

    public void setRequestClientAuth(CertificateKeySelection clientAuthCKS)
    {
        this.requestClientAuth = true;
        this.clientAuthCKS = clientAuthCKS;
    }

    public void setClientAuthSigAlgs(Vector clientAuthSigAlgs)
    {
        this.clientAuthSigAlgs = clientAuthSigAlgs;
    }

    public void setSelectedHybridTest(HybridExample target)
    {
        selectedHybridTest = target;
    }
    public void setSelectedCipherSuites(int[] selectedCipherSuites)
    {
        this.selectedCipherSuites = selectedCipherSuites;
    }

    public void setCKS(CertificateKeySelection CKS)
    {
        this.CKS = CKS;
    }

    MockX9146TlsServer()
    {
        super(new BcTlsCrypto());
        selectedCipherSuites = super.getSupportedCipherSuites();
    }

    protected Vector getProtocolNames()
    {
        Vector protocolNames = new Vector();
        protocolNames.addElement(ProtocolName.HTTP_2_TLS);
        protocolNames.addElement(ProtocolName.HTTP_1_1);
        return protocolNames;
    }

    public TlsCredentials getCredentials() throws IOException
    {
        /*
         * TODO[tls13] Should really be finding the first client-supported signature scheme that the
         * server also supports and has credentials for.
         */
        if (TlsUtils.isTLSv13(context))
        {
            if (useRelatedPair)
            {
                try
                {
                    return X9146RelatedPairUtil.createRelatedPairCredentials(context);
                }
                catch (Exception e)
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error, e);
                }
            }
            return getPQSignerCredentials();
        }

        return super.getCredentials();
    }

    protected int[] getSupportedCipherSuites()
    {
        return TlsUtils.getSupportedCipherSuites(getCrypto(), selectedCipherSuites);
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        if(DEBUG)
        {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS server raised alert: " + AlertLevel.getText(alertLevel)
                    + ", " + AlertDescription.getText(alertDescription));
            if (message != null)
            {
                out.println("> " + message);
            }
            if (cause != null)
            {
                cause.printStackTrace(out);
            }
        }
    }

    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
        if(DEBUG)
        {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS server received alert: " + AlertLevel.getText(alertLevel)
                    + ", " + AlertDescription.getText(alertDescription));
        }
    }

    public ProtocolVersion getServerVersion() throws IOException
    {
        ProtocolVersion serverVersion = super.getServerVersion();
        if(DEBUG)
        {
            System.out.println("TLS server negotiated " + serverVersion);
        }
        return serverVersion;
    }

    public CertificateRequest getCertificateRequest() throws IOException
    {
        if (!requestClientAuth)
        {
            return null;
        }

        // X9.146: request client authentication and advertise the server's supported KeySelection list.
        // The accepted signature algorithms include the chimera native (ECDSA) and alternate (ML-DSA)
        // schemes so a chimera client credential can negotiate cks_both.
        // The full set (chimera native ECDSA + alternate ML-DSA). Used for signature_algorithms_cert so the
        // ECDSA-signed client certificate chain always validates, independent of which algorithms are offered
        // for the client's CertificateVerify.
        Vector fullSigAlgs = TlsUtils.getDefaultSupportedSignatureAlgorithms(context);
        fullSigAlgs.add(SignatureAndHashAlgorithm.DRAFT_mldsa44);
        fullSigAlgs.add(SignatureAndHashAlgorithm.DRAFT_mldsa65);
        fullSigAlgs.add(SignatureAndHashAlgorithm.DRAFT_mldsa87);

        // signature_algorithms drives the client's CertificateVerify (and hence the CKS selection); a test
        // can restrict it (e.g. to ML-DSA only) to force a client-auth CKS downgrade.
        Vector serverSigAlgs = (clientAuthSigAlgs != null) ? clientAuthSigAlgs : fullSigAlgs;

        int[] cksList = null;
        if (clientAuthCKS != null)
        {
            Vector<KeySelection> ids = clientAuthCKS.getSignatureIdentifier();
            cksList = new int[ids.size()];
            for (int i = 0; i < ids.size(); i++)
            {
                cksList[i] = ids.elementAt(i).getValue();
            }
        }

        return new CertificateRequest(TlsUtils.EMPTY_BYTES, serverSigAlgs, fullSigAlgs, null, cksList);
    }

    public void notifyClientCertificate(org.bouncycastle.tls.Certificate clientCertificate) throws IOException
    {
        TlsCertificate[] chain = clientCertificate.getCertificateList();
        if(DEBUG)
        {
            System.out.println("TLS server received client certificate chain of length " + chain.length);
        }
        for (int i = 0; i != chain.length; i++)
        {
            Certificate entry = Certificate.getInstance(chain[i].getEncoded());
            // TODO Create fingerprint based on certificate signature algorithm digest
            if(DEBUG)
            {
                System.out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " ("
                        + entry.getSubject() + ")");
            }
        }

        boolean isEmpty = (clientCertificate == null || clientCertificate.isEmpty());

        if (isEmpty)
        {
            return;
        }

        String[] trustedCertResources = new String[]{
                "x509-client-dsa.pem",
                "x509-client-ecdh.pem",
                "x509-client-ecdsa.pem",
                "x509-client-ed25519.pem",
                "x509-client-ed448.pem",
                "x509-client-rsa_pss_256.pem",
                "x509-client-rsa_pss_384.pem",
                "x509-client-rsa_pss_512.pem",
                "x509-client-rsa.pem",

                "x9146/ca-P256-mldsa44-cert.pem",
                "x9146/ca-P384-mldsa65-cert.pem",
                "x9146/ca-P512-mldsa87-cert.pem",
                "x9146/ca-rsa3072-mldsa44-cert.pem"
        };

        //TODO[X9.146] Process the trusted cert resource via provided cks code
        CertificateKeySelection cks = context.getSecurityParameters().getCertificateKeySelection();

        TlsCertificate[] certPath = TlsTestUtils.getTrustedCertPath(context.getCrypto(), chain[0],
            trustedCertResources, cks);

        if (null == certPath)
        {
            throw new TlsFatalAlert(AlertDescription.bad_certificate);
        }

        TlsUtils.checkPeerSigAlgs(context, certPath);
    }

    public void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

        this.negotiatedCksCode = context.getSecurityParametersConnection().getCertificateKeySelectionCode();
        this.negotiatedClientCksCode = context.getSecurityParametersConnection().getClientCertificateKeySelectionCode();
        this.negotiatedCertWithExternPSK = context.getSecurityParametersConnection().isCertWithExternPSK();

        ProtocolName protocolName = context.getSecurityParametersConnection().getApplicationProtocol();
        if (protocolName != null && DEBUG)
        {
            System.out.println("Server ALPN: " + protocolName.getUtf8Decoding());
        }

        byte[] tlsServerEndPoint = context.exportChannelBinding(ChannelBinding.tls_server_end_point);
        if(DEBUG)
        {
            System.out.println("Server 'tls-server-end-point': " + hex(tlsServerEndPoint));
        }
        byte[] tlsUnique = context.exportChannelBinding(ChannelBinding.tls_unique);
        if(DEBUG)
        {
            System.out.println("Server 'tls-unique': " + hex(tlsUnique));
        }
        byte[] tlsExporter = context.exportChannelBinding(ChannelBinding.tls_exporter);
        if(DEBUG)
        {
            System.out.println("Server 'tls-exporter': " + hex(tlsExporter));
        }
    }

    public void processClientExtensions(Hashtable clientExtensions) throws IOException
    {
        if (context.getSecurityParametersHandshake().getClientRandom() == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

//        TlsExtensionsUtils.addCertificationKeySelections(clientExtensions, SUPPORTED_CKSCODE);
//        TlsExtensionsUtils.addCertificationKeySelection(clientExtensions, SUPPORTED_CKSCODE[0]);

        //TODO: Do we need to check for CKS Code Extension ?? (create hasCertificateKeySelection)
        super.processClientExtensions(clientExtensions);
    }

    public Hashtable getServerExtensions() throws IOException
    {
        if (context.getSecurityParametersHandshake().getServerRandom() == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (CKS != null)
        {
            Vector cksValues = new Vector();
            for (int i = 0; i < CKS.getSignatureIdentifier().size(); i++)
            {
                cksValues.add(Integers.valueOf(((KeySelection)CKS.getSignatureIdentifier().elementAt(i)).getValue()));
            }
            TlsExtensionsUtils.addCertificateKeySelectionList(serverExtensions, cksValues);
        }

        return super.getServerExtensions();
    }

    public void getServerExtensionsForConnection(Hashtable serverExtensions) throws IOException
    {
        if (context.getSecurityParametersHandshake().getServerRandom() == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        super.getServerExtensionsForConnection(serverExtensions);
    }

    protected TlsCredentialedDecryptor getRSAEncryptionCredentials() throws IOException
    {
        return TlsTestUtils.loadEncryptionCredentials(context, new String[]{ "x509-server-rsa-enc.pem", "x509-ca-rsa.pem" },
            "x509-server-key-rsa-enc.pem");
    }

    protected TlsCredentialedSigner  getPQSignerCredentials() throws IOException
    {
        //TODO: do I need to also load the server ALT key?
        // make a load dual credential function?

        Vector clientSigAlgs = context.getSecurityParametersHandshake().getClientSigAlgs();

        switch (selectedHybridTest)
        {
        case mldsa44p256:
            if (fixedDualAlgs)
            {
                return TlsTestUtils.loadDualSignerCredentials(context,
                new String[]{ "x9146/server-P256-mldsa44-cert.pem" },
                "x9146/server-P256-key.pem", "x9146/server-mldsa44-key-pq.pem",
                SignatureScheme.getSignatureAndHashAlgorithm(SignatureScheme.ecdsa_secp256r1_sha256),
                SignatureAndHashAlgorithm.DRAFT_mldsa44);
            }
            return TlsTestUtils.loadDualSignerCredentials(context, clientSigAlgs,
            SignatureAlgorithm.ecdsa, (short)SignatureScheme.DRAFT_mldsa44,
            "x9146/server-P256-mldsa44-cert.pem",
            "x9146/server-P256-key.pem", "x9146/server-mldsa44-key-pq.pem");
        case mldsa65p384:
            return TlsTestUtils.loadDualSignerCredentials(context, clientSigAlgs,
            SignatureAlgorithm.ecdsa, (short)SignatureScheme.DRAFT_mldsa65,
            "x9146/server-P384-mldsa65-cert.pem",
            "x9146/server-P384-key.pem", "x9146/server-mldsa65-key-pq.pem");
        case mldsa87p521:
            return TlsTestUtils.loadDualSignerCredentials(context, clientSigAlgs,
            SignatureAlgorithm.ecdsa, (short)SignatureScheme.DRAFT_mldsa87,
            "x9146/server-P521-mldsa87-cert.pem",
            "x9146/server-P521-key.pem", "x9146/server-mldsa87-key-pq.pem");
        case mldsa44rsa3072:
            return TlsTestUtils.loadDualSignerCredentials(context, clientSigAlgs,
            SignatureAlgorithm.rsa_pss_rsae_sha256, (short)SignatureScheme.DRAFT_mldsa44,
            "x9146/server-rsa3072-mldsa44-cert.pem",
            "x9146/server-rsa3072-key.pem", "x9146/server-mldsa44-key-pq.pem");
        case noPQC:
            return getRSASignerCredentials();
        default:
            throw new IOException("server cert/key not set correctly");
        }
    }
    protected TlsCredentialedSigner getRSASignerCredentials() throws IOException
    {
        Vector clientSigAlgs = context.getSecurityParametersHandshake().getClientSigAlgs();
        return TlsTestUtils.loadSignerCredentialsServer(context, clientSigAlgs, SignatureAlgorithm.rsa);
    }

    protected String hex(byte[] data)
    {
        return data == null ? "(null)" : Hex.toHexString(data);
    }
}
