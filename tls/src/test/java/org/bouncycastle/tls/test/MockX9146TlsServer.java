package org.bouncycastle.tls.test;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.ChannelBinding;
import org.bouncycastle.tls.DefaultTlsServer;
import org.bouncycastle.tls.ProtocolName;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsCredentialedDecryptor;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
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

    // Change this to manipulate server cks choice
    byte[] SUPPORTED_CKSCODE = new byte[] {3, 2, 1, 0};
    boolean DEBUG = false;

    public void setSelectedHybridTest(HybridExample target)
    {
        selectedHybridTest = target;
    }
    public void setSelectedCipherSuites(int[] selectedCipherSuites)
    {
        this.selectedCipherSuites = selectedCipherSuites;
    }

    public void setSupportedCksCode(int cksCode)
    {
        SUPPORTED_CKSCODE = new byte[]{(byte)cksCode};
        if (cksCode == 0)
        {
            SUPPORTED_CKSCODE = null;
        }
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

        //NOT NEEDED FOR X9.146 POC
        return null;
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

        //TODO[X9.146] process the trusted cert resource via provided cks code
        short cksCode = context.getSecurityParameters().getCertificateKeySelectionCode();

        TlsCertificate[] certPath = TlsTestUtils.getTrustedCertPath(context.getCrypto(), chain[0],
            trustedCertResources, cksCode);

        if (null == certPath)
        {
            throw new TlsFatalAlert(AlertDescription.bad_certificate);
        }

        TlsUtils.checkPeerSigAlgs(context, certPath);
    }

    public void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

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

        // Don't add CKS extension if it is cks_default
        if (SUPPORTED_CKSCODE != null && TlsExtensionsUtils.hasCertificationKeySelections(clientExtensions))
        {
            TlsExtensionsUtils.addCertificationKeySelections(serverExtensions, SUPPORTED_CKSCODE);
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
