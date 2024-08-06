package org.bouncycastle.tls.test;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.CertificateKeySelectionType;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.ChannelBinding;
import org.bouncycastle.tls.ClientCertificateType;
import org.bouncycastle.tls.DefaultTlsServer;
import org.bouncycastle.tls.ProtocolName;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAlgorithm;
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
    MockX9146TlsServer()
    {
        super(new BcTlsCrypto());
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

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
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

    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("TLS server received alert: " + AlertLevel.getText(alertLevel)
            + ", " + AlertDescription.getText(alertDescription));
    }

    public ProtocolVersion getServerVersion() throws IOException
    {
        ProtocolVersion serverVersion = super.getServerVersion();

        System.out.println("TLS server negotiated " + serverVersion);

        return serverVersion;
    }

    public CertificateRequest getCertificateRequest() throws IOException
    {

        //NOT NEEDED FOR X9.146 POC

        return null;

//        Vector serverSigAlgs = null;
//        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(context.getServerVersion()))
//        {
//            serverSigAlgs = TlsUtils.getDefaultSupportedSignatureAlgorithms(context);
//        }
//
//        Vector certificateAuthorities = new Vector();
//      certificateAuthorities.addElement(TlsTestUtils.loadBcCertificateResource("x9146/ca-P256-mldsa44-cert.pem").getSubject());
////      certificateAuthorities.addElement(TlsTestUtils.loadBcCertificateResource("x509-ca-dsa.pem").getSubject());
////      certificateAuthorities.addElement(TlsTestUtils.loadBcCertificateResource("x509-ca-ecdsa.pem").getSubject());
////      certificateAuthorities.addElement(TlsTestUtils.loadBcCertificateResource("x509-ca-rsa.pem").getSubject());
//
//        // All the CA certificates are currently configured with this subject
//        certificateAuthorities.addElement(new X500Name("CN=BouncyCastle TLS Test CA"));
//
//        if (TlsUtils.isTLSv13(context))
//        {
//            // TODO[tls13] Support for non-empty request context
//            byte[] certificateRequestContext = TlsUtils.EMPTY_BYTES;
//
//            // TODO[tls13] Add TlsTestConfig.serverCertReqSigAlgsCert
//            Vector serverSigAlgsCert = null;
//
//            return new CertificateRequest(certificateRequestContext, serverSigAlgs, serverSigAlgsCert,
//                certificateAuthorities);
//        }
//        else
//        {
//            short[] certificateTypes = new short[]{ ClientCertificateType.rsa_sign,
//                ClientCertificateType.dss_sign, ClientCertificateType.ecdsa_sign };
//
//            return new CertificateRequest(certificateTypes, serverSigAlgs, certificateAuthorities);
//        }
    }

    public void notifyClientCertificate(org.bouncycastle.tls.Certificate clientCertificate) throws IOException
    {
        TlsCertificate[] chain = clientCertificate.getCertificateList();

        System.out.println("TLS server received client certificate chain of length " + chain.length);
        for (int i = 0; i != chain.length; i++)
        {
            Certificate entry = Certificate.getInstance(chain[i].getEncoded());
            // TODO Create fingerprint based on certificate signature algorithm digest
            System.out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " ("
                + entry.getSubject() + ")");
        }

        boolean isEmpty = (clientCertificate == null || clientCertificate.isEmpty());

        if (isEmpty)
        {
            return;
        }

        String[] trustedCertResources = new String[]{
                "x9146/ca-P256-mldsa44-cert.pem",
//                "x9146/ca-P256-falcon1-cert.pem"
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
        if (protocolName != null)
        {
            System.out.println("Server ALPN: " + protocolName.getUtf8Decoding());
        }

        byte[] tlsServerEndPoint = context.exportChannelBinding(ChannelBinding.tls_server_end_point);
        System.out.println("Server 'tls-server-end-point': " + hex(tlsServerEndPoint));

        byte[] tlsUnique = context.exportChannelBinding(ChannelBinding.tls_unique);
        System.out.println("Server 'tls-unique': " + hex(tlsUnique));

        byte[] tlsExporter = context.exportChannelBinding(ChannelBinding.tls_exporter);
        System.out.println("Server 'tls-exporter': " + hex(tlsExporter));
    }

    public void processClientExtensions(Hashtable clientExtensions) throws IOException
    {
        if (context.getSecurityParametersHandshake().getClientRandom() == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        //DO I NEED TO DO THIS
        TlsExtensionsUtils.addCertificationKeySelections(clientExtensions, new byte[]{2});


        //TODO: Do we need to check for CKS Code Extension ?? (create hasCertificateKeySelection)
        super.processClientExtensions(clientExtensions);
    }

    public Hashtable getServerExtensions() throws IOException
    {
        if (context.getSecurityParametersHandshake().getServerRandom() == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        //TODO[x9.146]: Change TlsExtensionsUtils.getCertficationKeySelection to return a vector of shorts instead of just one ckscode

//        TlsExtensionsUtils.addCertificationKeySelection(serverExtensions, TlsExtensionsUtils.getCertificationKeySelection(clientExtensions));
        TlsExtensionsUtils.addCertificationKeySelections(serverExtensions, new byte[]{2});

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


        return TlsTestUtils.loadDualSignerCredentials(context, clientSigAlgs,
                SignatureAlgorithm.ecdsa, SignatureAlgorithm.dilithiumr3_2,
                "x9146/server-P256-mldsa44-cert.pem",
                "x9146/server-P256-key.pem", "x9146/server-mldsa44-key-pq.pem");
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
