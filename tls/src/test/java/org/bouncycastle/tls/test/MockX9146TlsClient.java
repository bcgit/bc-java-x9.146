package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.PrintStream;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.ChannelBinding;
import org.bouncycastle.tls.ClientCertificateType;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.MaxFragmentLength;
import org.bouncycastle.tls.ProtocolName;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.TlsSession;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

class MockX9146TlsClient
        extends DefaultTlsClient
{
    TlsSession session;

    short cksCode = 0;
    int[] selectedCipherSuites = null;

    boolean DEBUG = false;

    public void setSelectedCipherSuites(int[] selectedCipherSuites)
    {
        this.selectedCipherSuites = selectedCipherSuites;
    }

    public void setCksCode(short cksCode)
    {
        this.cksCode = cksCode;
    }

    protected int[] getSupportedCipherSuites()
    {
        return TlsUtils.getSupportedCipherSuites(getCrypto(), selectedCipherSuites);
    }

    MockX9146TlsClient(TlsSession session)
    {
        super(new BcTlsCrypto());
        this.session = session;
        selectedCipherSuites = super.getSupportedCipherSuites();
    }

    protected Vector getProtocolNames()
    {
        Vector protocolNames = new Vector();
        protocolNames.addElement(ProtocolName.HTTP_1_1);
        protocolNames.addElement(ProtocolName.HTTP_2_TLS);
        return protocolNames;
    }

    public TlsSession getSessionToResume()
    {
        return this.session;
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        if(DEBUG)
        {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS client raised alert: " + AlertLevel.getText(alertLevel)
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
            out.println("TLS client received alert: " + AlertLevel.getText(alertLevel)
                    + ", " + AlertDescription.getText(alertDescription));
        }
    }

    protected Vector getSupportedSignatureAlgorithms()
    {
        Vector defaultVector = TlsUtils.getDefaultSupportedSignatureAlgorithms(context);
        //TODO use addIfSupported?

        // ML-DSA
        defaultVector.add(SignatureAndHashAlgorithm.DRAFT_mldsa44);
        defaultVector.add(SignatureAndHashAlgorithm.DRAFT_mldsa65);
        defaultVector.add(SignatureAndHashAlgorithm.DRAFT_mldsa87);

        //OQS
        defaultVector.add(SignatureAndHashAlgorithm.OQS_CODEPOINT_P256_MLDSA44);
        defaultVector.add(SignatureAndHashAlgorithm.OQS_CODEPOINT_RSA3072_MLDSA44);
        defaultVector.add(SignatureAndHashAlgorithm.OQS_CODEPOINT_P384_MLDSA65);
        defaultVector.add(SignatureAndHashAlgorithm.OQS_CODEPOINT_P521_MLDSA87);

        //WOLFSSL
        defaultVector.add(SignatureAndHashAlgorithm.WOLFSSL_HYBRID_P256_MLDSA_LEVEL2);
        defaultVector.add(SignatureAndHashAlgorithm.WOLFSSL_HYBRID_RSA3072_MLDSA_LEVEL2);
        defaultVector.add(SignatureAndHashAlgorithm.WOLFSSL_HYBRID_P384_MLDSA_LEVEL3);
        defaultVector.add(SignatureAndHashAlgorithm.WOLFSSL_HYBRID_P521_MLDSA_LEVEL5);

        // Hybrid
        // ecdsa-dilithium
//        defaultVector.add(SignatureAndHashAlgorithm.hybrid_p256_id_ml_dsa_44);
//        defaultVector.add(SignatureAndHashAlgorithm.hybrid_p384_id_ml_dsa_65);
//        defaultVector.add(SignatureAndHashAlgorithm.hybrid_p521_id_ml_dsa_87);
        // rsa-dilithium
//        defaultVector.add(SignatureAndHashAlgorithm.hybrid_rsa3072_dilithiumr3_2);
        // ecdsa-falcon
//        defaultVector.add(SignatureAndHashAlgorithm.hybrid_p256_falcon_512);
//        defaultVector.add(SignatureAndHashAlgorithm.hybrid_p521_falcon_1024);
        // rsa-falcon
//        defaultVector.add(SignatureAndHashAlgorithm.hybrid_rsa3072_falcon_512);

        // FALCON
//        defaultVector.add(SignatureAndHashAlgorithm.falcon_512);
//        defaultVector.add(SignatureAndHashAlgorithm.falcon_1024);


        return defaultVector;
    }

    public Hashtable getClientExtensions() throws IOException
    {
        if (context.getSecurityParametersHandshake().getClientRandom() == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        Hashtable clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(super.getClientExtensions());
        {
            /*
             * NOTE: If you are copying test code, do not blindly set these extensions in your own client.
             */
            TlsExtensionsUtils.addMaxFragmentLengthExtension(clientExtensions, MaxFragmentLength.pow2_9);
            TlsExtensionsUtils.addPaddingExtension(clientExtensions, context.getCrypto().getSecureRandom().nextInt(16));
            TlsExtensionsUtils.addTruncatedHMacExtension(clientExtensions);
            //TODO: why does adding the CKS extension break the tls connection with wolfssl?
            if (cksCode != 0)
            {
                TlsExtensionsUtils.addCertificationKeySelection(clientExtensions, cksCode);
            }

        }
        return clientExtensions;
    }

    public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException
    {
        super.notifyServerVersion(serverVersion);
        if(DEBUG)
        {
            System.out.println("TLS client negotiated " + serverVersion);
        }
    }

    public TlsAuthentication getAuthentication() throws IOException
    {
        return new TlsAuthentication()
        {
            public void notifyServerCertificate(TlsServerCertificate serverCertificate) throws IOException
            {
                TlsCertificate[] chain = serverCertificate.getCertificate().getCertificateList();

//                System.out.println("TLS client received server certificate chain of length " + chain.length);
//                Certificate prev = Certificate.getInstance(chain[0].getEncoded()); // TODO: check if 0 is ca or ee
                for (int i = 0; i != chain.length; i++)
                {
//                    Certificate entry = Certificate.getInstance(chain[i].getEncoded());
//
//                    byte[] tbs = entry.getTBSCertificate().getEncoded();
//                    SignatureAndHashAlgorithm sigAndHashAlg = (SignatureAndHashAlgorithm)CERT_SIG_ALG_OIDS.get(sigAlgOID);
//
//
//
//                    System.out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " ("
//                            + entry.getSubject() + ")");
                }

                boolean isEmpty = serverCertificate == null || serverCertificate.getCertificate() == null
                        || serverCertificate.getCertificate().isEmpty();

                if (isEmpty)
                {
                    throw new TlsFatalAlert(AlertDescription.bad_certificate);
                }

                String[] trustedCertResources = new String[]{
                        "x9146/server-P256-mldsa44-cert.pem",
                        "x9146/server-P384-mldsa65-cert.pem",
                        "x9146/server-P521-mldsa87-cert.pem",
                        "x9146/server-rsa3072-mldsa44-cert.pem"
                };

                TlsCertificate[] certPath = TlsTestUtils.getTrustedCertPath(context.getCrypto(), chain[0],
                        trustedCertResources);

                if (null == certPath)
                {
                    throw new TlsFatalAlert(AlertDescription.bad_certificate);
                }

                TlsUtils.checkPeerSigAlgs(context, certPath);
            }

            public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException
            {
                short[] certificateTypes = certificateRequest.getCertificateTypes();
                if (certificateTypes == null || !Arrays.contains(certificateTypes, ClientCertificateType.rsa_sign))
                {
                    return null;
                }

                return TlsTestUtils.loadSignerCredentials(context, certificateRequest.getSupportedSignatureAlgorithms(),
                        SignatureAlgorithm.rsa, "x509-client-rsa.pem", "x509-client-key-rsa.pem");
            }
        };
    }

    public void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

        ProtocolName protocolName = context.getSecurityParametersConnection().getApplicationProtocol();
        if (protocolName != null && DEBUG)
        {
            System.out.println("Client ALPN: " + protocolName.getUtf8Decoding());
        }

        TlsSession newSession = context.getSession();
        if (newSession != null)
        {
            if (newSession.isResumable())
            {
                byte[] newSessionID = newSession.getSessionID();
                String hex = hex(newSessionID);

                if(DEBUG)
                {
                    if (this.session != null && Arrays.areEqual(this.session.getSessionID(), newSessionID))
                    {
                        System.out.println("Client resumed session: " + hex);
                    }
                    else
                    {
                        System.out.println("Client established session: " + hex);
                    }
                }

                this.session = newSession;
            }

            byte[] tlsServerEndPoint = context.exportChannelBinding(ChannelBinding.tls_server_end_point);
            if (null != tlsServerEndPoint && DEBUG)
            {
                System.out.println("Client 'tls-server-end-point': " + hex(tlsServerEndPoint));
            }

            byte[] tlsUnique = context.exportChannelBinding(ChannelBinding.tls_unique);
            if(DEBUG)
            {
                System.out.println("Client 'tls-unique': " + hex(tlsUnique));
            }

            byte[] tlsExporter = context.exportChannelBinding(ChannelBinding.tls_exporter);
            if(DEBUG)
            {
                System.out.println("Client 'tls-exporter': " + hex(tlsExporter));
            }
        }
    }

    public void processServerExtensions(Hashtable serverExtensions) throws IOException
    {
        if (context.getSecurityParametersHandshake().getServerRandom() == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        super.processServerExtensions(serverExtensions);
    }

    protected String hex(byte[] data)
    {
        return data == null ? "(null)" : Hex.toHexString(data);
    }
}
