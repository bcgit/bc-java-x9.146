package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;

/**
 * Generator for Version 3 TBSCertificateStructures.
 * <pre>
 * TBSCertificate ::= SEQUENCE {
 *      version          [ 0 ]  Version DEFAULT v1(0),
 *      serialNumber            CertificateSerialNumber,
 *      signature               AlgorithmIdentifier,
 *      issuer                  Name,
 *      validity                Validity,
 *      subject                 Name,
 *      subjectPublicKeyInfo    SubjectPublicKeyInfo,
 *      issuerUniqueID    [ 1 ] IMPLICIT UniqueIdentifier OPTIONAL,
 *      subjectUniqueID   [ 2 ] IMPLICIT UniqueIdentifier OPTIONAL,
 *      extensions        [ 3 ] Extensions OPTIONAL
 *      }
 * </pre>
 *
 */
public class V3TBSCertificateGenerator
{
    DERTaggedObject         version = new DERTaggedObject(true, 0, new ASN1Integer(2));

    ASN1Integer              serialNumber;
    AlgorithmIdentifier     signature;
    X500Name                issuer;
    Time                    startDate, endDate;
    X500Name                subject;
    SubjectPublicKeyInfo    subjectPublicKeyInfo;
    Extensions              extensions;

    private boolean altNamePresentAndCritical;
    private DERBitString issuerUniqueID;
    private DERBitString subjectUniqueID;

    public V3TBSCertificateGenerator()
    {
    }

    public void setSerialNumber(
        ASN1Integer  serialNumber)
    {
        this.serialNumber = serialNumber;
    }

    public void setSignature(
        AlgorithmIdentifier    signature)
    {
        this.signature = signature;
    }

        /**
     * @deprecated use X500Name method
     */
    public void setIssuer(
        X509Name    issuer)
    {
        this.issuer = X500Name.getInstance(issuer);
    }

    public void setIssuer(
        X500Name issuer)
    {
        this.issuer = issuer;
    }
    
    public void setStartDate(
        ASN1UTCTime startDate)
    {
        this.startDate = new Time(startDate);
    }

    public void setStartDate(
        Time startDate)
    {
        this.startDate = startDate;
    }

    public void setEndDate(
        ASN1UTCTime endDate)
    {
        this.endDate = new Time(endDate);
    }

    public void setEndDate(
        Time endDate)
    {
        this.endDate = endDate;
    }

        /**
     * @deprecated use X500Name method
     */
    public void setSubject(
        X509Name    subject)
    {
        this.subject = X500Name.getInstance(subject.toASN1Primitive());
    }

    public void setSubject(
        X500Name subject)
    {
        this.subject = subject;
    }

    public void setIssuerUniqueID(
        DERBitString uniqueID)
    {
        this.issuerUniqueID = uniqueID;
    }

    public void setSubjectUniqueID(
        DERBitString uniqueID)
    {
        this.subjectUniqueID = uniqueID;
    }

    public void setSubjectPublicKeyInfo(
        SubjectPublicKeyInfo    pubKeyInfo)
    {
        this.subjectPublicKeyInfo = pubKeyInfo;
    }

    /**
     * @deprecated use method taking Extensions
     * @param extensions
     */
    public void setExtensions(
        X509Extensions    extensions)
    {
        setExtensions(Extensions.getInstance(extensions));
    }

    public void setExtensions(
        Extensions    extensions)
    {
        this.extensions = extensions;
        if (extensions != null)
        {
            Extension altName = extensions.getExtension(Extension.subjectAlternativeName);

            if (altName != null && altName.isCritical())
            {
                altNamePresentAndCritical = true;
            }
        }
    }

    public ASN1Sequence generatePreTBSCertificate()
    {
        if (signature != null)
        {
            throw new IllegalStateException("signature field should not be set in PreTBSCertificate");
        }
        if ((serialNumber == null)
            || (issuer == null) || (startDate == null) || (endDate == null)
            || (subject == null && !altNamePresentAndCritical) || (subjectPublicKeyInfo == null))
        {
            throw new IllegalStateException("not all mandatory fields set in V3 TBScertificate generator");
        }

        return generateTBSStructure();
    }

    private ASN1Sequence generateTBSStructure()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(10);

        v.add(version);
        try
        {
            System.out.println("version: " + Hex.toHexString(version.getEncoded()));
        } catch (Exception e) {}
        v.add(serialNumber);
        try
        {
            System.out.println("serialNumber: " + Hex.toHexString(serialNumber.getEncoded()));
        } catch (Exception e) {}

        if (signature != null)
        {
            v.add(signature);
            try
            {
                System.out.println("signature: " + Hex.toHexString(signature.getEncoded()));
            } catch (Exception e) {}
        }
        
        v.add(issuer);
        try
        {
            System.out.println("issuer: " + Hex.toHexString(issuer.getEncoded()));
        } catch (Exception e) {}

        //
        // before and after dates
        //
        {
            ASN1EncodableVector validity = new ASN1EncodableVector(2);
            validity.add(startDate);
            try
            {
                System.out.println("startDate: " + Hex.toHexString(startDate.getEncoded()));
            } catch (Exception e) {}
            validity.add(endDate);
            try
            {
                System.out.println("endDate: " + Hex.toHexString(endDate.getEncoded()));
            } catch (Exception e) {}

            v.add(new DERSequence(validity));
        }

        if (subject != null)
        {
            v.add(subject);
            try
            {
                System.out.println("subject: " + Hex.toHexString(subject.getEncoded()));
            } catch (Exception e) {}
        }
        else
        {
            v.add(new DERSequence());
        }

        v.add(subjectPublicKeyInfo);
        try
        {
            System.out.println("subjectPublicKeyInfo: " + Hex.toHexString(subjectPublicKeyInfo.getEncoded()));
        } catch (Exception e) {}

        if (issuerUniqueID != null)
        {
            v.add(new DERTaggedObject(false, 1, issuerUniqueID));

            try
            {
                System.out.println("issuerUniqueID: " + Hex.toHexString(issuerUniqueID.getEncoded()));
            } catch (Exception e) {}
        }

        if (subjectUniqueID != null)
        {
            v.add(new DERTaggedObject(false, 2, subjectUniqueID));

            try
            {
                System.out.println("subjectUniqueID: " + Hex.toHexString(subjectUniqueID.getEncoded()));
            } catch (Exception e) {}
        }

        if (extensions != null)
        {
            v.add(new DERTaggedObject(true, 3, extensions));

            try
            {
                System.out.println("extensions: " + Hex.toHexString(new DERTaggedObject(true, 3, extensions).getEncoded()));
            } catch (Exception e) {}
        }

        return new DERSequence(v);
    }

    public TBSCertificate generateTBSCertificate()
    {
        if ((serialNumber == null) || (signature == null)
            || (issuer == null) || (startDate == null) || (endDate == null)
            || (subject == null && !altNamePresentAndCritical) || (subjectPublicKeyInfo == null))
        {
            throw new IllegalStateException("not all mandatory fields set in V3 TBScertificate generator");
        }

        return TBSCertificate.getInstance(generateTBSStructure());
    }
}
