package com.krestfield.ezsign.msg;

import com.krestfield.ezsign.KEzSignException;

import java.security.cert.X509Certificate;

/**
 * KVerifySignatureReqMsg
 *
 * Copyright (C) 2016 Krestfield Ltd - All Rights Reserved
 */
public class KVerifySignatureReqMsg extends KEzSignReqMsg
{
    public final static String MESSAGE_ID = "VERI";

    public final static int SIG_TYPE_PKCS7 = 1;
    public final static int SIG_TYPE_RAW = 2;

    public final static String CERT_DELIM = "^";

    final int NUM_ITEMS = 8;
    final int SIGNATURE_INDEX = 0;
    final int CONTENT_INDEX = 1;
    final int IS_DIGEST_INDEX = 2;
    final int BYPASS_REVOCATION_INDEX = 3;
    final int BYPASS_PATHBUILD_INDEX = 4;
    final int SIG_TYPE_INDEX = 5;
    final int SIGNER_CERT_INDEX = 6;
    final int OTHER_CERTS_INDEX = 7;

    public KVerifySignatureReqMsg(String channel, byte[] signature, byte[] content, boolean isDigest, boolean bypassRevocationCheck, boolean bypassPathBuild) throws KEzSignException
    {
        this(channel, signature, content, isDigest, bypassRevocationCheck, bypassPathBuild, SIG_TYPE_PKCS7, null, null);
    }

    public KVerifySignatureReqMsg(String channel, byte[] signature, byte[] content, boolean isDigest) throws KEzSignException
    {
        this(channel, signature, content, isDigest, false, false, SIG_TYPE_PKCS7, null, null);
    }

    public KVerifySignatureReqMsg(String channel, byte[] signature, byte[] content, boolean isDigest, int signatureType,
                                  X509Certificate signerCert, X509Certificate[] otherCerts) throws KEzSignException
    {
        this(channel, signature, content, isDigest, false, false, signatureType, signerCert, otherCerts);
    }

    public KVerifySignatureReqMsg(String channel, byte[] signature, byte[] content, boolean isDigest,
                                  boolean bypassRevocationCheck, boolean bypassPathBuild, int signatureType,
                                  X509Certificate signerCert, X509Certificate[] otherCerts) throws KEzSignException
    {
        super(MESSAGE_ID, channel);

        initDataItems(NUM_ITEMS);

        if (signature == null || signature.length == 0)
            throw new KEzSignException("The signature to verify was null or empty.  Cannot verify signature");
        m_msgDataItems[SIGNATURE_INDEX] = KBase64.ToBase64String(signature);

        if (content == null || content.length == 0)
            throw new KEzSignException("The content data to verify was null or empty.  Cannot verify signature");
        m_msgDataItems[CONTENT_INDEX] = KBase64.ToBase64String(content);

        m_msgDataItems[IS_DIGEST_INDEX] = isDigest ? TRUE_STR : FALSE_STR;
        m_msgDataItems[BYPASS_REVOCATION_INDEX] = bypassRevocationCheck ? TRUE_STR : FALSE_STR;
        m_msgDataItems[BYPASS_PATHBUILD_INDEX] = bypassPathBuild ? TRUE_STR : FALSE_STR;
        m_msgDataItems[SIG_TYPE_INDEX] = Integer.toString(signatureType);
        if (signatureType == SIG_TYPE_RAW)
        {
            if (signerCert == null)
                throw new KEzSignException("The signer certificate was not " +
                        "provided.  The signer certificate is required in order to verify a raw signature");
            setSignerCert(signerCert);
            setOtherCerts(otherCerts);
        }
    }

    /**
     * Convert the certificate to base64 data
     *
     * @param signerCert
     */
    private void setSignerCert(X509Certificate signerCert) throws KEzSignException
    {
        if (signerCert == null)
        {
            m_msgDataItems[SIGNER_CERT_INDEX] = EMPTY_STR;
        }
        else
        {
            try
            {
                byte[] certData = signerCert.getEncoded();
                m_msgDataItems[SIGNER_CERT_INDEX] = KBase64.ToBase64String(certData);
            } catch (Exception e)
            {
                throw new KEzSignException("There was an error extracting the data from the signer certificate.  Check the certificate is valid");
            }
        }
    }

    /**
     * Convert the certificate array to delimited list of base64 data
     *
     * @param otherCerts
     */
    private void setOtherCerts(X509Certificate[] otherCerts) throws KEzSignException
    {
        if (otherCerts == null || otherCerts.length == 0)
        {
            m_msgDataItems[OTHER_CERTS_INDEX] = EMPTY_STR;
        }
        else
        {
            int i = 0;
            try
            {
                StringBuilder sb = new StringBuilder();
                for (i = 0; i < otherCerts.length; i++)
                {
                    if (i > 0)
                        sb.append(CERT_DELIM);

                    byte[] certData = otherCerts[i].getEncoded();
                    String b64Data = KBase64.ToBase64String(certData);
                    sb.append(b64Data);
                }
                m_msgDataItems[OTHER_CERTS_INDEX] = sb.toString();
            }
            catch (Exception e) {
                throw new KEzSignException("There was an error extracting the data from the other certificate provided at index " + i + ".  Check the certificate is valid");
            }
        }
    }

    public byte[] getSignature()
    {
        return KBase64.FromBase64String(m_msgDataItems[SIGNATURE_INDEX]);
    }

    public byte[] getContent()
    {
        return KBase64.FromBase64String(m_msgDataItems[CONTENT_INDEX]);
    }

    public boolean isDigest()
    {
        return m_msgDataItems[IS_DIGEST_INDEX].equalsIgnoreCase(TRUE_STR) ? true : false;
    }

    public boolean getByPassRevocationCheck()
    {
        return m_msgDataItems[BYPASS_REVOCATION_INDEX].equalsIgnoreCase(TRUE_STR) ? true : false;
    }

    public boolean getByPassPathBuild()
    {
        return m_msgDataItems[BYPASS_PATHBUILD_INDEX].equalsIgnoreCase(TRUE_STR) ? true : false;
    }

}
/********************************************* END OF FILE *****************************************************
 ***************************************************************************************************************/