package com.krestfield.ezsign.msg;

import com.krestfield.ezsign.KEzSignException;

/**
 * Copyright Krestfield 2016
 */
public class KSignDataRespMsg extends KEzSignRespMsg
{
    final String MESSAGE_ID = "NGIS";
    final int SIG_INDEX = 0;

    private byte[] m_signature;
    private String m_b64Signature;

    public KSignDataRespMsg(String fullMessage) throws KEzSignException
    {
        super(fullMessage);

        // Error messages do not contain any extra data and the response code and error
        // message would have been dealt with by the parent class
        if (m_respDataItems == null || m_respDataItems.length == 0)
            return;
            //throw new KEzSignException("No signature was returned in the response data");

        try
        {
            if (m_respDataItems[SIG_INDEX] == null)
                throw new KEzSignException("The signature contained in the response was empty");

            m_b64Signature = m_respDataItems[SIG_INDEX];
            m_signature = KBase64.FromBase64String(m_respDataItems[SIG_INDEX]);
        }
        catch (Exception e)
        {
            throw new KEzSignException("There was an error converting the signature data: " + e.getMessage());
        }
    }

    public byte[] getSignature()
    {
        return m_signature;
    }

    public String getB64Signature()
    {
        return m_b64Signature;
    }
}
/********************************************* END OF FILE *****************************************************
 ***************************************************************************************************************/