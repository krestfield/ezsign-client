package com.krestfield.ezsign.msg;

import com.krestfield.ezsign.KEzSignException;

/**
 * KEzSignRespMsg
 *
 * Copyright (C) 2016 Krestfield Ltd - All Rights Reserved
 */
public class KEzSignRespMsg extends KEzSignMsg
{
    // These values must match the values in KEzSignRespMsg in EzSignServer
    public static final int RESP_OK = 0;
    public static final int RESP_GENERAL_EXCEPTION = 1;
    public static final int RESP_SIGNING_EXCEPTION = 2;
    public static final int RESP_VERIFICATION_EXCEPTION = 3;
    public static final int RESP_REVOCATION_EXCEPTION = 4;
    public static final int RESP_PATH_EXCEPTION = 5;
    public static final int RESP_ENCIPHER_EXCEPTION = 6;

    protected String m_returnedMsgId;
    protected int m_responseCode = 0;
    protected String m_errorMsg;
    protected String[] m_respDataItems;

    /**
     * Message Format:
     * Message ID (reversed) : Response Code : [Error Msg] : DataItem1 : DataItem2...
     *
     * @param fullMessage
     * @throws KEzSignException
     */
    public KEzSignRespMsg(String fullMessage) throws KEzSignException
    {
        if (fullMessage == null || fullMessage.length() == 0)
            throw new KEzSignException("Message received is empty or null");

        int componentIndex = 0;
        String[] components = fullMessage.split(KEzSignMsg.DELIMITER);

        if (components == null || components.length < 2)
            throw new KEzSignException("Response received from the server was not valid");

        // Message ID - should be 4 chars
        m_returnedMsgId = components[componentIndex];
        componentIndex++;

        // Response Code
        m_responseCode = Integer.parseInt(components[componentIndex]);
        componentIndex++;

        // If response code not 0, get error message
        if (m_responseCode != 0)
        {
            m_errorMsg = components[componentIndex];
            componentIndex++;
        }

        // Copy the remaining items into the data items array for the
        // sub classes to process
        m_respDataItems = new String[components.length - componentIndex];
        int newIndex = 0;
        while (componentIndex < components.length)
        {
            m_respDataItems[newIndex] = components[componentIndex];
            componentIndex++;
        }
    }

    public int getResponseCode()
    {
        return m_responseCode;
    }

    public String getErrorMessage()
    {
        return m_errorMsg;
    }
}
/********************************************* END OF FILE *****************************************************
 ***************************************************************************************************************/