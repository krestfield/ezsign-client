package com.krestfield.ezsign.msg;

import com.krestfield.ezsign.KEzSignException;

/**
 * Copyright Krestfield 2017
 */
public class KEncipherRespMsg extends KEzSignRespMsg
{
    public final static String MESSAGE_ID = "ICNE";
    final int DATA_INDEX = 0;

    private byte[] m_data;

    public KEncipherRespMsg(String fullMessage) throws KEzSignException
    {
        super(fullMessage);

        // Error messages do not contain any extra data and the response code and error
        // message would have been dealt with by the parent class
        if (m_respDataItems == null || m_respDataItems.length == 0)
            return;

        try
        {
            if (m_respDataItems[DATA_INDEX] == null)
                throw new KEzSignException("The data contained in the response was empty");

            m_data = KBase64.FromBase64String(m_respDataItems[DATA_INDEX]);
        }
        catch (Exception e)
        {
            throw new KEzSignException("There was an error converting the response data: " + e.getMessage());
        }
    }

    public byte[] getData()
    {
        return m_data;
    }
}
/********************************************* END OF FILE *****************************************************
 ***************************************************************************************************************/