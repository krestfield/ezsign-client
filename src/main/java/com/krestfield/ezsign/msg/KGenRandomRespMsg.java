package com.krestfield.ezsign.msg;

import com.krestfield.ezsign.KEzSignException;

/**
 * KGenRandomRespMsg
 *
 * Copyright Krestfield 2016
 */
public class KGenRandomRespMsg extends KEzSignRespMsg
{
    public final static String MESSAGE_ID = "DNAR"; // RAND
    final int RAND_BYTES_INDEX = 0;

    private byte[] m_randomBytes;

    /**
     * Constructor
     *
     * @param fullMessage
     * @throws KEzSignException
     */
    public KGenRandomRespMsg(String fullMessage) throws KEzSignException
    {
        super(fullMessage);

        if (m_respDataItems == null || m_respDataItems.length == 0)
            return;
            //throw new KEzSignException("No random bytes were returned in the response data");

        try
        {
            if (m_respDataItems[RAND_BYTES_INDEX] == null)
                throw new KEzSignException("No random bytes were contained in the response");

            m_randomBytes = KBase64.FromBase64String(m_respDataItems[RAND_BYTES_INDEX]);
        }
        catch (Exception e)
        {
            throw new KEzSignException("There was an error converting the random bytes: " + e.getMessage());
        }
    }

    /**
     * Returns the random byte array
     *
     * @return
     */
    public byte[] getRandomBytes()
    {
        return m_randomBytes;
    }
}
/********************************************************************************************************************/
/** END OF FILE *****************************************************************************************************/
/********************************************************************************************************************/
