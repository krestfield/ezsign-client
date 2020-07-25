package com.krestfield.ezsign.msg;

import com.krestfield.ezsign.KEzSignException;

/**
 * KGenRandomReqMsg
 *
 * Copyright Krestfield 2016
 */
public class KGenRandomReqMsg extends KEzSignReqMsg
{
    public final static String MESSAGE_ID = "RAND";

    final int NUM_BYTES_INDEX = 0;

    private int m_numBytes;

    public KGenRandomReqMsg(String channel, int numBytes) throws KEzSignException
    {
        super(MESSAGE_ID, channel);

        m_msgDataItems = new String[1];
        m_msgDataItems[NUM_BYTES_INDEX] = Integer.toString(numBytes);
    }
}
/********************************************************************************************************************/
/** END OF FILE *****************************************************************************************************/
/********************************************************************************************************************/
