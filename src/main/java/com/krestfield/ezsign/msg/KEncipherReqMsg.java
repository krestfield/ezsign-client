package com.krestfield.ezsign.msg;

import com.krestfield.ezsign.KEzSignException;

/**
 * KEncipherReqMsg
 *
 * Message Format
 *   0: Encrypt - 1, Decrypt 0
 *   1: Data
 *   2: Key Label - optional, as a default can be set
 *
 *   Delimiter is ~
 *
 * Copyright Krestfield 2017
 */
public class KEncipherReqMsg extends KEzSignReqMsg
{
    public final static String MESSAGE_ID = "ENCI";

    final int ENCRYPT_INDEX = 0;
    final int DATA_INDEX = 1;
    final int KEY_LABEL_INDEX = 2;
    final int NUM_ITEMS = 3;

    public KEncipherReqMsg(String channel, boolean encrypt, byte[] data, String keyLabel) throws KEzSignException
    {
        super(MESSAGE_ID, channel);

        initDataItems(NUM_ITEMS);

        m_msgDataItems[ENCRYPT_INDEX] = encrypt ? TRUE_STR : FALSE_STR;

        if (data == null || data.length == 0)
            throw new KEzSignException("The data to encipher was empty or null.  Cannot encipher data");

        m_msgDataItems[DATA_INDEX] = KBase64.ToBase64String(data);

        if (keyLabel != null && !keyLabel.isEmpty())
            m_msgDataItems[KEY_LABEL_INDEX] = keyLabel;
    }
}
/********************************************* END OF FILE *****************************************************
 ***************************************************************************************************************/