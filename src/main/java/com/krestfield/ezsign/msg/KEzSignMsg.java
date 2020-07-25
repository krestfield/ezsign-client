package com.krestfield.ezsign.msg;

import com.krestfield.ezsign.KEzSignException;

/**
 * KEzSignMsg
 *
 * Copyright (C) 2016 Krestfield Ltd - All Rights Reserved
 */
public class KEzSignMsg
{
    public static String DELIMITER = "~";
    final int MESSAGE_ID_LEN = 4;
    final String TRUE_STR = "1";
    final String FALSE_STR = "0";
    final String EMPTY_STR = " ";

    public void checkMessageId(String messageId, String returnedMessageId) throws KEzSignException
    {
        // Expected is a reverse of what was sent
        String expected = new StringBuilder(messageId).reverse().toString();
        if (expected.compareTo(returnedMessageId) != 0)
            throw new KEzSignException("There was an error communicating with the server.  The message ID returned was not expected");
    }
}
/********************************************* END OF FILE *****************************************************
 ***************************************************************************************************************/