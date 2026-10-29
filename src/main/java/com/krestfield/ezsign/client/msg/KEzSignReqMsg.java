package com.krestfield.ezsign.client.msg;

import com.krestfield.ezsign.client.KEzSignException;

/**
 * KEzSignReqMsg
 *
 * Copyright (C) 2016 Krestfield Ltd - All Rights Reserved
 */
public class KEzSignReqMsg extends KEzSignMsg
{
    protected String m_messageId;
    protected String m_channelName;
    protected String[] m_msgDataItems;

    /**
     * Message Format is:
     * MESSAGE_ID : CHANNEL : DATA1 : DATA2...
     * @param messageId The message ID e.g. SIGN
     * @param channel The channel name
     * @throws KEzSignException If there is an error
     */
    public KEzSignReqMsg(String messageId, String channel) throws KEzSignException
    {
        if (messageId.length() != MESSAGE_ID_LEN)
            throw new KEzSignException("Message ID can only be " + MESSAGE_ID_LEN + " characters.  Message ID received: " + messageId);

        if (channel == null || channel.length() == 0)
            throw new KEzSignException("Channel name is null or empty");
        checkField("channel name", channel);

        m_messageId = messageId;
        m_channelName = channel;
    }

    /**
     * Creates the number of items required and sets them all to empty string
     *
     * @param size The number of items
     */
    /**
     * Checks a value does not contain the message delimiter or a line break, which would change the fields of
     * the message (or end it) and could be used to alter the request
     *
     * @param name What the value is, for the error message
     * @param value The value
     * @throws KEzSignException If the value contains a character that cannot be sent
     */
    public static void checkField(String name, String value) throws KEzSignException
    {
        if (value != null && (value.contains(DELIMITER) || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0))
            throw new KEzSignException("The " + name + " cannot contain '" + DELIMITER + "' or a line break");
    }

    public void initDataItems(int size)
    {
        m_msgDataItems = new String[size];
        for (int i = 0; i < m_msgDataItems.length; i++)
            m_msgDataItems[i] = EMPTY_STR;
    }

    /**
     * Message Format is:
     * MESSAGE_ID : CHANNEL : DATA1 : DATA2...
     * Returned as a string
     *
     * @return The full message
     */
    public String getMessage()
    {
        String fullMsg = m_messageId + DELIMITER +
                         m_channelName;

        if (m_msgDataItems != null && m_msgDataItems.length != 0)
        {
            for (int item = 0; item < m_msgDataItems.length; item++)
            {
                fullMsg += (DELIMITER + m_msgDataItems[item]);
            }
        }

        return fullMsg;
    }
}
/********************************************* END OF FILE *****************************************************
 ***************************************************************************************************************/