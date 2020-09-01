package com.krestfield.ezsign.msg;

import com.krestfield.ezsign.KEzSignException;

/**
 * KSignDataReqMsg
 *
 * Copyright (C) 2016 Krestfield Ltd - All Rights Reserved
 */
public class KSignDataReqMsg extends KEzSignReqMsg
{
    final static String MESSAGE_ID = "SIGN";

    public final static int SIG_TYPE_PKCS7 = 1;
    public final static int SIG_TYPE_RAW = 2;

    final int DTS_INDEX = 0;
    final int IS_DIGEST_INDEX = 1;
    final int HASH_ALG_INDEX = 2;
    final int SIG_TYPE_INDEX = 3;
    final int TRANS_ID_INDEX = 4;
    final int NUM_ITEMS = 5;

    /**
     *
     * @param channel The channel name
     * @param dataToSign The data to sign
     * @param isDigest Whether the data is a digest or not
     * @throws KEzSignException If there is an error
     */
    public KSignDataReqMsg(String channel, byte[] dataToSign, boolean isDigest) throws KEzSignException
    {
        super(MESSAGE_ID, channel);

        //m_msgDataItems = new String[NUM_ITEMS];
        initDataItems(NUM_ITEMS);

        if (dataToSign == null || dataToSign.length == 0)
            throw new KEzSignException("The data to sign was empty or null.  Cannot sign data");
        m_msgDataItems[DTS_INDEX] = KBase64.ToBase64String(dataToSign);

        m_msgDataItems[IS_DIGEST_INDEX] = isDigest ? TRUE_STR : FALSE_STR;
    }

    /**
     *
     * @param channel The channel name
     * @param dataToSign The data to sign
     * @param signatureType If the da ta is RAW of P7
     * @throws KEzSignException If there is an error
     */
    public KSignDataReqMsg(String channel, byte[] dataToSign, int signatureType) throws KEzSignException
    {
        this(channel, dataToSign, false);

        try
        {
            m_msgDataItems[SIG_TYPE_INDEX] = Integer.toString(signatureType);
        }
        catch (Exception e)
        {
            throw new KEzSignException("There was an error creating the Sign Data Request message. " + e.getMessage());
        }
    }

    /**
     *
     * @param channel The channel name
     * @param dataToSign The data to sign
     * @param isDigest Whether the data is a digest or not
     * @param hashAlg The hash algorithm
     * @param transId The transation ID
     * @throws KEzSignException If there is an error
     */
    public KSignDataReqMsg(String channel, byte[] dataToSign, boolean isDigest, String hashAlg, String transId) throws KEzSignException
    {
        this(channel, dataToSign, isDigest);
        try
        {
            m_msgDataItems[HASH_ALG_INDEX] = hashAlg;
            m_msgDataItems[TRANS_ID_INDEX] = transId;
        }
        catch (Exception e)
        {
            throw new KEzSignException("There was an error creating the Sign Data Request message. " + e.getMessage());
        }
    }
}
/********************************************* END OF FILE *****************************************************
 ***************************************************************************************************************/