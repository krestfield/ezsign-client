package com.krestfield.ezsign.msg;

import com.krestfield.ezsign.KEzSignException;

/**
 * KVerifySignatureRespMsg
 *
 * Copyright (C) 2016 Krestfield Ltd - All Rights Reserved
 */
public class KVerifySignatureRespMsg extends KEzSignRespMsg
{
    public final static String MESSAGE_ID = "IREV";

    public KVerifySignatureRespMsg(String fullMessage) throws KEzSignException
    {
        super(fullMessage);
    }
}
/********************************************* END OF FILE *****************************************************
 ***************************************************************************************************************/