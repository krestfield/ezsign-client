package com.krestfield.ezsign;

import java.security.cert.X509Certificate;

/**
 * KPathException
 *
 * Copyright (C) 2016 Krestfield Ltd - All Rights Reserved
 */
public class KPathException extends Exception
{
    X509Certificate m_cert;
    public KPathException(String message)
    {
        super(message);
    }

    public KPathException(String message, Throwable t)
    {
        super(message, t);
    }
}
/********************************************* END OF FILE *****************************************************
 ***************************************************************************************************************/