package com.krestfield.ezsign.client;

import java.security.cert.X509Certificate;

/**
 * KTransport
 *
 * Sends the client's requests to the server: over the socket API (KSocketTransport) or the REST API
 * (KRestTransport). Both return the result in the same form, using the socket API's response codes, so
 * EzSignClient reports errors in the same way whichever is used
 *
 * Copyright (C) 2026 Krestfield Ltd - All Rights Reserved
 */
interface KTransport
{
    /**
     * The result of a request
     */
    class Result
    {
        // One of the KEzSignRespMsg.RESP_ codes
        final int m_code;
        final String m_error;
        final byte[] m_data;

        Result(int code, String error, byte[] data)
        {
            m_code = code;
            m_error = error;
            m_data = data;
        }

        static Result ok(byte[] data)
        {
            return new Result(0, null, data);
        }
    }

    Result signData(String channelName, byte[] dataToSign, boolean isDigest) throws KEzSignException, KEzSignConnectException;

    Result generateRandomBytes(String channelName, int numBytes) throws KEzSignException, KEzSignConnectException;

    Result verifySignature(String channelName, byte[] signature, byte[] contentBytes, boolean dataIsDigest,
                           boolean bypassRevocationCheck, boolean bypassPathBuild, int signatureType,
                           X509Certificate signerCert, X509Certificate[] otherCerts) throws KEzSignException, KEzSignConnectException;

    Result encipher(String channelName, boolean encrypt, byte[] data, String keyLabel) throws KEzSignException, KEzSignConnectException;
}
/********************************************* END OF FILE *****************************************************
 ***************************************************************************************************************/
