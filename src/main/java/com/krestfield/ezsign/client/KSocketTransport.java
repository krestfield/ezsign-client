package com.krestfield.ezsign.client;

import com.krestfield.ezsign.client.msg.KEncipherReqMsg;
import com.krestfield.ezsign.client.msg.KEncipherRespMsg;
import com.krestfield.ezsign.client.msg.KEzSignRespMsg;
import com.krestfield.ezsign.client.msg.KGenRandomReqMsg;
import com.krestfield.ezsign.client.msg.KGenRandomRespMsg;
import com.krestfield.ezsign.client.msg.KSignDataReqMsg;
import com.krestfield.ezsign.client.msg.KSignDataRespMsg;
import com.krestfield.ezsign.client.msg.KVerifySignatureReqMsg;
import com.krestfield.ezsign.client.msg.KVerifySignatureRespMsg;
import com.krestfield.ezsign.client.utils.KEncrypt;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.X509Certificate;

/**
 * KSocketTransport
 *
 * Sends requests to the server's socket API. Each request uses a new connection: one line is sent and one line
 * is received. If an auth code is set, both are encrypted with it
 *
 * Copyright (C) 2026 Krestfield Ltd - All Rights Reserved
 */
class KSocketTransport implements KTransport
{
    // If the server returns an empty response (under extreme load), resend up to this many times
    static final int MAX_SEND_RETRIES = 5;

    // Wait this long before resending
    static final int RETRY_SEND_WAIT_MS = 5;

    // Each connection attempt times out after this long. Attempts are made until the connect timeout is reached
    static final int CONNECT_ATTEMPT_TIMEOUT_MS = 1000;

    // Wait this long before another connection attempt
    static final int RETRY_CONNECT_WAIT_MS = 10;

    // Sent by the server when a request could not be processed, e.g. when all instances are busy
    static final String UNKNOWN_MESSAGE_ID = "UKNW";

    private final String m_host;
    private final int m_port;
    private final int m_connectTimeoutMs;
    private final int m_readTimeoutMs;
    private final KEncrypt m_authCode;
    private final KTlsConfig m_tls;

    /**
     * @param authCode The auth code encryption, or null if no auth code is used
     * @param tls The TLS settings, or null to connect without TLS
     */
    KSocketTransport(String host, int port, int connectTimeoutMs, int readTimeoutMs, KEncrypt authCode, KTlsConfig tls)
    {
        m_host = host;
        m_port = port;
        m_connectTimeoutMs = connectTimeoutMs;
        m_readTimeoutMs = readTimeoutMs;
        m_authCode = authCode;
        m_tls = tls;
    }

    public Result signData(String channelName, byte[] dataToSign, boolean isDigest) throws KEzSignException, KEzSignConnectException
    {
        KSignDataReqMsg msg = new KSignDataReqMsg(channelName, dataToSign, isDigest);
        KSignDataRespMsg resp = new KSignDataRespMsg(sendMessage(msg.getMessage()));
        checkResponse(resp, "SIGN");
        return new Result(resp.getResponseCode(), resp.getErrorMessage(), resp.getSignature());
    }

    public Result generateRandomBytes(String channelName, int numBytes) throws KEzSignException, KEzSignConnectException
    {
        KGenRandomReqMsg msg = new KGenRandomReqMsg(channelName, numBytes);
        KGenRandomRespMsg resp = new KGenRandomRespMsg(sendMessage(msg.getMessage()));
        checkResponse(resp, KGenRandomReqMsg.MESSAGE_ID);
        return new Result(resp.getResponseCode(), resp.getErrorMessage(), resp.getRandomBytes());
    }

    public Result verifySignature(String channelName, byte[] signature, byte[] contentBytes, boolean dataIsDigest,
                                  boolean bypassRevocationCheck, boolean bypassPathBuild, int signatureType,
                                  X509Certificate signerCert, X509Certificate[] otherCerts) throws KEzSignException, KEzSignConnectException
    {
        KVerifySignatureReqMsg msg = new KVerifySignatureReqMsg(channelName, signature, contentBytes, dataIsDigest,
                bypassRevocationCheck, bypassPathBuild, signatureType, signerCert, otherCerts);
        KVerifySignatureRespMsg resp = new KVerifySignatureRespMsg(sendMessage(msg.getMessage()));
        checkResponse(resp, KVerifySignatureReqMsg.MESSAGE_ID);
        return new Result(resp.getResponseCode(), resp.getErrorMessage(), null);
    }

    public Result encipher(String channelName, boolean encrypt, byte[] data, String keyLabel) throws KEzSignException, KEzSignConnectException
    {
        KEncipherReqMsg msg = new KEncipherReqMsg(channelName, encrypt, data, keyLabel);
        KEncipherRespMsg resp = new KEncipherRespMsg(sendMessage(msg.getMessage()));
        checkResponse(resp, KEncipherReqMsg.MESSAGE_ID);
        return new Result(resp.getResponseCode(), resp.getErrorMessage(), resp.getData());
    }

    /**
     * Checks the response is for the request sent: the server returns the request's message ID reversed, or
     * UKNW with an error when it could not process the request
     */
    static void checkResponse(KEzSignRespMsg resp, String requestId) throws KEzSignException
    {
        String returned = resp.getReturnedMessageId();
        if (UNKNOWN_MESSAGE_ID.equals(returned) && resp.getResponseCode() != KEzSignRespMsg.RESP_OK)
            return;
        resp.checkMessageId(requestId, returned);
    }

    /**
     * Opens a connection, making attempts until the connect timeout is reached. Under extreme load the server
     * may not accept the first attempt
     */
    private Socket connect() throws KEzSignException, KEzSignConnectException
    {
        int maxAttempts = Math.max(1, m_connectTimeoutMs / CONNECT_ATTEMPT_TIMEOUT_MS);
        Exception lastError = null;
        for (int attempt = 0; attempt < maxAttempts; attempt++)
        {
            Socket socket = null;
            try
            {
                if (m_tls != null)
                {
                    SSLSocket sslSocket = (SSLSocket) m_tls.context().getSocketFactory().createSocket();
                    SSLParameters params = sslSocket.getSSLParameters();
                    m_tls.apply(params);
                    sslSocket.setSSLParameters(params);
                    socket = sslSocket;
                }
                else
                    socket = new Socket();

                socket.connect(new InetSocketAddress(m_host, m_port), CONNECT_ATTEMPT_TIMEOUT_MS);
                // Set before the TLS handshake, so a server that does not answer cannot hold the client
                socket.setSoTimeout(m_readTimeoutMs);
                if (socket instanceof SSLSocket)
                    ((SSLSocket) socket).startHandshake();
                socket.setSoLinger(true, 0);
                return socket;
            }
            catch (SSLException e)
            {
                // A TLS failure (e.g. an untrusted certificate or a host name mismatch) is not helped by retrying
                close(socket);
                throw new KEzSignConnectException("The TLS connection to the EzSign server on host " + m_host + " port " +
                        m_port + " failed. Check the server's certificate is trusted and is valid for the host name " +
                        "used, and the server is configured for TLS. " + e.getMessage());
            }
            catch (Exception e)
            {
                close(socket);
                lastError = e;
                try
                {
                    Thread.sleep(RETRY_CONNECT_WAIT_MS);
                }
                catch (InterruptedException ie)
                {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        throw new KEzSignConnectException("There was an error connecting to the EzSign server. " +
                "Ensure the server is running on host " + m_host + " and listening on port " + m_port +
                " and there is connectivity between this client and the server. " +
                (lastError != null ? lastError.getMessage() : ""));
    }

    private static void close(Socket socket)
    {
        try
        {
            if (socket != null)
                socket.close();
        }
        catch (Exception e)
        {
            // The server closes the streams once it has responded
        }
    }

    /**
     * Sends the message and returns the response. One request is sent at a time by each client, as before
     */
    private synchronized String sendMessage(String clearMessage) throws KEzSignException, KEzSignConnectException
    {
        String encMessage = m_authCode == null ? clearMessage : encrypt(clearMessage);

        String encRespMessage = null;
        // Under extreme load (CPU near 100% 500 threads+) the server may occasionally return an empty
        // message. Re-send up to MAX_SEND_RETRIES times
        for (int attempt = 0; attempt < MAX_SEND_RETRIES && (encRespMessage == null || encRespMessage.isEmpty()); attempt++)
        {
            if (attempt > 0)
            {
                try
                {
                    Thread.sleep(RETRY_SEND_WAIT_MS);
                }
                catch (InterruptedException e)
                {
                    Thread.currentThread().interrupt();
                    break;
                }
            }

            Socket socket = connect();
            try
            {
                BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
                bw.write(encMessage + "\n");
                bw.flush();

                BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                encRespMessage = br.readLine();
            }
            catch (IOException e)
            {
                throw new KEzSignConnectException("There was an error communicating with the EzSign server on host " +
                        m_host + " port " + m_port + ". " + e.getMessage());
            }
            finally
            {
                close(socket);
            }
        }

        if (encRespMessage == null || encRespMessage.isEmpty())
            throw new KEzSignConnectException("The EzSign server on host " + m_host + " port " + m_port +
                    " closed the connection without responding. " + (m_authCode != null ?
                    "Check the client and server use the same auth code" :
                    "If the server uses an auth code, the client must be given the same auth code"));

        return m_authCode == null ? encRespMessage : decrypt(encRespMessage);
    }

    private String encrypt(String clearMessage) throws KEzSignException
    {
        try
        {
            return m_authCode.encryptData(clearMessage);
        }
        catch (Exception e)
        {
            throw new KEzSignException("There was an error encrypting the message being sent to the " +
                    "server with the auth code key. " + e.getMessage());
        }
    }

    private String decrypt(String encMessage) throws KEzSignException
    {
        try
        {
            return m_authCode.decryptData(encMessage);
        }
        catch (Exception e)
        {
            throw new KEzSignException("There was an error decrypting the response message received from the " +
                    "server with the auth code key. Check both the server and client are using the same auth code. " + e.getMessage());
        }
    }
}
/********************************************* END OF FILE *****************************************************
 ***************************************************************************************************************/
