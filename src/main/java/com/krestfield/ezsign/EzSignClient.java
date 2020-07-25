package com.krestfield.ezsign;

import com.krestfield.ezsign.msg.KEncipherReqMsg;
import com.krestfield.ezsign.msg.KEncipherRespMsg;
import com.krestfield.ezsign.msg.KEzSignRespMsg;
import com.krestfield.ezsign.msg.KGenRandomReqMsg;
import com.krestfield.ezsign.msg.KGenRandomRespMsg;
import com.krestfield.ezsign.msg.KSignDataReqMsg;
import com.krestfield.ezsign.msg.KSignDataRespMsg;
import com.krestfield.ezsign.msg.KVerifySignatureReqMsg;
import com.krestfield.ezsign.msg.KVerifySignatureRespMsg;
import com.krestfield.ezsign.utils.KEncrypt;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.X509Certificate;

/**
 * EzSignClient
 *
 * The EzSign Client
 *
 * Provides a simple API to generate and verify digital signatures
 *
 * Copyright (C) 2017 Krestfield Ltd - All Rights Reserved
 */
public class EzSignClient
{
    /**
     * Local properties
     */
    private Socket socket = null;
    String m_host;
    int m_port;

    // Default overall timeouts
    int m_readTimeoutMs = 5000;
    int m_connectTimeoutMs = 5000;

    // If send fails, retry up to this many times
    final int MAX_SEND_RETRIES = 5;

    // If send fails, wait this long before retrying
    final int RETRY_SEND_WAIT_MS = 5;

    // If connect fails, wait this long before retrying
    final int RETRY_CONNECT_WAIT_MS = 10;

    // The initial connection timeout
    int CONNECT_TIMEOUT = 1000;

    boolean m_usingAuthCode = false;
    KEncrypt m_encrypt = null;

    /**
     * The Constructor
     *
     * @param host
     * @param port
     */
    public EzSignClient(String host, int port)
    {
        m_host = host;
        m_port = port;
    }

    public EzSignClient(String host, int port, String authCode) throws KEzSignException
    {
        this(host, port);
        setAuthCode(authCode);
    }

    /**
     * The Constructor
     *
     * @param host
     * @param port
     */
    public EzSignClient(String host, int port, int connectTimeoutInMs, int readTimeoutInMs)
    {
        m_host = host;
        m_port = port;

        if (readTimeoutInMs > 0)
            m_readTimeoutMs = readTimeoutInMs;

        if (connectTimeoutInMs > 0)
            m_connectTimeoutMs = connectTimeoutInMs;
    }

    public EzSignClient(String host, int port, int connectTimeoutInMs, int readTimeoutInMs, String authCode) throws KEzSignException
    {
        this(host, port, connectTimeoutInMs, readTimeoutInMs);
        setAuthCode(authCode);
    }

    private void setAuthCode(String authCode) throws KEzSignException
    {
        if (authCode != null && authCode.length() > 0)
        {
            m_usingAuthCode = true;
            m_encrypt = new KEncrypt(authCode);
        }
    }

    /**
     * Sets the host to use
     *
     * @param host
     */
    public void setHost(String host)
    {
        m_host = host;
    }

    /**
     * Returns the hostname currently being used
     *
     * @return
     */
    public String getHost()
    {
        return m_host;
    }

    /**
     * Sets the port to be used
     *
     * @param port
     */
    public void setPort(int port)
    {
        m_port = port;
    }

    /**
     * Returns the port number currently being used
     *
     * @return
     */
    public int getPort()
    {
        return m_port;
    }


    /**
     * Generates a signature and returns the produced PKCS#7
     *
     * @param channelName
     * @param dataToSign
     * @param isDigest
     * @return
     * @throws KSigningException
     * @throws KEzSignException
     * @throws KEzSignConnectException
     */
    public byte[] signData(String channelName, byte[] dataToSign, boolean isDigest) throws KSigningException, KEzSignException, KEzSignConnectException
    {
        KSignDataReqMsg msg = new KSignDataReqMsg(channelName, dataToSign, isDigest);

        String response = sendMessage(msg.getMessage());

        KSignDataRespMsg resp = new KSignDataRespMsg(response);
        int respCode = resp.getResponseCode();
        if (respCode != KSignDataRespMsg.RESP_OK)
        {
            String error = resp.getErrorMessage();
            switch (respCode)
            {
                case KEzSignRespMsg.RESP_GENERAL_EXCEPTION:
                    throw new KEzSignException(error);
                case KEzSignRespMsg.RESP_SIGNING_EXCEPTION:
                    throw new KSigningException(error);
            }
        }
        return resp.getSignature();
    }

    /**
     * Generates the number of random bytes requested
     *
     * @param channelName
     * @param numBytes
     * @return
     * @throws KEzSignException
     * @throws KEzSignConnectException
     */
    public byte[] generateRandomBytes(String channelName, int numBytes) throws KEzSignException, KEzSignConnectException
    {
        KGenRandomReqMsg msg = new KGenRandomReqMsg(channelName, numBytes);

        String response = sendMessage(msg.getMessage());

        KGenRandomRespMsg resp = new KGenRandomRespMsg(response);
        int respCode = resp.getResponseCode();
        if (respCode != KGenRandomRespMsg.RESP_OK)
        {
            String error = resp.getErrorMessage();
            switch (respCode)
            {
                case KEzSignRespMsg.RESP_GENERAL_EXCEPTION:
                    throw new KEzSignException(error);
            }
        }
        return resp.getRandomBytes();
    }

    /**
     * Verifies a signature
     *
     * @param channelName
     * @param signature
     * @param contentBytes
     * @param dataIsDigest
     * @return
     * @throws KVerificationException
     * @throws KPathException
     * @throws KRevocationException
     * @throws KEzSignException
     * @throws KEzSignConnectException
     */
    public void verifySignature(String channelName, byte[] signature, byte[] contentBytes, boolean dataIsDigest)
            throws KVerificationException, KPathException, KRevocationException, KEzSignException, KEzSignConnectException
    {
        verifySignature(channelName, signature, contentBytes, dataIsDigest, false, false, KVerifySignatureReqMsg.SIG_TYPE_PKCS7,
                null, null);
    }

    /**
     * Verifies a raw signature
     *
     * @param channelName
     * @param signature
     * @param contentBytes
     * @param dataIsDigest
     * @param signerCert
     * @throws KVerificationException
     * @throws KPathException
     * @throws KRevocationException
     * @throws KEzSignException
     * @throws KEzSignConnectException
     */
    public void verifyRawSignature(String channelName, byte[] signature, byte[] contentBytes, boolean dataIsDigest, X509Certificate signerCert)
            throws KVerificationException, KPathException, KRevocationException, KEzSignException, KEzSignConnectException
    {
        verifySignature(channelName, signature, contentBytes, dataIsDigest, false, false, KVerifySignatureReqMsg.SIG_TYPE_RAW,
                signerCert, null);
    }

    /**
     * Verifies a raw signature.  Allows other certificates in the chain to be supplied
     *
     * @param channelName
     * @param signature
     * @param contentBytes
     * @param dataIsDigest
     * @throws KVerificationException
     * @throws KPathException
     * @throws KRevocationException
     * @throws KEzSignException
     * @throws KEzSignConnectException
     */
    public void verifyRawSignature(String channelName, byte[] signature, byte[] contentBytes, boolean dataIsDigest,
                                   X509Certificate signerCert, X509Certificate[] otherCerts)
            throws KVerificationException, KPathException, KRevocationException, KEzSignException, KEzSignConnectException
    {
        verifySignature(channelName, signature, contentBytes, dataIsDigest, false, false, KVerifySignatureReqMsg.SIG_TYPE_RAW,
                signerCert, otherCerts);
    }

    /**
     * Verifies a raw signature.  Allows other certificates in the chain to be supplied and
     * the bypassing of revocation checking and path building
     *
     * @param channelName
     * @param signature
     * @param contentBytes
     * @param dataIsDigest
     * @throws KVerificationException
     * @throws KPathException
     * @throws KRevocationException
     * @throws KEzSignException
     * @throws KEzSignConnectException
     */
    public void verifyRawSignature(String channelName, byte[] signature, byte[] contentBytes, boolean dataIsDigest,
                                   X509Certificate signerCert, X509Certificate[] otherCerts, boolean bypassRevocationCheck,
                                   boolean bypassPathBuild)
            throws KVerificationException, KPathException, KRevocationException, KEzSignException, KEzSignConnectException
    {
        verifySignature(channelName, signature, contentBytes, dataIsDigest, bypassRevocationCheck, bypassPathBuild,
                KVerifySignatureReqMsg.SIG_TYPE_RAW, signerCert, otherCerts);
    }

    /**
     * Verifies a signature.  Allows the bypassing of revocation checking and path building
     *
     * @param channelName
     * @param signature
     * @param contentBytes
     * @param dataIsDigest
     * @param bypassRevocationCheck
     * @param bypassPathBuild
     * @return
     * @throws KVerificationException
     * @throws KPathException
     * @throws KRevocationException
     * @throws KEzSignException
     * @throws KEzSignConnectException
     */
    public void verifySignature(String channelName, byte[] signature, byte[] contentBytes, boolean dataIsDigest,
                                   boolean bypassRevocationCheck, boolean bypassPathBuild)
            throws KVerificationException, KPathException, KRevocationException, KEzSignException, KEzSignConnectException
    {
        verifySignature(channelName, signature, contentBytes, dataIsDigest,
                bypassRevocationCheck, bypassPathBuild, KVerifySignatureReqMsg.SIG_TYPE_PKCS7, null, null);
    }

    /**
     * Verifies a raw signature.  Allows the bypassing of revocation checking and path building
     *
     * @param channelName
     * @param signature
     * @param contentBytes
     * @param dataIsDigest
     * @param bypassRevocationCheck
     * @param bypassPathBuild
     * @throws KVerificationException
     * @throws KPathException
     * @throws KRevocationException
     * @throws KEzSignException
     * @throws KEzSignConnectException
     */
    public void verifyRawSignature(String channelName, byte[] signature, byte[] contentBytes, boolean dataIsDigest,
                                   boolean bypassRevocationCheck, boolean bypassPathBuild,
                                   X509Certificate signerCert, X509Certificate[] otherCerts)
            throws KVerificationException, KPathException, KRevocationException, KEzSignException, KEzSignConnectException
    {
        verifySignature(channelName, signature, contentBytes, dataIsDigest,
                bypassRevocationCheck, bypassPathBuild, KVerifySignatureReqMsg.SIG_TYPE_RAW, signerCert, otherCerts);
    }

    /**
     * All verify signature calls ultimately call this method which includes all parameters
     *
     * @param channelName
     * @param signature
     * @param contentBytes
     * @param dataIsDigest
     * @param bypassRevocationCheck
     * @param bypassPathBuild
     * @param signatureType
     * @throws KVerificationException
     * @throws KPathException
     * @throws KRevocationException
     * @throws KEzSignException
     * @throws KEzSignConnectException
     */
    private void verifySignature(String channelName, byte[] signature, byte[] contentBytes, boolean dataIsDigest,
                                 boolean bypassRevocationCheck, boolean bypassPathBuild, int signatureType,
                                 X509Certificate signerCert, X509Certificate[] otherCerts)
            throws KVerificationException, KPathException, KRevocationException, KEzSignException, KEzSignConnectException
    {
        KVerifySignatureReqMsg msg = new KVerifySignatureReqMsg(channelName, signature, contentBytes, dataIsDigest,
                bypassRevocationCheck, bypassPathBuild, signatureType, signerCert, otherCerts);

        String response = sendMessage(msg.getMessage());

        KVerifySignatureRespMsg resp = new KVerifySignatureRespMsg(response);
        int respCode = resp.getResponseCode();
        if (respCode != KSignDataRespMsg.RESP_OK)
        {
            String error = resp.getErrorMessage();
            switch (respCode)
            {
                case KEzSignRespMsg.RESP_GENERAL_EXCEPTION:
                    throw new KEzSignException(error);
                case KEzSignRespMsg.RESP_VERIFICATION_EXCEPTION:
                    throw new KVerificationException(error);
                case KEzSignRespMsg.RESP_REVOCATION_EXCEPTION:
                    throw new KRevocationException(error);
                case KEzSignRespMsg.RESP_PATH_EXCEPTION:
                    throw new KPathException(error);
            }
        }
    }


    /**
     * Encrypts the data provided in dataToEncrypt with the key referenced by keyLabel
     *
     * @param channelName
     * @param dataToEncrypt
     * @param keyLabel
     * @return
     * @throws KEzSignException
     * @throws KEzSignConnectException
     * @throws KEncipherException
     */
    public byte[] encryptData(String channelName, byte[] dataToEncrypt, String keyLabel) throws KEzSignException, KEzSignConnectException, KEncipherException
    {
        KEncipherReqMsg msg = new KEncipherReqMsg(channelName, true, dataToEncrypt, keyLabel);

        String response = sendMessage(msg.getMessage());

        KEncipherRespMsg resp = new KEncipherRespMsg(response);
        int respCode = resp.getResponseCode();
        if (respCode != KSignDataRespMsg.RESP_OK)
        {
            String error = resp.getErrorMessage();
            switch (respCode)
            {
                case KEzSignRespMsg.RESP_GENERAL_EXCEPTION:
                    throw new KEzSignException(error);
                case KEzSignRespMsg.RESP_ENCIPHER_EXCEPTION:
                    throw new KEncipherException(error);
            }
        }

        return resp.getData();
    }

    /**
     * Decrypts data previously encrypted with encryptData using the key referenced by keyLabel
     *
     * @param channelName
     * @param encryptedData
     * @param keyLabel
     * @return
     * @throws KEzSignException
     * @throws KEzSignConnectException
     * @throws KEncipherException
     */
    public byte[] decryptData(String channelName, byte[] encryptedData, String keyLabel) throws KEzSignException, KEzSignConnectException, KEncipherException
    {
        KEncipherReqMsg msg = new KEncipherReqMsg(channelName, false, encryptedData, keyLabel);

        String response = sendMessage(msg.getMessage());

        KEncipherRespMsg resp = new KEncipherRespMsg(response);
        int respCode = resp.getResponseCode();
        if (respCode != KSignDataRespMsg.RESP_OK)
        {
            String error = resp.getErrorMessage();
            switch (respCode)
            {
                case KEzSignRespMsg.RESP_GENERAL_EXCEPTION:
                    throw new KEzSignException(error);
                case KEzSignRespMsg.RESP_ENCIPHER_EXCEPTION:
                    throw new KEncipherException(error);
            }
        }

        return resp.getData();
    }

    /**
     * Connects to the server
     *
     * @throws KEzSignConnectException
     */
    private void connect() throws KEzSignConnectException
    {
        // Under extreme server load (nearing 100% )the client may not be connect
        // We therefore, try to connect every sleepTimeMs until the connection timeout is reached
        int numRetries = 0;
        //int maxNumRetries = m_connectTimeoutMs / RETRY_CONNECT_WAIT_MS;
        int maxNumRetries = m_connectTimeoutMs / CONNECT_TIMEOUT;

        boolean connected = false;
        while (!connected)
        {
            try
            {
                socket.connect(new InetSocketAddress(m_host, m_port), CONNECT_TIMEOUT/*m_connectTimeoutMs*/);
                socket.setSoLinger(true, 0);
                socket.setSoTimeout(m_readTimeoutMs);

                connected = true;
            }
            catch (Exception exception)
            {
                if (numRetries >= maxNumRetries)
                {
                    throw new KEzSignConnectException("There was an error connecting to the EzSign server.  " +
                            "Ensure the server is running on host " + m_host + " and listening on port " + m_port +
                            " and there is connectivity between this client and the server. " +
                            "If auth code is in use, check both the client and server are using the same code. " + exception.getMessage());
                }
                else
                {
                    // If we get here the socket is probably overloaded, trying to reconnect
                    // will just keep failing, so create new
                    try { socket = new Socket(); } catch (Exception e){}
                    numRetries++;
                    try { Thread.sleep(RETRY_CONNECT_WAIT_MS); } catch (Exception e){ }
                }
            }
        }
    }

    /**
     * Disconnects from the server
     */
    private void disconnect()
    {
        try
        {
            if (socket != null)
            {
                socket.close();
                // This always throws an exception as the server
                // closes the input and output streams
            }
        }
        catch(Exception e)
        {
            //e.printStackTrace();
        }
    }

    private String encryptMessage(String clearMessage) throws KEzSignException
    {
        try
        {
            String encMessage = clearMessage;
            if (m_usingAuthCode)
            {
                encMessage = m_encrypt.encryptData(clearMessage);
            }

            return encMessage;
        }
        catch (Exception e)
        {
            throw new KEzSignException("There was an error encrypting the message being sent to the " +
                    "server with the auth code key. " + e.getMessage());
        }
    }

    private String decryptMessage(String encMessage) throws KEzSignException
    {
        try
        {
            String clearMessage = encMessage;
            if (m_usingAuthCode)
            {
                clearMessage = m_encrypt.decryptData(encMessage);
            }

            return clearMessage;
        }
        catch (Exception e)
        {
            throw new KEzSignException("There was an error decrypting the response message received from the " +
                    "server with the auth code key. Check both the server and client are using the same auth code password. " + e.getMessage());
        }
    }

    /**
     * Sends the message to the server and gets the response string
     *
     * @param clearMessage
     * @return
     * @throws KEzSignConnectException
     */
    private String sendMessage(String clearMessage) throws KEzSignConnectException
    {
        try
        {
            String encMessage = encryptMessage(clearMessage);

            socket = new Socket();
            synchronized (socket)
            {
                String encRespMessage = null;

                int retryCount = 0;
                // Under extreme load (CPU near 100% 500 threads+) the server may occasionally
                // return an empty message.  Check for this here and re-send, up to MAX_SEND_RETRIES
                while ((encRespMessage == null || encRespMessage.isEmpty()) && retryCount < MAX_SEND_RETRIES)
                {
                    connect();

                    //Send the message to the server
                    OutputStream os = socket.getOutputStream();
                    OutputStreamWriter osw = new OutputStreamWriter(os);
                    BufferedWriter bw = new BufferedWriter(osw);

                    String sendMessage = encMessage + "\n";
                    bw.write(sendMessage);
                    bw.flush();

                    //Get the return message from the server
                    InputStream is = socket.getInputStream();
                    InputStreamReader isr = new InputStreamReader(is);
                    BufferedReader br = new BufferedReader(isr);
                    encRespMessage = br.readLine();

                    is.close();
                    os.close();

                    disconnect();

                    retryCount++;

                    // Wait, and then try again
                    if (encRespMessage == null || encRespMessage.isEmpty())
                        // Try to sleep.  If fails, just continue
                        try { Thread.sleep(RETRY_SEND_WAIT_MS); }catch (Exception e){};
                }

                String clearRespMessage = decryptMessage(encRespMessage);

                return clearRespMessage;
            }
        }
        catch (KEzSignConnectException connEx)
        {
            throw new KEzSignConnectException(connEx.getMessage());
        }
        catch (Exception e)
        {
            throw new KEzSignConnectException("There was an error connecting to the EzSign server.  " +
                    "Ensure the server is running on host " + m_host + " and listening on port " + m_port +
                    " and there is connectivity between this client and the server.  " +
                    "If auth code is in use, check both the client and server are using the same code. " + e.getMessage());
        }
        finally
        {
            disconnect();
        }
    }
}
/********************************************* END OF FILE *****************************************************
 ***************************************************************************************************************/