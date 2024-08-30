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

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

/**
 * EzSignClient
 *
 * The EzSign Client
 *
 * Provides a simple API to generate and verify digital signatures
 *
 * Copyright (C) 2024 Krestfield Ltd - All Rights Reserved
 */
public class EzSignClient
{
    /**
     * Local properties
     */
    private Socket m_socket = null;
    private SSLSocketFactory m_sslSockFactory = null;
    boolean m_useTls = false;
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
     * @param host The name of the host to connect to - IP address or hostname
     * @param port The port the EzSign server is listening on
     */
    public EzSignClient(String host, int port)
    {
        m_host = host;
        m_port = port;
    }

    /**
     * Call to enable TLS connections to the server.  Note that the server must be configured to also use TLS
     *
     * @return The new EzSignClient instance
     */
    public EzSignClient useTls()
    {
        m_sslSockFactory = (SSLSocketFactory)SSLSocketFactory.getDefault();
        m_useTls = true;

        return this;
    }

    /**
     * Call to enable client side TLS.  Note that the server must be configured to require a client certificate
     *
     * @param clientKeystoreFilename The full path to the client keystore file
     * @param clientKeystorePassword The password protecting the keystore file
     * @param keyStoreType The keystore type. Can be either "PKCS12" or "JKS"
     * @return The new EzSignClient instance
     * @throws KEzSignException
     */
    public EzSignClient useClientTls(String clientKeystoreFilename, String clientKeystorePassword, String keyStoreType) throws KEzSignException
    {
        try
        {
            KeyStore clientKeyStore = KeyStore.getInstance(keyStoreType);
            clientKeyStore.load(new FileInputStream(clientKeystoreFilename), clientKeystorePassword.toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(clientKeyStore, clientKeystorePassword.toCharArray());
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), null, null);

            m_sslSockFactory = sslContext.getSocketFactory();

            m_useTls = true;

            return this;
        }
        catch (Exception e)
        {
            throw new KEzSignException("There was an error opening the connection using client SSL. " + e.getMessage());
        }
    }

    /**
     *
     * @param host The name of the host to connect to - IP address or hostname
     * @param port The port the EzSign server is listening on
     * @param authCode The auth code - this must be the same as has been configured at the server
     * @throws KEzSignException If there is an error
     */
    public EzSignClient(String host, int port, String authCode) throws KEzSignException
    {
        this(host, port);
        setAuthCode(authCode);
    }

    /**
     * The Constructor
     *
     * @param host The name of the host to connect to - IP address or hostname
     * @param port The port the EzSign server is listening on
     * @param connectTimeoutInMs The max time in milliseconds to wait before failing the connection
     * @param readTimeoutInMs The max time in milliseconds to wait for a response
     */
    public EzSignClient(String host, int port, int connectTimeoutInMs, int readTimeoutInMs)
    {
        this(host, port);

        if (readTimeoutInMs > 0)
            m_readTimeoutMs = readTimeoutInMs;

        if (connectTimeoutInMs > 0)
            m_connectTimeoutMs = connectTimeoutInMs;
    }

    /**
     *
     * @param host The name of the host to connect to - IP address or hostname
     * @param port The port the EzSign server is listening on
     * @param connectTimeoutInMs The max time in milliseconds to wait before failing the connection
     * @param readTimeoutInMs The max time in milliseconds to wait for a response
     * @param authCode The auth code - this must be the same as has been configured at the server
     * @throws KEzSignException If there is an error
     */
    public EzSignClient(String host, int port, int connectTimeoutInMs, int readTimeoutInMs, String authCode) throws KEzSignException
    {
        this(host, port, connectTimeoutInMs, readTimeoutInMs);
        setAuthCode(authCode);
    }

    /**
     * Sets the auth code
     *
     * @param authCode The auth code - this must be the same as has been configured at the server
     * @throws KEzSignException If there is an error
     */
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
     * @param host The name of the host to connect to - IP address or hostname
     */
    public void setHost(String host)
    {
        m_host = host;
    }

    /**
     * Returns the hostname currently being used
     *
     * @return The hostname or IP address
     */
    public String getHost()
    {
        return m_host;
    }

    /**
     * Sets the port to be used
     *
     * @param port The port to connect to
     */
    public void setPort(int port)
    {
        m_port = port;
    }

    /**
     * Returns the port number currently being used
     *
     * @return The port to connect to
     */
    public int getPort()
    {
        return m_port;
    }

    /**
     * Generates a signature and returns the produced PKCS#7
     *
     * @param channelName The name of the EzSign channel to process the request
     * @param dataToSign The data to sign
     * @param isDigest True if the data is a digest (already hashed)
     * @return The signature
     * @throws KSigningException If there is a signing exception
     * @throws KEzSignException If there is an error
     * @throws KEzSignConnectException If unable to connect to the EzSign server
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
     * @param channelName The name of the EzSign channel to process the request
     * @param numBytes The number of bytes to generate
     * @return The random bytes
     * @throws KEzSignException If there is an error
     * @throws KEzSignConnectException If unable to connect to the EzSign server
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
     * @param channelName The name of the EzSign channel to process the request
     * @param signature The PKCS7 signature data to verify
     * @param contentBytes The content that was signed
     * @param dataIsDigest True if the data is a digest (already hashed)
     * @throws KVerificationException If there is a signature verification error
     * @throws KPathException If there is a path building error
     * @throws KRevocationException If there is a revocation check error
     * @throws KEzSignException If there is an error
     * @throws KEzSignConnectException If unable to connect to the EzSign server
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
     * @param channelName The name of the EzSign channel to process the request
     * @param signature The RAW signature data to verify
     * @param contentBytes The content that was signed
     * @param dataIsDigest True if the data is a digest (already hashed)
     * @param signerCert The cert that signed the data
     * @throws KVerificationException If there is a signature verification error
     * @throws KPathException If there is a path building error
     * @throws KRevocationException If there is a revocation check error
     * @throws KEzSignException If there is an error
     * @throws KEzSignConnectException If unable to connect to the EzSign server
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
     * @param channelName The name of the EzSign channel to process the request
     * @param signature The RAW signature data to verify
     * @param contentBytes The content that was signed
     * @param dataIsDigest True if the data is a digest (already hashed)
     * @param signerCert The cert that signed the data
     * @param otherCerts Other certs in the path - required if they are not present on the server
     * @throws KVerificationException If there is a signature verification error
     * @throws KPathException If there is a path building error
     * @throws KRevocationException If there is a revocation check error
     * @throws KEzSignException If there is an error
     * @throws KEzSignConnectException If unable to connect to the EzSign server
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
     * @param channelName The name of the EzSign channel to process the request
     * @param signature The RAW signature data to verify
     * @param contentBytes The content that was signed
     * @param dataIsDigest True if the data is a digest (already hashed)
     * @param signerCert The cert that signed the data
     * @param otherCerts Other certs in the path - required if they are not present on the server
     * @param bypassRevocationCheck If true, revocation checking will be skipped
     * @param bypassPathBuild If true, path building will be skipped
     * @throws KVerificationException If there is a signature verification error
     * @throws KPathException If there is a path building error
     * @throws KRevocationException If there is a revocation check error
     * @throws KEzSignException If there is an error
     * @throws KEzSignConnectException If unable to connect to the EzSign server
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
     * @param channelName The name of the EzSign channel to process the request
     * @param signature The RAW signature data to verify
     * @param contentBytes The content that was signed
     * @param dataIsDigest True if the data is a digest (already hashed)
     * @param bypassRevocationCheck If true, revocation checking will be skipped
     * @param bypassPathBuild If true, path building will be skipped
     * @throws KVerificationException If there is a signature verification error
     * @throws KPathException If there is a path building error
     * @throws KRevocationException If there is a revocation check error
     * @throws KEzSignException If there is an error
     * @throws KEzSignConnectException If unable to connect to the EzSign server
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
     * @param channelName The name of the EzSign channel to process the request
     * @param signature The RAW signature data to verify
     * @param contentBytes The content that was signed
     * @param dataIsDigest True if the data is a digest (already hashed)
     * @param bypassRevocationCheck If true, revocation checking will be skipped
     * @param bypassPathBuild If true, path building will be skipped
     * @param signerCert The cert that signed the data
     * @param otherCerts Other certs in the path - required if they are not present on the server
     * @throws KVerificationException If there is a signature verification error
     * @throws KPathException If there is a path building error
     * @throws KRevocationException If there is a revocation check error
     * @throws KEzSignException If there is an error
     * @throws KEzSignConnectException If unable to connect to the EzSign server
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
     * @param channelName The name of the EzSign channel to process the request
     * @param signature The RAW signature data to verify
     * @param contentBytes The content that was signed
     * @param dataIsDigest True if the data is a digest (already hashed)
     * @param bypassRevocationCheck If true, revocation checking will be skipped
     * @param bypassPathBuild If true, path building will be skipped
     * @param signatureType IF the signature is SIG_TYPE_PKCS7 or SIG_TYPE_RAW
     * @throws KVerificationException If there is a signature verification error
     * @throws KPathException If there is a path building error
     * @throws KRevocationException If there is a revocation check error
     * @throws KEzSignException If there is an error
     * @throws KEzSignConnectException If unable to connect to the EzSign server
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
     * @param channelName The name of the EzSign channel to process the request
     * @param dataToEncrypt The data to encrypt
     * @param keyLabel The name of the key to perfom the decryption - as configured on the server
     * @return The encrypted data
     * @throws KEzSignException If there is an error
     * @throws KEzSignConnectException If unable to connect to the EzSign server
     * @throws KEncipherException If there is an error encrypting
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
     * @param channelName The name of the EzSign channel to process the request
     * @param encryptedData The encrypted data
     * @param keyLabel The name of the key to perfom the decryption - as configured on the server
     * @return THe clear data
     * @throws KEzSignException If there is an error
     * @throws KEzSignConnectException If unable to connect to the EzSign server
     * @throws KEncipherException If there is an error decrypting
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
     * @throws KEzSignConnectException If unable to connect
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
                m_socket.connect(new InetSocketAddress(m_host, m_port), CONNECT_TIMEOUT);
                if (m_useTls)
                {
                    SSLSocket sock = (SSLSocket) m_socket;
                    sock.startHandshake();
                }
                m_socket.setSoLinger(true, 0);
                m_socket.setSoTimeout(m_readTimeoutMs);

                connected = true;
            }
            catch (Exception exception)
            {
                if (numRetries >= maxNumRetries)
                {
                    throw new KEzSignConnectException("There was an error connecting to the EzSign server. " +
                            "Ensure the server is running on host " + m_host + " and listening on port " + m_port +
                            " and there is connectivity between this client and the server. " +
                            "If auth code is in use, check both the client and server are using the same code. " + exception.getMessage());
                }
                else
                {
                    // If we get here the socket is probably overloaded, trying to reconnect
                    // will just keep failing, so create new
                    try {
                        m_socket = new Socket();
                        if (m_useTls)
                            m_socket = m_sslSockFactory.createSocket();
                        else
                            m_socket = new Socket();
                    } catch (Exception e){}
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
            if (m_socket != null)
            {
                m_socket.close();
                // This always throws an exception as the server
                // closes the input and output streams
            }
        }
        catch(Exception e)
        {
            //e.printStackTrace();
        }
    }

    /**
     *
     * @param clearMessage The clear data
     * @return The encrypted data
     * @throws KEzSignException If there is an error encrypting
     */
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

    /**
     *
     * @param encMessage The encrypted message
     * @return The clear message
     * @throws KEzSignException If there is an error decrypting
     */
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
     * @param clearMessage The formatted message
     * @return The response
     * @throws KEzSignConnectException If unable to connect to the EzSign server
     */
    private synchronized String sendMessage(String clearMessage) throws KEzSignConnectException
    {
        try
        {
            String encMessage = encryptMessage(clearMessage);

            if (m_useTls)
                m_socket = m_sslSockFactory.createSocket();
            else
                m_socket = new Socket();

            String encRespMessage = null;

            int retryCount = 0;
            // Under extreme load (CPU near 100% 500 threads+) the server may occasionally
            // return an empty message.  Check for this here and re-send, up to MAX_SEND_RETRIES
            while ((encRespMessage == null || encRespMessage.isEmpty()) && retryCount < MAX_SEND_RETRIES)
            {
                connect();

                //Send the message to the server
                OutputStream os = m_socket.getOutputStream();
                OutputStreamWriter osw = new OutputStreamWriter(os);
                BufferedWriter bw = new BufferedWriter(osw);

                String sendMessage = encMessage + "\n";
                bw.write(sendMessage);
                bw.flush();

                //Get the return message from the server
                InputStream is = m_socket.getInputStream();
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
        catch (KEzSignConnectException connEx)
        {
            throw new KEzSignConnectException(connEx.getMessage());
        }
        catch (Exception e)
        {
            throw new KEzSignConnectException("There was an error connecting to the EzSign server. " +
                    "Ensure the server is running on host " + m_host + " and listening on port " + m_port +
                    " and there is connectivity between this client and the server. " +
                    "If auth code is in use, check both the client and server are using the same code. Error Details: " + e.getMessage());
        }
        finally
        {
            disconnect();
        }
    }
}
/********************************************* END OF FILE *****************************************************
 ***************************************************************************************************************/