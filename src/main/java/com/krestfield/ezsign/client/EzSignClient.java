package com.krestfield.ezsign.client;

import com.krestfield.ezsign.client.msg.KEzSignRespMsg;
import com.krestfield.ezsign.client.msg.KVerifySignatureReqMsg;
import com.krestfield.ezsign.client.utils.KEncrypt;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.Properties;

/**
 * EzSignClient
 *
 * The EzSign Client
 *
 * Provides a simple API to generate and verify digital signatures, encrypt and decrypt data and generate random
 * data, using an EzSign server.
 *
 * The client can use either of the server's APIs. The calls are the same for both:
 *
 * - The socket API (the default). Optionally protected with an auth code and/or TLS
 *       new EzSignClient("127.0.0.1", 5656)
 *
 * - The REST API (HTTPS). The client authenticates with an API token or a TLS client certificate, and the
 *   server checks the user has permission for each channel and operation
 *       new EzSignClient("ezsign.example.com", 8443).useRestApi().useApiToken(token)
 *
 * The settings can also be read from a properties file, so the API can be changed without changing code. See
 * fromProperties
 *
 * Copyright (C) 2026 Krestfield Ltd - All Rights Reserved
 */
public class EzSignClient
{
    // Property names read by fromProperties
    public static final String PROP_API = "ezsign.api";
    public static final String PROP_HOST = "ezsign.host";
    public static final String PROP_PORT = "ezsign.port";
    public static final String PROP_CONNECT_TIMEOUT = "ezsign.connectTimeoutMs";
    public static final String PROP_READ_TIMEOUT = "ezsign.readTimeoutMs";
    public static final String PROP_TLS = "ezsign.tls";
    public static final String PROP_AUTH_CODE = "ezsign.authCode";
    public static final String PROP_API_TOKEN = "ezsign.apiToken";
    public static final String PROP_CLIENT_KEYSTORE = "ezsign.clientKeyStore";
    public static final String PROP_CLIENT_KEYSTORE_PASSWORD = "ezsign.clientKeyStorePassword";
    public static final String PROP_CLIENT_KEYSTORE_TYPE = "ezsign.clientKeyStoreType";
    public static final String PROP_TRUSTSTORE = "ezsign.trustStore";
    public static final String PROP_TRUSTSTORE_PASSWORD = "ezsign.trustStorePassword";
    public static final String PROP_TRUSTSTORE_TYPE = "ezsign.trustStoreType";
    public static final String PROP_VERIFY_HOSTNAME = "ezsign.verifyHostname";

    // A secret property (e.g. ezsign.apiToken) may instead name a file holding the value, with this suffix
    public static final String FILE_SUFFIX = "File";

    public static final String API_SOCKET = "socket";
    public static final String API_REST = "rest";

    /**
     * Local properties
     */
    String m_host;
    int m_port;

    // Default overall timeouts
    int m_readTimeoutMs = 5000;
    int m_connectTimeoutMs = 5000;

    // Socket API settings
    boolean m_useTls = false;
    KEncrypt m_encrypt = null;

    // REST API settings
    boolean m_useRestApi = false;
    boolean m_restUseTls = true;
    String m_apiToken = null;

    // TLS settings, for both APIs
    final KTlsConfig m_tls = new KTlsConfig();

    // Created from the settings when first used
    private KTransport m_transport = null;


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
     * Call to enable TLS connections to the server.  Note that the server must be configured to also use TLS.
     * The REST API always uses TLS, so this is only needed for the socket API
     *
     * The server's certificate must be issued by a CA in the Java trust store, or in the trust store set with
     * useTrustStore, and must be valid for the host name the client connects to (see verifyHostname)
     *
     * @return The new EzSignClient instance
     */
    public synchronized EzSignClient useTls()
    {
        m_useTls = true;
        m_transport = null;
        return this;
    }

    /**
     * Call to enable client side TLS.  Note that the server must be configured to require a client certificate.
     *
     * With the REST API, the client certificate authenticates the client (if no API token is set). It must be
     * registered to a user on the server
     *
     * @param clientKeystoreFilename The full path to the client keystore file
     * @param clientKeystorePassword The password protecting the keystore file
     * @param keyStoreType The keystore type. Can be either "PKCS12" or "JKS"
     * @return The new EzSignClient instance
     * @throws KEzSignException
     */
    public synchronized EzSignClient useClientTls(String clientKeystoreFilename, String clientKeystorePassword, String keyStoreType) throws KEzSignException
    {
        m_tls.setClientKeyStore(clientKeystoreFilename, clientKeystorePassword, keyStoreType);
        m_useTls = true;
        m_transport = null;
        return this;
    }

    /**
     * Sets the CA certificates trusted to issue the server's TLS certificate, for either API. Without this the
     * Java trust store is used. For the socket API, TLS must also be turned on with useTls()
     *
     * @param trustStoreFilename The full path to the trust store file
     * @param trustStorePassword The password protecting the trust store file (may be null for a PKCS12 file with
     *                           no password)
     * @param keyStoreType The trust store type. Can be either "PKCS12" or "JKS"
     * @return This EzSignClient instance
     * @throws KEzSignException If the trust store cannot be loaded
     */
    public synchronized EzSignClient useTrustStore(String trustStoreFilename, String trustStorePassword, String keyStoreType) throws KEzSignException
    {
        m_tls.setTrustStore(trustStoreFilename, trustStorePassword, keyStoreType);
        m_transport = null;
        return this;
    }

    /**
     * Sets whether the server's certificate must be valid for the host name the client connects to. This is
     * on by default and should only be turned off if the server's certificate cannot be changed to include the
     * host name or IP address used: without it, any certificate issued by a trusted CA is accepted
     *
     * @param verify True to check the host name (the default)
     * @return This EzSignClient instance
     */
    public synchronized EzSignClient verifyHostname(boolean verify)
    {
        m_tls.setVerifyHostname(verify);
        m_transport = null;
        return this;
    }

    /**
     * Use the server's REST API (HTTPS). Set the port to the REST API port (server.restapi.port) and
     * authenticate with useApiToken or useClientTls. All other calls are unchanged
     *
     * @return This EzSignClient instance
     */
    public synchronized EzSignClient useRestApi()
    {
        return useRestApi(true);
    }

    /**
     * Use the server's REST API
     *
     * @param useTls Whether to use HTTPS. Only false for a server configured with server.restapi.useTls=false,
     *               e.g. behind a TLS proxy on the same machine
     * @return This EzSignClient instance
     */
    public synchronized EzSignClient useRestApi(boolean useTls)
    {
        m_useRestApi = true;
        m_restUseTls = useTls;
        m_transport = null;
        return this;
    }

    /**
     * Use the server's socket API (the default)
     *
     * @return This EzSignClient instance
     */
    public synchronized EzSignClient useSocketApi()
    {
        m_useRestApi = false;
        m_transport = null;
        return this;
    }

    /**
     * Returns true if the REST API is used, false for the socket API
     */
    public synchronized boolean isUsingRestApi()
    {
        return m_useRestApi;
    }

    /**
     * Sets the API token used to authenticate to the REST API. It is sent as Authorization: Bearer token
     *
     * @param apiToken The API token, as created with ezsign-manage
     * @return This EzSignClient instance
     */
    public synchronized EzSignClient useApiToken(String apiToken)
    {
        m_apiToken = apiToken == null || apiToken.trim().isEmpty() ? null : apiToken.trim();
        m_transport = null;
        return this;
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
            m_encrypt = new KEncrypt(authCode);
    }

    /**
     * Sets the host to use
     *
     * @param host The name of the host to connect to - IP address or hostname
     */
    public synchronized void setHost(String host)
    {
        m_host = host;
        m_transport = null;
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
    public synchronized void setPort(int port)
    {
        m_port = port;
        m_transport = null;
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
        checkChannel(channelName);
        if (dataToSign == null || dataToSign.length == 0)
            throw new KEzSignException("The data to sign was empty or null.  Cannot sign data");

        KTransport.Result result = transport().signData(channelName, dataToSign, isDigest);
        if (result.m_code == KEzSignRespMsg.RESP_SIGNING_EXCEPTION)
            throw new KSigningException(result.m_error);
        checkOk(result);
        return data(result);
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
        checkChannel(channelName);
        if (numBytes < 1)
            throw new KEzSignException("The number of random bytes must be at least 1");

        KTransport.Result result = transport().generateRandomBytes(channelName, numBytes);
        checkOk(result);
        return data(result);
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
        checkChannel(channelName);
        if (signature == null || signature.length == 0)
            throw new KEzSignException("The signature to verify was null or empty.  Cannot verify signature");
        if (contentBytes == null || contentBytes.length == 0)
            throw new KEzSignException("The content data to verify was null or empty.  Cannot verify signature");
        if (signatureType == KVerifySignatureReqMsg.SIG_TYPE_RAW && signerCert == null)
            throw new KEzSignException("The signer certificate was not " +
                    "provided.  The signer certificate is required in order to verify a raw signature");

        KTransport.Result result = transport().verifySignature(channelName, signature, contentBytes, dataIsDigest,
                bypassRevocationCheck, bypassPathBuild, signatureType, signerCert, otherCerts);
        switch (result.m_code)
        {
            case KEzSignRespMsg.RESP_VERIFICATION_EXCEPTION:
                throw new KVerificationException(result.m_error);
            case KEzSignRespMsg.RESP_REVOCATION_EXCEPTION:
                throw new KRevocationException(result.m_error);
            case KEzSignRespMsg.RESP_PATH_EXCEPTION:
                throw new KPathException(result.m_error);
            default:
                checkOk(result);
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
        return encipher(channelName, true, dataToEncrypt, keyLabel);
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
        return encipher(channelName, false, encryptedData, keyLabel);
    }

    private byte[] encipher(String channelName, boolean encrypt, byte[] data, String keyLabel)
            throws KEzSignException, KEzSignConnectException, KEncipherException
    {
        checkChannel(channelName);
        if (data == null || data.length == 0)
            throw new KEzSignException("The data to encipher was empty or null.  Cannot encipher data");

        KTransport.Result result = transport().encipher(channelName, encrypt, data, keyLabel);
        if (result.m_code == KEzSignRespMsg.RESP_ENCIPHER_EXCEPTION)
            throw new KEncipherException(result.m_error);
        checkOk(result);
        return data(result);
    }

    private static void checkChannel(String channelName) throws KEzSignException
    {
        if (channelName == null || channelName.isEmpty())
            throw new KEzSignException("Channel name is null or empty");
    }

    /**
     * Returns the data of a successful result. A result with no data is returned as an empty array, never null,
     * whichever API is used
     */
    private static byte[] data(KTransport.Result result)
    {
        return result.m_data == null ? new byte[0] : result.m_data;
    }

    /**
     * Throws a KEzSignException for any error not already handled. An unexpected response code is an error,
     * never a null result
     */
    private static void checkOk(KTransport.Result result) throws KEzSignException
    {
        if (result.m_code == KEzSignRespMsg.RESP_OK)
            return;
        if (result.m_error != null && !result.m_error.isEmpty())
            throw new KEzSignException(result.m_error);
        throw new KEzSignException("The server returned an error (response code " + result.m_code + ")");
    }

    /**
     * Returns the transport for the current settings, creating it if the settings have changed
     */
    synchronized KTransport transport() throws KEzSignException
    {
        if (m_transport != null)
            return m_transport;
        if (m_host == null || m_host.isEmpty())
            throw new KEzSignException("The host of the EzSign server has not been set");

        if (m_useRestApi)
        {
            if (m_encrypt != null)
                throw new KEzSignException("An auth code is only used by the socket API. The REST API uses TLS and an " +
                        "API token or client certificate instead: remove the auth code, or call useSocketApi()");
            if (m_apiToken == null && !m_tls.hasClientCertificate())
                throw new KEzSignException("The REST API requires the client to authenticate: call useApiToken() " +
                        "or useClientTls()");
            if (!m_restUseTls && m_apiToken == null)
                throw new KEzSignException("A client certificate can only be used over TLS");
            m_transport = new KRestTransport(m_host, m_port, m_restUseTls, m_connectTimeoutMs, m_readTimeoutMs, m_apiToken, m_tls);
        }
        else
        {
            if (m_apiToken != null)
                throw new KEzSignException("An API token is only used by the REST API: call useRestApi(), and set the " +
                        "port to the REST API port");
            m_transport = new KSocketTransport(m_host, m_port, m_connectTimeoutMs, m_readTimeoutMs, m_encrypt,
                    m_useTls ? m_tls : null);
        }
        return m_transport;
    }

    /**
     * Creates a client from settings in a properties file. See fromProperties(Properties)
     *
     * @param propertiesFile The properties file
     * @return The client
     * @throws KEzSignException If the file cannot be read or a setting is not valid
     */
    public static EzSignClient fromProperties(String propertiesFile) throws KEzSignException
    {
        Properties props = new Properties();
        try
        {
            InputStream is = new FileInputStream(propertiesFile);
            try
            {
                props.load(is);
            }
            finally
            {
                is.close();
            }
        }
        catch (IOException e)
        {
            throw new KEzSignException("Unable to read the EzSign client properties file " + propertiesFile + ". " + e.getMessage());
        }
        return fromProperties(props);
    }

    /**
     * Creates a client from settings, so the API (socket or REST) and its settings can be changed without
     * changing code:
     *
     *   ezsign.api                          socket (the default) or rest
     *   ezsign.host                         The server's host name or IP address (required)
     *   ezsign.port                         The socket API port or the REST API port (required)
     *   ezsign.connectTimeoutMs             Optional, default 5000
     *   ezsign.readTimeoutMs                Optional, default 5000
     *   ezsign.tls                          true to use TLS with the socket API. The REST API uses TLS unless false
     *   ezsign.authCode                     The socket API auth code (optional)
     *   ezsign.apiToken                     The REST API token
     *   ezsign.clientKeyStore               A client certificate key store (.p12 or .jks) for TLS client authentication
     *   ezsign.clientKeyStorePassword
     *   ezsign.clientKeyStoreType           PKCS12 (default) or JKS
     *   ezsign.trustStore                   CA certificates trusted to issue the server certificate (optional)
     *   ezsign.trustStorePassword
     *   ezsign.trustStoreType               PKCS12 (default) or JKS
     *   ezsign.verifyHostname               false to turn off the host name check (not recommended)
     *
     * Any secret (authCode, apiToken and the passwords) can instead be read from the first line of a file, by
     * adding File to its name, e.g. ezsign.apiTokenFile=/opt/app/ezsign-token.txt
     *
     * @param props The settings
     * @return The client
     * @throws KEzSignException If a setting is missing or not valid
     */
    public static EzSignClient fromProperties(Properties props) throws KEzSignException
    {
        String host = setting(props, PROP_HOST);
        if (host == null)
            throw new KEzSignException(PROP_HOST + " must be set");
        int port = intSetting(props, PROP_PORT, -1);
        if (port < 1 || port > 65535)
            throw new KEzSignException(PROP_PORT + " must be set to a port number");

        EzSignClient client = new EzSignClient(host, port, intSetting(props, PROP_CONNECT_TIMEOUT, 0),
                intSetting(props, PROP_READ_TIMEOUT, 0));

        String api = setting(props, PROP_API);
        boolean rest;
        if (api == null || api.equalsIgnoreCase(API_SOCKET))
            rest = false;
        else if (api.equalsIgnoreCase(API_REST))
            rest = true;
        else
            throw new KEzSignException(PROP_API + " must be " + API_SOCKET + " or " + API_REST);

        String tls = setting(props, PROP_TLS);
        if (tls != null && !tls.equalsIgnoreCase("true") && !tls.equalsIgnoreCase("false"))
            throw new KEzSignException(PROP_TLS + " must be true or false");
        if (rest)
            client.useRestApi(tls == null || tls.equalsIgnoreCase("true"));
        else if ("true".equalsIgnoreCase(tls))
            client.useTls();

        client.setAuthCode(secret(props, PROP_AUTH_CODE));
        client.useApiToken(secret(props, PROP_API_TOKEN));

        String trustStore = setting(props, PROP_TRUSTSTORE);
        if (trustStore != null)
            client.useTrustStore(trustStore, secret(props, PROP_TRUSTSTORE_PASSWORD), setting(props, PROP_TRUSTSTORE_TYPE));
        String clientKeyStore = setting(props, PROP_CLIENT_KEYSTORE);
        if (clientKeyStore != null)
            client.useClientTls(clientKeyStore, secret(props, PROP_CLIENT_KEYSTORE_PASSWORD), setting(props, PROP_CLIENT_KEYSTORE_TYPE));

        String verifyHostname = setting(props, PROP_VERIFY_HOSTNAME);
        if (verifyHostname != null)
            client.verifyHostname(!verifyHostname.equalsIgnoreCase("false"));

        // Report a mismatched setting (e.g. an API token with the socket API) now rather than on the first call
        client.transport();
        return client;
    }

    private static String setting(Properties props, String name)
    {
        String value = props.getProperty(name);
        return value == null || value.trim().isEmpty() ? null : value.trim();
    }

    private static int intSetting(Properties props, String name, int defaultValue) throws KEzSignException
    {
        String value = setting(props, name);
        if (value == null)
            return defaultValue;
        try
        {
            return Integer.parseInt(value);
        }
        catch (NumberFormatException e)
        {
            throw new KEzSignException(name + " must be a number");
        }
    }

    /**
     * Returns a secret setting, from the property or from the first line of the file named by the property
     * with File added to its name
     */
    private static String secret(Properties props, String name) throws KEzSignException
    {
        String value = props.getProperty(name);
        if (value != null && !value.isEmpty())
            return value;
        String file = setting(props, name + FILE_SUFFIX);
        if (file == null)
            return null;
        try
        {
            BufferedReader reader = new BufferedReader(new FileReader(file));
            try
            {
                String line = reader.readLine();
                return line == null || line.isEmpty() ? null : line;
            }
            finally
            {
                reader.close();
            }
        }
        catch (IOException e)
        {
            throw new KEzSignException("Unable to read " + name + FILE_SUFFIX + " " + file + ". " + e.getMessage());
        }
    }
}
/********************************************* END OF FILE *****************************************************
 ***************************************************************************************************************/
