package com.krestfield.ezsign.client;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * KTlsConfig
 *
 * The TLS settings used to connect to the server, by either API: the client certificate (if any), the CAs
 * trusted to issue the server's certificate, and whether the server's host name is checked
 *
 * Copyright (C) 2026 Krestfield Ltd - All Rights Reserved
 */
class KTlsConfig
{
    // The protocols used, newest first. Older protocols are not offered
    static final List<String> PROTOCOLS = Arrays.asList("TLSv1.3", "TLSv1.2");

    private KeyManager[] m_keyManagers = null;
    private TrustManager[] m_trustManagers = null;
    private boolean m_verifyHostname = true;
    private SSLContext m_context = null;

    /**
     * Loads the client certificate and key used to authenticate to the server
     */
    synchronized void setClientKeyStore(String filename, String password, String type) throws KEzSignException
    {
        try
        {
            KeyStore keyStore = load(filename, password, type);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, password == null ? new char[0] : password.toCharArray());
            m_keyManagers = kmf.getKeyManagers();
            m_context = null;
        }
        catch (Exception e)
        {
            throw new KEzSignException("There was an error loading the client key store " + filename + ". " + e.getMessage());
        }
    }

    /**
     * Loads the CA certificates trusted to issue the server's certificate. Without this the Java default
     * trust store (cacerts, or javax.net.ssl.trustStore) is used
     */
    synchronized void setTrustStore(String filename, String password, String type) throws KEzSignException
    {
        try
        {
            KeyStore trustStore = load(filename, password, type);
            if (trustStore.size() == 0)
                throw new KEzSignException("It contains no certificates");
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            m_trustManagers = tmf.getTrustManagers();
            m_context = null;
        }
        catch (Exception e)
        {
            throw new KEzSignException("There was an error loading the trust store " + filename + ". " + e.getMessage());
        }
    }

    private static KeyStore load(String filename, String password, String type) throws Exception
    {
        KeyStore keyStore = KeyStore.getInstance(type == null || type.isEmpty() ? "PKCS12" : type);
        InputStream is = new FileInputStream(filename);
        try
        {
            keyStore.load(is, password == null ? null : password.toCharArray());
        }
        finally
        {
            is.close();
        }
        return keyStore;
    }

    synchronized void setVerifyHostname(boolean verify)
    {
        m_verifyHostname = verify;
    }

    synchronized boolean isVerifyHostname()
    {
        return m_verifyHostname;
    }

    synchronized boolean hasClientCertificate()
    {
        return m_keyManagers != null;
    }

    /**
     * Returns the TLS context built from the settings
     */
    synchronized SSLContext context() throws KEzSignException
    {
        if (m_context == null)
        {
            try
            {
                if (m_keyManagers == null && m_trustManagers == null)
                {
                    // Nothing set on the client: the JVM default, which also reads the javax.net.ssl.keyStore and
                    // trustStore system properties, as earlier versions did
                    m_context = SSLContext.getDefault();
                }
                else
                {
                    SSLContext context = SSLContext.getInstance("TLS");
                    context.init(m_keyManagers, m_trustManagers, null);
                    m_context = context;
                }
            }
            catch (Exception e)
            {
                throw new KEzSignException("There was an error creating the TLS context. " + e.getMessage());
            }
        }
        return m_context;
    }

    /**
     * Applies the protocols and, unless turned off, the host name check to a connection's parameters
     */
    void apply(SSLParameters params)
    {
        List<String> protocols = new ArrayList<String>();
        for (String supported : params.getProtocols())
            if (PROTOCOLS.contains(supported))
                protocols.add(supported);
        if (!protocols.isEmpty())
            params.setProtocols(protocols.toArray(new String[0]));
        if (isVerifyHostname())
            params.setEndpointIdentificationAlgorithm("HTTPS");
    }
}
/********************************************* END OF FILE *****************************************************
 ***************************************************************************************************************/
