package com.krestfield.ezsign.client;

import com.krestfield.ezsign.client.msg.KEzSignRespMsg;
import com.krestfield.ezsign.client.msg.KVerifySignatureReqMsg;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * KRestTransport
 *
 * Sends requests to the server's REST API (HTTPS and JSON). The client authenticates with an API token
 * (Authorization: Bearer) and/or a TLS client certificate. Requests may be sent from several threads at once,
 * and connections are reused.
 *
 * REST errors are reported with the socket API's response codes, so EzSignClient throws the same exceptions
 * for both APIs
 *
 * Copyright (C) 2026 Krestfield Ltd - All Rights Reserved
 */
class KRestTransport implements KTransport
{
    static final String API_PATH = "/v1/channels/";
    static final String HEADER_TRANS_ID = "X-Transaction-Id";

    // Accepts any host name, used only when host name checking has been turned off
    private static final HostnameVerifier ANY_HOST = new HostnameVerifier()
    {
        public boolean verify(String hostname, SSLSession session)
        {
            return true;
        }
    };

    private final String m_baseUrl;
    private final String m_apiToken;
    private final int m_connectTimeoutMs;
    private final int m_readTimeoutMs;
    private final KTlsConfig m_tls;

    /**
     * @param useTls Whether to use HTTPS. Only turned off for a server with server.restapi.useTls=false
     * @param apiToken The API token, or null to authenticate with the client certificate
     * @param tls The TLS settings
     */
    KRestTransport(String host, int port, boolean useTls, int connectTimeoutMs, int readTimeoutMs, String apiToken, KTlsConfig tls)
    {
        String hostPart = host.indexOf(':') >= 0 && !host.startsWith("[") ? "[" + host + "]" : host;
        m_baseUrl = (useTls ? "https://" : "http://") + hostPart + ":" + port;
        m_apiToken = apiToken;
        m_connectTimeoutMs = connectTimeoutMs;
        m_readTimeoutMs = readTimeoutMs;
        m_tls = useTls ? tls : null;
    }

    String getBaseUrl()
    {
        return m_baseUrl;
    }

    public Result signData(String channelName, byte[] dataToSign, boolean isDigest) throws KEzSignException, KEzSignConnectException
    {
        Map<String, Object> request = new LinkedHashMap<String, Object>();
        request.put("data", base64(dataToSign));
        request.put("isDigest", isDigest);
        return call(channelName, "sign", request, "signature");
    }

    public Result generateRandomBytes(String channelName, int numBytes) throws KEzSignException, KEzSignConnectException
    {
        Map<String, Object> request = new LinkedHashMap<String, Object>();
        request.put("numBytes", numBytes);
        return call(channelName, "random", request, "data");
    }

    public Result verifySignature(String channelName, byte[] signature, byte[] contentBytes, boolean dataIsDigest,
                                  boolean bypassRevocationCheck, boolean bypassPathBuild, int signatureType,
                                  X509Certificate signerCert, X509Certificate[] otherCerts) throws KEzSignException, KEzSignConnectException
    {
        Map<String, Object> request = new LinkedHashMap<String, Object>();
        request.put("signature", base64(signature));
        if (contentBytes != null)
            request.put("content", base64(contentBytes));
        request.put("isDigest", dataIsDigest);
        request.put("bypassRevocationCheck", bypassRevocationCheck);
        request.put("bypassPathBuild", bypassPathBuild);
        if (signatureType == KVerifySignatureReqMsg.SIG_TYPE_RAW)
        {
            request.put("signatureType", "raw");
            request.put("signerCert", base64(encoded(signerCert)));
            if (otherCerts != null && otherCerts.length > 0)
            {
                List<String> others = new ArrayList<String>();
                for (X509Certificate cert : otherCerts)
                    others.add(base64(encoded(cert)));
                request.put("otherCerts", others);
            }
        }
        else
            request.put("signatureType", "pkcs7");
        return call(channelName, "verify", request, null);
    }

    public Result encipher(String channelName, boolean encrypt, byte[] data, String keyLabel) throws KEzSignException, KEzSignConnectException
    {
        Map<String, Object> request = new LinkedHashMap<String, Object>();
        request.put("data", base64(data));
        if (keyLabel != null && !keyLabel.isEmpty())
            request.put("keyLabel", keyLabel);
        return call(channelName, encrypt ? "encrypt" : "decrypt", request, "data");
    }

    private static String base64(byte[] data)
    {
        return Base64.getEncoder().encodeToString(data);
    }

    private static byte[] encoded(X509Certificate cert) throws KEzSignException
    {
        try
        {
            return cert.getEncoded();
        }
        catch (Exception e)
        {
            throw new KEzSignException("There was an error extracting the data from the certificate. Check the certificate is valid");
        }
    }

    /**
     * Encodes the channel name for the request path
     */
    static String pathSegment(String channelName) throws KEzSignException
    {
        try
        {
            return URLEncoder.encode(channelName, "UTF-8").replace("+", "%20");
        }
        catch (Exception e)
        {
            throw new KEzSignException("The channel name could not be encoded. " + e.getMessage());
        }
    }

    /**
     * Posts the request and returns the result
     *
     * @param resultField The response field holding the result (base64), or null if there is none
     */
    private Result call(String channelName, String operation, Map<String, Object> request, String resultField)
            throws KEzSignException, KEzSignConnectException
    {
        String url = m_baseUrl + API_PATH + pathSegment(channelName) + "/" + operation;
        HttpURLConnection conn = null;
        int status;
        String body;
        String transId;
        try
        {
            conn = (HttpURLConnection) new URL(url).openConnection();
            if (conn instanceof HttpsURLConnection)
            {
                HttpsURLConnection https = (HttpsURLConnection) conn;
                https.setSSLSocketFactory(m_tls.context().getSocketFactory());
                if (!m_tls.isVerifyHostname())
                    https.setHostnameVerifier(ANY_HOST);
            }
            conn.setConnectTimeout(m_connectTimeoutMs);
            conn.setReadTimeout(m_readTimeoutMs);
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");
            if (m_apiToken != null)
                conn.setRequestProperty("Authorization", "Bearer " + m_apiToken);

            // Not streamed: HttpURLConnection then keeps the body of a 401 response, which explains the failure
            byte[] requestBytes = KJson.write(request).getBytes(StandardCharsets.UTF_8);
            OutputStream os = conn.getOutputStream();
            try
            {
                os.write(requestBytes);
            }
            finally
            {
                os.close();
            }

            status = conn.getResponseCode();
            transId = conn.getHeaderField(HEADER_TRANS_ID);
            body = read(status < 400 ? conn.getInputStream() : conn.getErrorStream());
        }
        catch (SSLException e)
        {
            throw new KEzSignConnectException("The TLS connection to the EzSign REST API at " + m_baseUrl + " failed. " +
                    "Check the server's certificate is trusted and is valid for the host name used" +
                    (m_tls.hasClientCertificate() ? ", and the client certificate is issued by a CA the server trusts" : "") +
                    ". " + e.getMessage());
        }
        catch (IOException e)
        {
            throw new KEzSignConnectException("There was an error connecting to the EzSign REST API at " + m_baseUrl +
                    ". Ensure the server is running with the REST API enabled on this port and there is connectivity " +
                    "between this client and the server. " + e.getMessage());
        }

        Map<String, Object> response;
        try
        {
            response = body.isEmpty() ? new LinkedHashMap<String, Object>() : KJson.parseObject(body);
        }
        catch (KJson.KJsonException e)
        {
            throw new KEzSignException("The response from the EzSign REST API was not valid JSON (HTTP " + status + ")" +
                    transIdText(transId) + ". Check the port is the REST API port. " + e.getMessage());
        }

        if (status == 200)
        {
            if (resultField == null)
                return Result.ok(null);
            Object value = response.get(resultField);
            if (!(value instanceof String))
                throw new KEzSignException("The response from the EzSign REST API did not contain " + resultField + transIdText(transId));
            try
            {
                return Result.ok(Base64.getDecoder().decode((String) value));
            }
            catch (IllegalArgumentException e)
            {
                throw new KEzSignException("The " + resultField + " returned by the EzSign REST API was not valid base64" + transIdText(transId));
            }
        }
        return error(status, response, transId);
    }

    /**
     * Converts an error response to the socket API's response code and an error message
     */
    static Result error(int status, Map<String, Object> response, String transId)
    {
        String code = null;
        String message = null;
        Object error = response.get("error");
        if (error instanceof Map)
        {
            Object c = ((Map<?, ?>) error).get("code");
            Object m = ((Map<?, ?>) error).get("message");
            code = c instanceof String ? (String) c : null;
            message = m instanceof String ? (String) m : null;
        }
        if (message == null)
            message = "The EzSign REST API returned HTTP " + status;

        String prefix = "";
        if (status == 401)
            prefix = "Authentication failed. ";
        else if (status == 403)
            prefix = "Not permitted. ";

        String details = message + " (HTTP " + status + (code != null ? ", " + code : "") + transIdText(transId) + ")";
        return new Result(responseCode(code), prefix + details, null);
    }

    static int responseCode(String restCode)
    {
        if (restCode == null)
            return KEzSignRespMsg.RESP_GENERAL_EXCEPTION;
        if (restCode.equals("SIGNING_FAILED"))
            return KEzSignRespMsg.RESP_SIGNING_EXCEPTION;
        if (restCode.equals("VERIFICATION_FAILED"))
            return KEzSignRespMsg.RESP_VERIFICATION_EXCEPTION;
        if (restCode.equals("PATH_VALIDATION_FAILED"))
            return KEzSignRespMsg.RESP_PATH_EXCEPTION;
        if (restCode.equals("REVOCATION_CHECK_FAILED"))
            return KEzSignRespMsg.RESP_REVOCATION_EXCEPTION;
        if (restCode.equals("ENCRYPTION_FAILED") || restCode.equals("DECRYPTION_FAILED"))
            return KEzSignRespMsg.RESP_ENCIPHER_EXCEPTION;
        return KEzSignRespMsg.RESP_GENERAL_EXCEPTION;
    }

    private static String transIdText(String transId)
    {
        return transId == null ? "" : ", transaction ID " + transId;
    }

    private static String read(InputStream is) throws IOException
    {
        if (is == null)
            return "";
        try
        {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int n;
            while ((n = is.read(buffer)) != -1)
                out.write(buffer, 0, n);
            return new String(out.toByteArray(), StandardCharsets.UTF_8).trim();
        }
        finally
        {
            is.close();
        }
    }
}
/********************************************* END OF FILE *****************************************************
 ***************************************************************************************************************/
