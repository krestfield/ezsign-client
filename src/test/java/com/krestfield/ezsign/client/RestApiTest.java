package com.krestfield.ezsign.client;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the REST API against a stand-in server
 */
class RestApiTest
{
    static final byte[] RESULT = "result-bytes".getBytes(StandardCharsets.UTF_8);
    static final String B64_RESULT = Base64.getEncoder().encodeToString(RESULT);

    static Function<FakeServers.RestRequest, FakeServers.RestResponse> respond(final int status, final String body)
    {
        return new Function<FakeServers.RestRequest, FakeServers.RestResponse>()
        {
            public FakeServers.RestResponse apply(FakeServers.RestRequest request)
            {
                return new FakeServers.RestResponse(status, body);
            }
        };
    }

    static String error(String code, String message)
    {
        return "{\"error\":{\"code\":\"" + code + "\",\"message\":\"" + message + "\"}}";
    }

    static EzSignClient tokenClient(FakeServers.RestServer server) throws Exception
    {
        return new EzSignClient("localhost", server.port()).useRestApi().useApiToken("ezs_token")
                .useTrustStore(FakeServers.resource("truststore.p12"), "changeit", "PKCS12");
    }

    static Map<String, Object> body(FakeServers.RestRequest request) throws Exception
    {
        return KJson.parseObject(request.m_body);
    }

    @Test
    void sendsEachOperationAsJson() throws Exception
    {
        try (FakeServers.RestServer server = new FakeServers.RestServer(false, respond(200, "{\"signature\":\"" + B64_RESULT + "\"}")))
        {
            EzSignClient client = tokenClient(server);
            assertArrayEquals(RESULT, client.signData("SIGNING", "hello".getBytes(StandardCharsets.UTF_8), true));
            FakeServers.RestRequest r = server.last();
            assertEquals("POST", r.m_method);
            assertEquals("/v1/channels/SIGNING/sign", r.m_path);
            assertEquals("Bearer ezs_token", r.m_authorization);
            assertEquals("application/json", r.m_contentType);
            assertEquals("aGVsbG8=", body(r).get("data"));
            assertEquals(true, body(r).get("isDigest"));

            server.m_handler = respond(200, "{\"data\":\"" + B64_RESULT + "\"}");
            assertArrayEquals(RESULT, client.encryptData("AES KEYS", new byte[] {1}, "key1"));
            assertEquals("/v1/channels/AES%20KEYS/encrypt", server.last().m_path);
            assertEquals("key1", body(server.last()).get("keyLabel"));

            assertArrayEquals(RESULT, client.decryptData("AES", new byte[] {1}, null));
            assertEquals("/v1/channels/AES/decrypt", server.last().m_path);
            assertFalse(body(server.last()).containsKey("keyLabel"));

            assertArrayEquals(RESULT, client.generateRandomBytes("RNG", 32));
            assertEquals(32L, body(server.last()).get("numBytes"));

            server.m_handler = respond(200, "{\"verified\":true}");
            client.verifySignature("SIGNING", new byte[] {1}, new byte[] {2}, false, true, false);
            Map<String, Object> verify = body(server.last());
            assertEquals("pkcs7", verify.get("signatureType"));
            assertEquals(true, verify.get("bypassRevocationCheck"));
            assertEquals(false, verify.get("bypassPathBuild"));
        }
    }

    @Test
    void anEmptyResultIsAnEmptyArray() throws Exception
    {
        try (FakeServers.RestServer server = new FakeServers.RestServer(false, respond(200, "{\"data\":\"\"}")))
        {
            assertArrayEquals(new byte[0], tokenClient(server).decryptData("AES", new byte[16], null));
        }
    }

    @Test
    void sendsRawSignatureCertificates() throws Exception
    {
        X509Certificate ca = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(FakeServers.keyStore("truststore.p12").getCertificate("ca").getEncoded()));
        try (FakeServers.RestServer server = new FakeServers.RestServer(false, respond(200, "{\"verified\":true}")))
        {
            tokenClient(server).verifyRawSignature("SIGNING", new byte[] {1}, new byte[] {2}, false, ca, new X509Certificate[] {ca});
            Map<String, Object> verify = body(server.last());
            assertEquals("raw", verify.get("signatureType"));
            assertEquals(Base64.getEncoder().encodeToString(ca.getEncoded()), verify.get("signerCert"));
            assertEquals(1, ((List<?>) verify.get("otherCerts")).size());
        }
    }

    @Test
    void mapsErrorsToTheSameExceptionsAsTheSocketApi() throws Exception
    {
        try (FakeServers.RestServer server = new FakeServers.RestServer(false, respond(422, "{\"verified\":false," +
                error("VERIFICATION_FAILED", "The signature did not verify").substring(1))))
        {
            EzSignClient client = tokenClient(server);
            KVerificationException v = assertThrows(KVerificationException.class,
                    () -> client.verifySignature("SIGNING", new byte[] {1}, new byte[] {2}, false));
            assertEquals("The signature did not verify (HTTP 422, VERIFICATION_FAILED, transaction ID 12345678)", v.getMessage());

            server.m_handler = respond(422, error("PATH_VALIDATION_FAILED", "No path"));
            assertThrows(KPathException.class, () -> client.verifySignature("SIGNING", new byte[] {1}, new byte[] {2}, false));
            server.m_handler = respond(422, error("REVOCATION_CHECK_FAILED", "Revoked"));
            assertThrows(KRevocationException.class, () -> client.verifySignature("SIGNING", new byte[] {1}, new byte[] {2}, false));
            server.m_handler = respond(500, error("SIGNING_FAILED", "HSM error"));
            assertThrows(KSigningException.class, () -> client.signData("SIGNING", new byte[] {1}, false));
            server.m_handler = respond(422, error("DECRYPTION_FAILED", "Bad padding"));
            assertThrows(KEncipherException.class, () -> client.decryptData("AES", new byte[] {1}, null));

            server.m_handler = respond(401, error("UNAUTHORIZED", "The API token was not recognised"));
            KEzSignException e = assertThrows(KEzSignException.class, () -> client.generateRandomBytes("RNG", 8));
            assertTrue(e.getMessage().startsWith("Authentication failed. The API token was not recognised (HTTP 401"), e.getMessage());

            server.m_handler = respond(403, error("FORBIDDEN", "User app does not have the sign permission on channel SIGNING"));
            e = assertThrows(KEzSignException.class, () -> client.signData("SIGNING", new byte[] {1}, false));
            assertTrue(e.getMessage().startsWith("Not permitted. User app does not have the sign permission"), e.getMessage());

            server.m_handler = respond(503, error("BUSY", "All instances are busy"));
            assertThrows(KEzSignException.class, () -> client.signData("SIGNING", new byte[] {1}, false));

            // Not the REST API (e.g. the wrong port)
            server.m_handler = respond(200, "not json");
            e = assertThrows(KEzSignException.class, () -> client.signData("SIGNING", new byte[] {1}, false));
            assertTrue(e.getMessage().contains("not valid JSON"), e.getMessage());
        }
    }

    @Test
    void authenticatesWithAClientCertificate() throws Exception
    {
        try (FakeServers.RestServer server = new FakeServers.RestServer(true, respond(200, "{\"data\":\"" + B64_RESULT + "\"}")))
        {
            EzSignClient client = new EzSignClient("localhost", server.port()).useRestApi()
                    .useClientTls(FakeServers.resource("client.p12"), "changeit", "PKCS12")
                    .useTrustStore(FakeServers.resource("truststore.p12"), "changeit", "PKCS12");
            assertArrayEquals(RESULT, client.generateRandomBytes("RNG", 12));
            assertNull(server.last().m_authorization);

            // Without the certificate the server refuses the handshake
            EzSignClient noCert = tokenClient(server);
            KEzSignConnectException e = assertThrows(KEzSignConnectException.class, () -> noCert.generateRandomBytes("RNG", 12));
            assertTrue(e.getMessage().contains("EzSign REST API"), e.getMessage());
        }
    }

    @Test
    void checksTheServerCertificateAndHostName() throws Exception
    {
        try (FakeServers.RestServer server = new FakeServers.RestServer(false, respond(200, "{\"data\":\"" + B64_RESULT + "\"}")))
        {
            String trustStore = FakeServers.resource("truststore.p12");
            EzSignClient byIp = new EzSignClient("127.0.0.1", server.port()).useRestApi().useApiToken("t")
                    .useTrustStore(trustStore, "changeit", "PKCS12");
            KEzSignConnectException e = assertThrows(KEzSignConnectException.class, () -> byIp.generateRandomBytes("RNG", 8));
            assertTrue(e.getMessage().contains("valid for the host name"), e.getMessage());
            byIp.verifyHostname(false);
            assertArrayEquals(RESULT, byIp.generateRandomBytes("RNG", 8));

            EzSignClient untrusted = new EzSignClient("localhost", server.port()).useRestApi().useApiToken("t");
            assertThrows(KEzSignConnectException.class, () -> untrusted.generateRandomBytes("RNG", 8));
        }
    }

    @Test
    void theSameClientCanSwitchBetweenApis() throws Exception
    {
        try (FakeServers.RestServer rest = new FakeServers.RestServer(false, respond(200, "{\"data\":\"" + B64_RESULT + "\"}"));
             FakeServers.SocketServer socket = new FakeServers.SocketServer(false, SocketApiTest.respond("DNAR~0~" + B64_RESULT)))
        {
            EzSignClient client = new EzSignClient("localhost", socket.port());
            assertArrayEquals(RESULT, client.generateRandomBytes("RNG", 8));

            client.useRestApi().useApiToken("ezs_token").useTrustStore(FakeServers.resource("truststore.p12"), "changeit", "PKCS12");
            client.setPort(rest.port());
            assertArrayEquals(RESULT, client.generateRandomBytes("RNG", 8));
            assertEquals(1, rest.m_received.size());

            // Back to the socket API: the token must be removed, as it is only used by the REST API
            client.useSocketApi().useApiToken(null);
            client.setPort(socket.port());
            assertArrayEquals(RESULT, client.generateRandomBytes("RNG", 8));
            assertEquals(2, socket.m_received.size());
        }
    }
}
