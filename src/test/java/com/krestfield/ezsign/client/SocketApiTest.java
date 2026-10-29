package com.krestfield.ezsign.client;

import com.krestfield.ezsign.client.utils.KEncrypt;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the socket API against a stand-in server
 */
class SocketApiTest
{
    static final byte[] SIGNATURE = "signature-bytes".getBytes(StandardCharsets.UTF_8);
    static final String B64_SIGNATURE = Base64.getEncoder().encodeToString(SIGNATURE);

    static Function<String, String> respond(final String response)
    {
        return new Function<String, String>()
        {
            public String apply(String request)
            {
                return response;
            }
        };
    }

    @Test
    void sendsRequestsAndReadsResponses() throws Exception
    {
        try (FakeServers.SocketServer server = new FakeServers.SocketServer(false, respond("NGIS~0~" + B64_SIGNATURE)))
        {
            EzSignClient client = new EzSignClient("127.0.0.1", server.port());
            assertArrayEquals(SIGNATURE, client.signData("SIGNING", "hello".getBytes(StandardCharsets.UTF_8), false));
            assertEquals("SIGN~SIGNING~aGVsbG8=~0~ ~ ~ ", server.m_received.get(0));

            server.m_handler = respond("ICNE~0~" + B64_SIGNATURE);
            assertArrayEquals(SIGNATURE, client.encryptData("AES", "x".getBytes(StandardCharsets.UTF_8), "key1"));
            assertEquals("ENCI~AES~1~eA==~key1", server.m_received.get(1));

            server.m_handler = respond("IREV~0");
            client.verifySignature("SIGNING", SIGNATURE, "hello".getBytes(StandardCharsets.UTF_8), false);
        }
    }

    @Test
    void reportsErrorsAsTheDeclaredExceptions() throws Exception
    {
        try (FakeServers.SocketServer server = new FakeServers.SocketServer(false, respond("NGIS~2~The key was not found")))
        {
            EzSignClient client = new EzSignClient("127.0.0.1", server.port());
            KSigningException e = assertThrows(KSigningException.class, () -> client.signData("SIGNING", new byte[] {1}, false));
            assertEquals("The key was not found", e.getMessage());

            // An error message containing the delimiter is kept whole
            server.m_handler = respond("IREV~3~Signature invalid~ hash mismatch");
            KVerificationException v = assertThrows(KVerificationException.class,
                    () -> client.verifySignature("SIGNING", new byte[] {1}, new byte[] {2}, false));
            assertEquals("Signature invalid~ hash mismatch", v.getMessage());

            server.m_handler = respond("IREV~5~No path");
            assertThrows(KPathException.class, () -> client.verifySignature("SIGNING", new byte[] {1}, new byte[] {2}, false));
            server.m_handler = respond("IREV~4~Revoked");
            assertThrows(KRevocationException.class, () -> client.verifySignature("SIGNING", new byte[] {1}, new byte[] {2}, false));
            server.m_handler = respond("ICNE~6~Bad key");
            assertThrows(KEncipherException.class, () -> client.decryptData("AES", new byte[] {1}, null));
        }
    }

    @Test
    void anUnexpectedResponseCodeIsAnErrorNotANullResult() throws Exception
    {
        // Previously signData returned null for any code other than 1 or 2
        try (FakeServers.SocketServer server = new FakeServers.SocketServer(false, respond("NGIS~3~Something else")))
        {
            EzSignClient client = new EzSignClient("127.0.0.1", server.port());
            KEzSignException e = assertThrows(KEzSignException.class, () -> client.signData("SIGNING", new byte[] {1}, false));
            assertEquals("Something else", e.getMessage());

            server.m_handler = respond("DNAR~6~Odd");
            assertThrows(KEzSignException.class, () -> client.generateRandomBytes("SIGNING", 8));

            server.m_handler = respond("NGIS~x~bad");
            e = assertThrows(KEzSignException.class, () -> client.signData("SIGNING", new byte[] {1}, false));
            assertTrue(e.getMessage().contains("response code was not a number"), e.getMessage());
        }
    }

    @Test
    void anEmptyResultIsAnEmptyArray() throws Exception
    {
        try (FakeServers.SocketServer server = new FakeServers.SocketServer(false, respond("ICNE~0~")))
        {
            EzSignClient client = new EzSignClient("127.0.0.1", server.port());
            assertArrayEquals(new byte[0], client.decryptData("AES", new byte[16], null));
        }
    }

    @Test
    void checksTheResponseIsForTheRequest() throws Exception
    {
        try (FakeServers.SocketServer server = new FakeServers.SocketServer(false, respond("DNAR~0~" + B64_SIGNATURE)))
        {
            EzSignClient client = new EzSignClient("127.0.0.1", server.port());
            KEzSignException e = assertThrows(KEzSignException.class, () -> client.signData("SIGNING", new byte[] {1}, false));
            assertTrue(e.getMessage().contains("message ID returned was not expected"), e.getMessage());

            // The server's response when it cannot process the request, e.g. when busy
            server.m_handler = respond("UKNW~1~All instances are busy");
            e = assertThrows(KEzSignException.class, () -> client.signData("SIGNING", new byte[] {1}, false));
            assertEquals("All instances are busy", e.getMessage());
        }
    }

    @Test
    void rejectsValuesThatWouldChangeTheMessage() throws Exception
    {
        try (FakeServers.SocketServer server = new FakeServers.SocketServer(false, respond("ICNE~0~" + B64_SIGNATURE)))
        {
            EzSignClient client = new EzSignClient("127.0.0.1", server.port());
            KEzSignException e = assertThrows(KEzSignException.class, () -> client.encryptData("AES", new byte[] {1}, "key1~1~x"));
            assertTrue(e.getMessage().contains("key label cannot contain"), e.getMessage());
            assertThrows(KEzSignException.class, () -> client.encryptData("AES\nSIGN", new byte[] {1}, null));
            assertThrows(KEzSignException.class, () -> client.signData("A~B", new byte[] {1}, false));
            // Nothing was sent
            assertEquals(0, server.m_received.size());
        }
    }

    @Test
    void encryptsWithTheAuthCode() throws Exception
    {
        final KEncrypt serverCode = new KEncrypt("auth-code-1");
        Function<String, String> handler = new Function<String, String>()
        {
            public String apply(String request)
            {
                try
                {
                    String clear = serverCode.decryptData(request);
                    if (!clear.startsWith("RAND~"))
                        return null;
                    return serverCode.encryptData("DNAR~0~" + B64_SIGNATURE);
                }
                catch (Exception e)
                {
                    // As the server: a request it cannot decrypt gets no response
                    return null;
                }
            }
        };
        try (FakeServers.SocketServer server = new FakeServers.SocketServer(false, handler))
        {
            EzSignClient client = new EzSignClient("127.0.0.1", server.port(), "auth-code-1");
            assertArrayEquals(SIGNATURE, client.generateRandomBytes("RNG", 15));
            assertTrue(!server.m_received.get(0).contains("RAND"), "The request is encrypted");

            EzSignClient wrong = new EzSignClient("127.0.0.1", server.port(), "auth-code-2");
            KEzSignConnectException e = assertThrows(KEzSignConnectException.class, () -> wrong.generateRandomBytes("RNG", 15));
            assertTrue(e.getMessage().contains("closed the connection without responding"), e.getMessage());
            assertTrue(e.getMessage().contains("same auth code"), e.getMessage());
        }
    }

    @Test
    void reportsWhenTheServerIsNotListening() throws Exception
    {
        int port;
        try (FakeServers.SocketServer server = new FakeServers.SocketServer(false, respond("x")))
        {
            port = server.port();
        }
        EzSignClient client = new EzSignClient("127.0.0.1", port, 1000, 1000);
        KEzSignConnectException e = assertThrows(KEzSignConnectException.class, () -> client.generateRandomBytes("RNG", 8));
        assertTrue(e.getMessage().contains("Ensure the server is running on host 127.0.0.1"), e.getMessage());
    }

    @Test
    void tlsChecksTheServerCertificateAndHostName() throws Exception
    {
        try (FakeServers.SocketServer server = new FakeServers.SocketServer(true, respond("DNAR~0~" + B64_SIGNATURE)))
        {
            String trustStore = FakeServers.resource("truststore.p12");

            // The certificate is for localhost
            EzSignClient client = new EzSignClient("localhost", server.port()).useTls().useTrustStore(trustStore, "changeit", "PKCS12");
            assertArrayEquals(SIGNATURE, client.generateRandomBytes("RNG", 15));

            // Connecting by IP address does not match the certificate
            EzSignClient byIp = new EzSignClient("127.0.0.1", server.port()).useTls().useTrustStore(trustStore, "changeit", "PKCS12");
            KEzSignConnectException e = assertThrows(KEzSignConnectException.class, () -> byIp.generateRandomBytes("RNG", 15));
            assertTrue(e.getMessage().contains("TLS connection"), e.getMessage());

            // ...unless the check is turned off
            byIp.verifyHostname(false);
            assertArrayEquals(SIGNATURE, byIp.generateRandomBytes("RNG", 15));

            // The test CA is not in the Java trust store
            EzSignClient untrusted = new EzSignClient("localhost", server.port()).useTls();
            assertThrows(KEzSignConnectException.class, () -> untrusted.generateRandomBytes("RNG", 15));
        }
    }
}
