package com.krestfield.ezsign.client;

import com.krestfield.ezsign.client.msg.KEzSignRespMsg;
import com.krestfield.ezsign.client.msg.KSignDataRespMsg;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the client settings, fromProperties, the JSON support and response parsing
 */
class ClientSettingsTest
{
    @TempDir
    File m_dir;

    @Test
    void refusesSettingsForTheOtherApi() throws Exception
    {
        KEzSignException e = assertThrows(KEzSignException.class,
                () -> new EzSignClient("localhost", 5656).useApiToken("t").generateRandomBytes("RNG", 8));
        assertTrue(e.getMessage().contains("only used by the REST API"), e.getMessage());

        e = assertThrows(KEzSignException.class,
                () -> new EzSignClient("localhost", 8443, "authcode").useRestApi().useApiToken("t").generateRandomBytes("RNG", 8));
        assertTrue(e.getMessage().contains("auth code is only used by the socket API"), e.getMessage());

        e = assertThrows(KEzSignException.class, () -> new EzSignClient("localhost", 8443).useRestApi().generateRandomBytes("RNG", 8));
        assertTrue(e.getMessage().contains("call useApiToken() or useClientTls()"), e.getMessage());
    }

    @Test
    void validatesArgumentsTheSameWayForBothApis() throws Exception
    {
        for (EzSignClient client : Arrays.asList(new EzSignClient("localhost", 1), new EzSignClient("localhost", 1).useRestApi().useApiToken("t")))
        {
            assertThrows(KEzSignException.class, () -> client.signData("SIGNING", new byte[0], false));
            assertThrows(KEzSignException.class, () -> client.signData("", new byte[] {1}, false));
            assertThrows(KEzSignException.class, () -> client.verifySignature("SIGNING", new byte[] {1}, null, false));
            assertThrows(KEzSignException.class, () -> client.verifyRawSignature("SIGNING", new byte[] {1}, new byte[] {1}, false, null));
            assertThrows(KEzSignException.class, () -> client.encryptData("AES", null, "k"));
            assertThrows(KEzSignException.class, () -> client.generateRandomBytes("RNG", 0));
        }
    }

    Properties props(String... pairs)
    {
        Properties p = new Properties();
        for (int i = 0; i < pairs.length; i += 2)
            p.setProperty(pairs[i], pairs[i + 1]);
        return p;
    }

    @Test
    void createsAClientFromProperties() throws Exception
    {
        EzSignClient socket = EzSignClient.fromProperties(props("ezsign.host", "10.0.0.5", "ezsign.port", "5656"));
        assertFalse(socket.isUsingRestApi());
        assertEquals("10.0.0.5", socket.getHost());
        assertTrue(socket.transport() instanceof KSocketTransport);

        File tokenFile = new File(m_dir, "token.txt");
        Files.write(tokenFile.toPath(), "ezs_from_file\n".getBytes(StandardCharsets.UTF_8));
        EzSignClient rest = EzSignClient.fromProperties(props("ezsign.api", "REST", "ezsign.host", "ezsign.example.com",
                "ezsign.port", "8443", "ezsign.apiTokenFile", tokenFile.getPath(), "ezsign.readTimeoutMs", "30000",
                "ezsign.trustStore", FakeServers.resource("truststore.p12"), "ezsign.trustStorePassword", "changeit"));
        assertTrue(rest.isUsingRestApi());
        assertEquals("ezs_from_file", rest.m_apiToken);
        assertEquals(30000, rest.m_readTimeoutMs);
        assertEquals("https://ezsign.example.com:8443", ((KRestTransport) rest.transport()).getBaseUrl());

        // A properties file
        File file = new File(m_dir, "client.properties");
        Files.write(file.toPath(), "ezsign.api=socket\nezsign.host=localhost\nezsign.port=5656\nezsign.authCode=abc\nezsign.tls=true\n"
                .getBytes(StandardCharsets.UTF_8));
        EzSignClient fromFile = EzSignClient.fromProperties(file.getPath());
        assertTrue(fromFile.m_useTls);
        assertTrue(fromFile.m_encrypt != null);
    }

    @Test
    void reportsInvalidProperties() throws Exception
    {
        assertMessage("ezsign.host must be set", props("ezsign.port", "1"));
        assertMessage("ezsign.port must be set", props("ezsign.host", "h"));
        assertMessage("ezsign.api must be socket or rest", props("ezsign.host", "h", "ezsign.port", "1", "ezsign.api", "soap"));
        assertMessage("ezsign.tls must be true or false", props("ezsign.host", "h", "ezsign.port", "1", "ezsign.tls", "yes"));
        // Checked when the client is created, not on the first call
        assertMessage("only used by the REST API", props("ezsign.host", "h", "ezsign.port", "1", "ezsign.apiToken", "t"));
        assertMessage("Unable to read ezsign.apiTokenFile", props("ezsign.host", "h", "ezsign.port", "1", "ezsign.api", "rest",
                "ezsign.apiTokenFile", new File(m_dir, "missing").getPath()));
    }

    void assertMessage(String expected, Properties p)
    {
        KEzSignException e = assertThrows(KEzSignException.class, () -> EzSignClient.fromProperties(p));
        assertTrue(e.getMessage().contains(expected), e.getMessage());
    }

    @Test
    void writesAndReadsJson() throws Exception
    {
        Map<String, Object> m = new LinkedHashMap<String, Object>();
        m.put("s", "a\"b\\c\n\u0001é");
        m.put("n", 32);
        m.put("b", true);
        m.put("l", Arrays.asList("x", "y"));
        String json = KJson.write(m);
        assertEquals("{\"s\":\"a\\\"b\\\\c\\n\\u0001é\",\"n\":32,\"b\":true,\"l\":[\"x\",\"y\"]}", json);
        Map<String, Object> back = KJson.parseObject(json);
        assertEquals("a\"b\\c\n\u0001é", back.get("s"));
        assertEquals(32L, back.get("n"));
        assertEquals(true, back.get("b"));
        assertEquals(Arrays.asList("x", "y"), back.get("l"));
        assertEquals(1.5, KJson.parseObject(" { \"d\" : 1.5 , \"z\" : null } ").get("d"));
        assertThrows(KJson.KJsonException.class, () -> KJson.parseObject("{\"a\":1"));
        assertThrows(KJson.KJsonException.class, () -> KJson.parseObject("[1]"));
        assertThrows(KJson.KJsonException.class, () -> KJson.parseObject("{} x"));
    }

    @Test
    void parsesResponses() throws Exception
    {
        KSignDataRespMsg ok = new KSignDataRespMsg("NGIS~0~aGVsbG8=");
        assertEquals("hello", new String(ok.getSignature(), StandardCharsets.UTF_8));
        assertEquals("NGIS", ok.getReturnedMessageId());

        KEzSignRespMsg error = new KEzSignRespMsg("IREV~3~a~b~c");
        assertEquals(3, error.getResponseCode());
        assertEquals("a~b~c", error.getErrorMessage());
    }
}
