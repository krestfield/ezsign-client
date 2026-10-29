package com.krestfield.ezsign.client;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

/**
 * Stand-ins for the EzSign server's socket and REST APIs, so the client can be tested without a server
 */
class FakeServers
{
    static final char[] PASSWORD = "changeit".toCharArray();

    static String resource(String name)
    {
        return FakeServers.class.getResource("/tls/" + name).getPath();
    }

    static KeyStore keyStore(String name) throws Exception
    {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        InputStream is = FakeServers.class.getResourceAsStream("/tls/" + name);
        try
        {
            ks.load(is, PASSWORD);
        }
        finally
        {
            is.close();
        }
        return ks;
    }

    /**
     * The server's TLS context: the localhost certificate, trusting the test CA for client certificates
     */
    static SSLContext serverContext() throws Exception
    {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore("server.p12"), PASSWORD);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore("truststore.p12"));
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return ctx;
    }

    /**
     * A socket API server: reads one line per connection and writes the handler's response, or closes the
     * connection without responding if the handler returns null
     */
    static class SocketServer implements AutoCloseable
    {
        final ServerSocket m_server;
        final List<String> m_received = new CopyOnWriteArrayList<String>();
        volatile Function<String, String> m_handler;

        SocketServer(boolean tls, Function<String, String> handler) throws Exception
        {
            m_handler = handler;
            if (tls)
                m_server = serverContext().getServerSocketFactory().createServerSocket(0, 50, InetAddress.getLoopbackAddress());
            else
                m_server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            Thread t = new Thread(new Runnable()
            {
                public void run()
                {
                    accept();
                }
            });
            t.setDaemon(true);
            t.start();
        }

        int port()
        {
            return m_server.getLocalPort();
        }

        void accept()
        {
            while (!m_server.isClosed())
            {
                try
                {
                    Socket socket = m_server.accept();
                    try
                    {
                        BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                        String line = br.readLine();
                        m_received.add(line);
                        String response = m_handler.apply(line);
                        if (response != null)
                        {
                            BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
                            bw.write(response + "\n");
                            bw.flush();
                        }
                    }
                    finally
                    {
                        socket.close();
                    }
                }
                catch (Exception e)
                {
                    // Next connection (e.g. a client that failed the TLS handshake)
                }
            }
        }

        public void close() throws Exception
        {
            m_server.close();
        }
    }

    /**
     * A request received by the REST server
     */
    static class RestRequest
    {
        String m_method;
        String m_path;
        String m_authorization;
        String m_contentType;
        String m_body;
    }

    /**
     * A response for the REST server to send
     */
    static class RestResponse
    {
        final int m_status;
        final String m_body;

        RestResponse(int status, String body)
        {
            m_status = status;
            m_body = body;
        }
    }

    /**
     * A REST API server over HTTPS (the localhost certificate)
     */
    static class RestServer implements AutoCloseable
    {
        final HttpsServer m_server;
        final List<RestRequest> m_received = new CopyOnWriteArrayList<RestRequest>();
        volatile Function<RestRequest, RestResponse> m_handler;

        RestServer(final boolean needClientCert, Function<RestRequest, RestResponse> handler) throws Exception
        {
            m_handler = handler;
            m_server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
            m_server.setHttpsConfigurator(new HttpsConfigurator(serverContext())
            {
                @Override
                public void configure(HttpsParameters params)
                {
                    SSLParameters sslParams = getSSLContext().getDefaultSSLParameters();
                    sslParams.setNeedClientAuth(needClientCert);
                    params.setSSLParameters(sslParams);
                }
            });
            m_server.createContext("/", new HttpHandler()
            {
                public void handle(HttpExchange exchange)
                {
                    try
                    {
                        RestRequest request = new RestRequest();
                        request.m_method = exchange.getRequestMethod();
                        request.m_path = exchange.getRequestURI().getRawPath();
                        request.m_authorization = exchange.getRequestHeaders().getFirst("Authorization");
                        request.m_contentType = exchange.getRequestHeaders().getFirst("Content-Type");
                        ByteArrayOutputStream body = new ByteArrayOutputStream();
                        InputStream in = exchange.getRequestBody();
                        byte[] buf = new byte[4096];
                        int n;
                        while ((n = in.read(buf)) != -1)
                            body.write(buf, 0, n);
                        request.m_body = new String(body.toByteArray(), StandardCharsets.UTF_8);
                        m_received.add(request);

                        RestResponse response = m_handler.apply(request);
                        byte[] bytes = response.m_body.getBytes(StandardCharsets.UTF_8);
                        exchange.getResponseHeaders().set("Content-Type", "application/json");
                        exchange.getResponseHeaders().set("X-Transaction-Id", "12345678");
                        exchange.sendResponseHeaders(response.m_status, bytes.length);
                        OutputStream os = exchange.getResponseBody();
                        os.write(bytes);
                        os.close();
                    }
                    catch (Exception e)
                    {
                        e.printStackTrace();
                    }
                    finally
                    {
                        exchange.close();
                    }
                }
            });
            m_server.start();
        }

        int port()
        {
            return m_server.getAddress().getPort();
        }

        RestRequest last()
        {
            return m_received.get(m_received.size() - 1);
        }

        public void close()
        {
            m_server.stop(0);
        }
    }
}
