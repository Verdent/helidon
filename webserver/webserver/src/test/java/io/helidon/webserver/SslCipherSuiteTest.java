/*
 * Copyright (c) 2021 Oracle and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.helidon.webserver;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import javax.net.SocketFactory;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;

import io.helidon.common.Builder;
import io.helidon.common.configurable.Resource;
import io.helidon.common.pki.KeyConfig;
import io.helidon.config.Config;
import io.helidon.config.ConfigSources;

import org.glassfish.jersey.apache.connector.ApacheClientProperties;
import org.glassfish.jersey.apache.connector.ApacheConnectorProvider;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.HttpUrlConnectorProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * The test of SSL Netty layer.
 */
public class SslCipherSuiteTest {

    private static final Config CONFIG = Config.builder().sources(ConfigSources.classpath("config-cipher-suite.conf")).build();

    private static final Logger LOGGER = Logger.getLogger(SslCipherSuiteTest.class.getName());

    private static WebServer webServer;
    private static Client clientFirst;
    private static Client clientSecond;

    /**
     * Start the secured Web Server
     *
     * @throws Exception in case of an error
     */
    @BeforeAll
    private static void startServer() throws Exception {

        webServer = WebServer.builder(createDefaultSocketRouting())
                .config(ServerConfiguration.builder(CONFIG.get("webserver")))
                .addNamedRouting("secured", createSecondRouting())
                .build();

        webServer.start()
                .thenAccept(ws -> {
                    System.out.println("WebServer is up!");
                    ws.whenShutdown().thenRun(() -> System.out.println("WEB server is DOWN. Good bye!"));
                })
                .exceptionally(t -> {
                    System.err.println("Startup failed: " + t.getMessage());
                    t.printStackTrace(System.err);
                    return null;
                })
                .toCompletableFuture()
                .get(10, TimeUnit.SECONDS);

        LOGGER.info("Started secured server at: https://localhost:" + webServer.port());
        System.out.println("TADY");
    }

    @BeforeAll
    public static void createClient() throws Exception {

//        SSLContext sc = SSLContextBuilder.create(CONFIG.get("client-ssl"));

        ClientConfig clientConfig = new ClientConfig()
                .connectorProvider(new HttpUrlConnectorProvider().connectionFactory(
                        new HttpUrlConnectorProvider.ConnectionFactory() {
                            @Override
                            public HttpURLConnection getConnection(final URL url) throws IOException {
                                HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
                                String[] array = new String[1];
                                array[0] = "TLS_RSA_WITH_AES_128_GCM_SHA256";
                                connection.setSSLSocketFactory(new TestCustomFactory(array));
                                return connection;
                            }
                        }));
//        KeyStore trust = KeyStore.getInstance("PKCS12");
//        trust.load(SslCipherSuiteTest.class.getResourceAsStream("/ssl-certificate-reloading/client-first.p12"), "password".toCharArray());

        clientFirst = ClientBuilder.newBuilder()
                .withConfig(clientConfig)
                .sslContext(clientSslContextTrustAll())
//                .sslContext(sc)
                .hostnameVerifier((s, sslSession) -> true)
                .build();


        clientConfig = new ClientConfig()
                .connectorProvider(new HttpUrlConnectorProvider().connectionFactory(
                        new HttpUrlConnectorProvider.ConnectionFactory() {
                            @Override
                            public HttpURLConnection getConnection(final URL url) throws IOException {
                                HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
                                String[] array = new String[1];
                                array[0] = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384";
                                connection.setSSLSocketFactory(new TestCustomFactory(array));
                                return connection;
                            }
                        }));


        clientSecond = ClientBuilder.newBuilder()
                .withConfig(clientConfig)
                .sslContext(clientSslContextTrustAll())
//                .trustStore(KeyStore.getInstance("PKCS12")
//                                    .load())
//                .sslContext(sc)
                .hostnameVerifier((s, sslSession) -> true)
                .build();

        System.out.println("TADY2");
    }

    private static Routing createDefaultSocketRouting() {
        return Routing.builder()
                .get("/", (req, res) -> res.send("It works!"))
                .build();
    }

    private static Routing createSecondRouting() {
        return Routing.builder()
                .get("/", (req, res) -> res.send("It works! Second!"))
                .build();
    }

    @AfterAll
    public static void close() throws Exception {
        if (webServer != null) {
            webServer.shutdown()
                    .toCompletableFuture()
                    .get(10, TimeUnit.SECONDS);
        }
        if (clientFirst != null) {
            clientFirst.close();
        }
        if (clientSecond != null) {
            clientSecond.close();
        }
    }

    @Test
    public void test() {
        WebTarget target = clientFirst.target("https://localhost:" + webServer.port());
        assertThat(target.request().get().readEntity(String.class), is("It works!"));
    }

//    public static void main(String[] args) throws Exception {
//        startServer();
//        TimeUnit.MINUTES.sleep(60);
//    }

    private static final class TestCustomFactory extends SSLSocketFactory {

        private final SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        private final String[] cipherSuite;

        TestCustomFactory(String[] cipherSuite) {
            this.cipherSuite = cipherSuite;
        }


        @Override
        public String[] getDefaultCipherSuites() {
            return cipherSuite;
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return cipherSuite;
        }

        @Override
        public Socket createSocket(Socket socket, String s, int i, boolean b) throws IOException {
            return factory.createSocket(socket, s, i, b);
        }

        @Override
        public Socket createSocket() throws IOException {
            return factory.createSocket();
        }

        @Override
        public Socket createSocket(String s, int i) throws IOException, UnknownHostException {
            return factory.createSocket(s, i);
        }

        @Override
        public Socket createSocket(String s, int i, InetAddress inetAddress, int i1) throws IOException, UnknownHostException {
            return factory.createSocket(s, i, inetAddress, i1);
        }

        @Override
        public Socket createSocket(InetAddress inetAddress, int i) throws IOException {
            return factory.createSocket(inetAddress, i);
        }

        @Override
        public Socket createSocket(InetAddress inetAddress, int i, InetAddress inetAddress1, int i1) throws IOException {
            return factory.createSocket(inetAddress, i, inetAddress1, i1);
        }
    }

    public static SSLContext clientSslContextTrustAll() throws NoSuchAlgorithmException, KeyManagementException {
        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = {
                new X509TrustManager() {
                    @Override
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    @Override
                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }

                    @Override
                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
        };

        // Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        return sc;
    }
}
