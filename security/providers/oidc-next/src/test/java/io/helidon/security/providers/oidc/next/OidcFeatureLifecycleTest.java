/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
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

package io.helidon.security.providers.oidc.next;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import io.helidon.http.HeaderNames;
import io.helidon.http.HttpMediaTypes;
import io.helidon.http.SetCookie;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webclient.api.WebClientConfig;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.WebServerConfig;
import io.helidon.webserver.http.HttpFeature;
import io.helidon.webserver.http.HttpRouting;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

class OidcFeatureLifecycleTest {
    @TestFactory
    Stream<DynamicTest> ownedFeatureClosesPrivateConnectionOnServerStop() {
        return Stream.of("server-feature", "http-feature", "direct-setup", "named-socket")
                .map(registration -> dynamicTest(registration, () -> {
                    try (DiscoveryPeer peer = new DiscoveryPeer()) {
                        OidcProviderConfig config = providerConfig(peer.issuer, false);
                        if ("named-socket".equals(registration)) {
                            config = OidcProviderConfig.builder(config).socket("oidc").buildPrototype();
                        }
                        OidcFeature feature = OidcFeature.create(config);
                        WebServerConfig.Builder builder = WebServer.builder().port(0);
                        switch (registration) {
                        case "server-feature" -> builder.addFeature(feature);
                        case "http-feature" -> builder.routing(routing -> routing.addFeature(feature));
                        case "direct-setup" -> builder.routing(feature::setup);
                        case "named-socket" -> builder.putSocket("oidc", socket -> socket.port(0)).addFeature(feature);
                        default -> throw new AssertionError(registration);
                        }
                        WebServer server = builder.build().start();
                        try {
                            errorCallback(server, config);
                            assertThat(peer.closed.getCount(), is(1L));
                            server.stop();
                            assertThat(peer.closed.await(2, TimeUnit.SECONDS), is(true));
                        } finally {
                            server.stop();
                        }
                    }
                }));
    }

    @TestFactory
    Stream<DynamicTest> ownedFeatureWaitsForLastActiveRegistration() {
        return Stream.of("same-feature", "same-builder", "copied-builder")
                .map(registration -> dynamicTest(registration, () -> {
                    try (DiscoveryPeer peer = new DiscoveryPeer()) {
                        OidcProviderConfig config = providerConfig(peer.issuer, false);
                        OidcFeature feature = OidcFeature.create(config);
                        HttpRouting.Builder routing = HttpRouting.builder();
                        feature.setup(routing);
                        WebServer first = WebServer.builder().port(0).addRouting(routing).build();
                        HttpRouting.Builder secondRouting = switch (registration) {
                            case "same-feature" -> HttpRouting.builder().addFeature(feature);
                            case "same-builder" -> routing;
                            case "copied-builder" -> routing.copy();
                            default -> throw new AssertionError(registration);
                        };
                        WebServer second = WebServer.builder().port(0).addRouting(secondRouting).build();
                        try {
                            first.start();
                            second.start();
                            errorCallback(first, config);
                            // Stopping a routing which never started must not release either active registration.
                            routing.copy().build().afterStop();
                            first.stop();
                            first.stop();
                            assertThat(peer.closed.getCount(), is(1L));
                            errorCallback(second, config);
                            second.stop();
                            assertThat(peer.closed.await(2, TimeUnit.SECONDS), is(true));
                        } finally {
                            first.stop();
                            second.stop();
                        }
                    }
                }));
    }

    @Test
    void providerBoundFeaturesLeaveCleanupToProviderOwner() throws Exception {
        try (DiscoveryPeer peer = new DiscoveryPeer()) {
            OidcProviderConfig config = providerConfig(peer.issuer, false);
            try (OidcProvider provider = OidcProvider.create(config)) {
                WebServer first = WebServer.builder().port(0).addFeature(OidcFeature.create(provider)).build();
                WebServer second = WebServer.builder().port(0).addFeature(OidcFeature.create(provider)).build();
                try {
                    first.start();
                    second.start();
                    errorCallback(first, config);
                    first.stop();
                    assertThat(peer.closed.getCount(), is(1L));
                    errorCallback(second, config);
                    second.stop();
                    assertThat(peer.closed.getCount(), is(1L));
                    provider.close();
                    assertThat(peer.closed.await(2, TimeUnit.SECONDS), is(true));
                } finally {
                    first.stop();
                    second.stop();
                }
            }
        }
    }

    @Test
    void failedStartupDoesNotCloseAnotherActiveRegistration() throws Exception {
        try (DiscoveryPeer peer = new DiscoveryPeer()) {
            OidcProviderConfig config = providerConfig(peer.issuer, false);
            OidcFeature feature = OidcFeature.create(config);
            WebServer first = WebServer.builder().port(0).addFeature(feature).build();
            WebServer second = WebServer.builder().port(0)
                    .routing(routing -> routing.addFeature(feature).addFeature(new HttpFeature() {
                        @Override
                        public void setup(HttpRouting.Builder routing) {
                        }

                        @Override
                        public void afterStart(WebServer webServer) {
                            throw new IllegalStateException("Test startup failure");
                        }
                    }))
                    .build();
            try {
                first.start();
                errorCallback(first, config);
                assertThrows(IllegalStateException.class, second::start);
                assertThat(second.isRunning(), is(false));
                errorCallback(first, config);
                assertThat(peer.closed.getCount(), is(1L));
                first.stop();
                assertThat(peer.closed.await(2, TimeUnit.SECONDS), is(true));
            } finally {
                first.stop();
                second.stop();
            }
        }
    }

    @Test
    void builtFeatureCannotStartAfterProviderCloses() {
        try (OidcProvider provider = OidcProvider.create()) {
            WebServer server = WebServer.builder().port(0).addFeature(OidcFeature.create(provider)).build();
            try {
                provider.close();
                assertThrows(IllegalStateException.class, server::start);
                assertThat(server.isRunning(), is(false));
            } finally {
                server.stop();
            }
        }
    }

    @Test
    void failedListenerBindingReleasesOnlyItsRegistration() throws Exception {
        try (DiscoveryPeer peer = new DiscoveryPeer(); ServerSocket occupied = new ServerSocket(0)) {
            OidcProviderConfig config = providerConfig(peer.issuer, false);
            OidcFeature feature = OidcFeature.create(config);
            WebServer first = WebServer.builder().port(0).addFeature(feature).build();
            WebServer second = WebServer.builder().port(occupied.getLocalPort()).addFeature(feature).build();
            try {
                first.start();
                errorCallback(first, config);
                assertThrows(IllegalStateException.class, second::start);
                assertThat(second.isRunning(), is(false));
                errorCallback(first, config);
                first.stop();
                assertThat(peer.closed.await(2, TimeUnit.SECONDS), is(true));
            } finally {
                first.stop();
                second.stop();
            }
        }
    }

    @Test
    void stoppedIndependentFeatureRequiresFreshOwner() {
        OidcProviderConfig config = OidcProviderConfig.create();
        OidcFeature feature = OidcFeature.create(config);
        WebServer server = WebServer.builder().port(0).addFeature(feature).build().start();
        server.stop();
        assertThrows(IllegalStateException.class, () -> feature.setup(HttpRouting.builder()));
        WebServer replacement = WebServer.builder().port(0).addFeature(OidcFeature.create(config)).build().start();
        replacement.stop();
    }

    @Test
    void providerClosePreservesJvmSharedConnections() {
        AtomicReference<String> discoveryConnection = new AtomicReference<>();
        WebServer discovery = WebServer.builder().port(0).routing(routing -> routing
                .get("/.well-known/openid-configuration", (request, response) -> {
                    discoveryConnection.set(request.socketId());
                    response.headers().contentType(HttpMediaTypes.JSON);
                    response.send(metadata(URI.create("http://localhost:" + request.localPeer().port())).toString());
                })
                .get("/connection", (request, response) -> response.send(request.socketId())))
                .build().start();
        URI issuer = URI.create("http://localhost:" + discovery.port());
        try (OidcProvider provider = OidcProvider.create(providerConfig(issuer, true))) {
            OidcTenantContext context = provider.tenantRuntimeRegistry().tenantContext("tenant").orElseThrow();
            assertThat(context.ready(), is(true));
            WebClient otherClient = WebClient.create(context.webClient().prototype());
            try {
                try (HttpClientResponse response = otherClient.get().uri(issuer.resolve("/connection")).request()) {
                    assertThat(response.as(String.class), is(discoveryConnection.get()));
                }
                provider.close();
                try (HttpClientResponse response = otherClient.get().uri(issuer.resolve("/connection")).request()) {
                    assertThat(response.as(String.class), is(discoveryConnection.get()));
                }
            } finally {
                otherClient.closeResource();
            }
        } finally {
            discovery.stop();
        }
    }

    private static OidcProviderConfig providerConfig(URI issuer, boolean sharedPool) {
        return OidcProviderConfig.builder()
                .putTenant("tenant", OidcTenantConfig.builder()
                        .issuer(issuer.toString())
                        .clientId("client-id")
                        .endpoints(endpoints -> endpoints.tlsRequired(false)
                                .wellKnownUri(issuer.resolve("/.well-known/openid-configuration")))
                        .webClient(WebClientConfig.builder().shareConnectionCache(sharedPool).buildPrototype())
                        .authorizationCode(code -> code.redirectionEndpointUri(URI.create("/oidc/callback")))
                        .cookies(cookies -> cookies.protection(protection -> protection.password("test-cookie-password")))
                        .buildPrototype())
                .buildPrototype();
    }

    private static JsonObject metadata(URI issuer) {
        return JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", issuer.resolve("/authorize").toString())
                .set("token_endpoint", issuer.resolve("/token").toString())
                .set("jwks_uri", issuer.resolve("/jwks").toString())
                .set("userinfo_endpoint", issuer.resolve("/userinfo").toString())
                .setStrings("response_types_supported", List.of("code"))
                .setStrings("code_challenge_methods_supported", List.of("S256"))
                .setStrings("id_token_signing_alg_values_supported", List.of("RS256"))
                .setStrings("token_endpoint_auth_methods_supported", List.of("none"))
                .build();
    }

    private static void errorCallback(WebServer server, OidcProviderConfig config) {
        URI callback = URI.create("http://localhost:" + server.port(config.socket().orElse(WebServer.DEFAULT_SOCKET_NAME))
                                          + "/oidc/callback");
        String state = OidcAuthorizationState.create("tenant",
                Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32])).value();
        Instant now = Instant.now();
        SetCookie cookie = OidcCookieStateHandler.create("tenant", config.tenants().get("tenant"))
                .createAuthenticationRequestCookie(new OidcAuthenticationRequestState("tenant", state, "nonce", "verifier",
                        null, config.tenants().get("tenant").issuer().orElseThrow(), URI.create("/resource"), callback,
                        now, now.plusSeconds(300)));
        WebClient client = WebClient.create();
        try (HttpClientResponse response = client.get().uri(callback)
                .queryParam("state", state).queryParam("error", "access_denied")
                .header(HeaderNames.COOKIE, cookie.name() + "=" + cookie.value()).request()) {
            assertThat(response.status(), is(Status.BAD_REQUEST_400));
            assertThat(response.as(String.class), is("OpenID Provider returned an Authorization Error Response"));
        } finally {
            client.closeResource();
        }
    }

    private static final class DiscoveryPeer implements AutoCloseable {
        private final ServerSocket listener;
        private final URI issuer;
        private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
        private final AtomicReference<Socket> connection = new AtomicReference<>();
        private final CountDownLatch closed = new CountDownLatch(1);
        private final Future<?> response;

        private DiscoveryPeer() throws Exception {
            listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
            issuer = new URI("http", null, listener.getInetAddress().getHostAddress(), listener.getLocalPort(),
                             null, null, null);
            response = executor.submit(() -> {
                try (Socket socket = listener.accept()) {
                    connection.set(socket);
                    socket.setSoTimeout(10_000);
                    BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(),
                                                                                     StandardCharsets.ISO_8859_1));
                    for (String line = reader.readLine(); line != null && !line.isEmpty(); line = reader.readLine()) {
                        // Consume the metadata request headers without closing the persistent connection.
                    }
                    byte[] body = metadata(issuer).toString().getBytes(StandardCharsets.UTF_8);
                    socket.getOutputStream().write(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                            + "Content-Length: " + body.length + "\r\nConnection: keep-alive\r\n\r\n")
                            .getBytes(StandardCharsets.US_ASCII));
                    socket.getOutputStream().write(body);
                    socket.getOutputStream().flush();
                    if (reader.read() == -1) {
                        closed.countDown();
                    }
                }
                return null;
            });
        }

        @Override
        public void close() throws Exception {
            listener.close();
            Socket socket = connection.get();
            if (socket != null) {
                socket.close();
            }
            response.cancel(true);
            executor.close();
        }
    }
}
