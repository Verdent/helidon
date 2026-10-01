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

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import java.util.stream.Stream;

import io.helidon.common.configurable.Resource;
import io.helidon.common.pki.Keys;
import io.helidon.common.tls.Tls;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webclient.api.WebClientConfig;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.http.HttpRouting;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Execution(ExecutionMode.SAME_THREAD)
class OidcJwkSetRedirectTest {
    private static final String ISSUER = "https://issuer.example";
    private static final Instant START = Instant.parse("2026-09-17T12:00:00Z");
    private static final AtomicInteger SOURCE_REQUESTS = new AtomicInteger();
    private static final AtomicInteger TARGET_REQUESTS = new AtomicInteger();

    private static String originalKeys;
    private static String redirectedKeys;
    private static volatile String sourceKeys;
    private static volatile String redirectLocation;
    private static volatile int redirectStatus;

    private static WebServer httpsServer;
    private static WebServer otherHttpsServer;
    private static WebServer httpServer;
    private static URI httpsUri;
    private static URI otherHttpsUri;
    private static URI httpUri;

    @BeforeAll
    static void initClass() {
        originalKeys = Resource.create("oidc-next-verify-public-jwk.json").string();
        redirectedKeys = Resource.create("oidc-next-sign-public-jwk.json").string();
        Keys keys = Keys.builder()
                .keystore(store -> store.passphrase("password").keystore(Resource.create("server.p12")))
                .build();
        Tls tls = Tls.builder().privateKey(keys).privateKeyCertChain(keys).build();
        httpsServer = server(tls);
        otherHttpsServer = server(tls);
        httpServer = server(Tls.builder().enabled(false).build());
        httpsUri = URI.create("https://localhost:" + httpsServer.port() + "/");
        otherHttpsUri = URI.create("https://localhost:" + otherHttpsServer.port() + "/");
        httpUri = URI.create("http://localhost:" + httpServer.port() + "/");
    }

    @AfterAll
    static void stopServers() {
        if (httpsServer != null) {
            httpsServer.stop();
        }
        if (otherHttpsServer != null) {
            otherHttpsServer.stop();
        }
        if (httpServer != null) {
            httpServer.stop();
        }
    }

    @BeforeEach
    void setUp() {
        resetResponses();
    }

    @TestFactory
    List<DynamicTest> initialLoadRejectsRedirects() {
        List<DynamicTest> tests = new ArrayList<>();
        for (int status : List.of(301, 302, 303, 307, 308)) {
            for (RedirectTarget target : targets()) {
                for (boolean tlsRequired : List.of(false, true)) {
                    for (boolean discovered : List.of(false, true)) {
                        String name = status + " " + target.name() + " tls=" + tlsRequired + " discovered=" + discovered;
                        tests.add(dynamicTest(name,
                                              () -> assertInitialRedirectRejected(status, target, tlsRequired, discovered)));
                    }
                }
            }
        }
        return tests;
    }

    @TestFactory
    Stream<DynamicTest> unknownKeyRefreshRejectsRedirects() {
        return refreshTests(false);
    }

    @TestFactory
    Stream<DynamicTest> periodicRefreshRejectsRedirects() {
        return refreshTests(true);
    }

    @Test
    void directHttpsLoadingAndRotationRemainSupported() {
        OidcTenantConfig tenant = tenant(httpsUri.resolve("jwks"), true, false);
        WebClient client = OidcWebClientFactory.create(tenant);
        try {
            MutableClock clock = new MutableClock();
            OidcJwkSetManager manager = manager(tenant, false, client, clock, true);
            assertThat(manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(true));

            sourceKeys = redirectedKeys;
            clock.advance(Duration.ofMinutes(1));

            assertThat(manager.jwkKeys().forKeyId("sign-rsa").isPresent(), is(true));
            assertThat(SOURCE_REQUESTS.get(), is(2));
            assertThat(TARGET_REQUESTS.get(), is(0));
        } finally {
            client.closeResource();
        }
    }

    @Test
    void directHttpRequiresExplicitTlsOptOut() {
        URI uri = httpUri.resolve("jwks");
        assertThrows(IllegalArgumentException.class, () -> tenant(uri, true, false));
        OidcTenantConfig tenant = tenant(uri, false, false);
        WebClient client = OidcWebClientFactory.create(tenant);
        try {
            assertThat(manager(tenant, false, client, new MutableClock(), true)
                               .jwkKeys().forKeyId("verify-rsa").isPresent(), is(true));
            assertThat(SOURCE_REQUESTS.get(), is(1));
            assertThat(TARGET_REQUESTS.get(), is(0));
        } finally {
            client.closeResource();
        }
    }

    @Test
    void developmentHttpStillRejectsRedirects() {
        redirectLocation = httpUri.resolve("target").toString();
        OidcTenantConfig tenant = tenant(httpUri.resolve("jwks"), false, false);
        WebClient client = OidcWebClientFactory.create(tenant);
        try {
            assertRedirectFailure(() -> manager(tenant, false, client, new MutableClock(), true).jwkKeys(), 302);
            assertThat(SOURCE_REQUESTS.get(), is(1));
            assertThat(TARGET_REQUESTS.get(), is(0));
        } finally {
            client.closeResource();
        }
    }

    @Test
    void fileLoadingRemainsSupported() throws Exception {
        URI uri = getClass().getClassLoader().getResource("oidc-next-verify-public-jwk.json").toURI();
        WebClient client = WebClient.create();
        try {
            assertThat(new OidcJwkSetLoader(client).load(uri).forKeyId("verify-rsa").isPresent(), is(true));
            assertThat(SOURCE_REQUESTS.get(), is(0));
            assertThat(TARGET_REQUESTS.get(), is(0));
        } finally {
            client.closeResource();
        }
    }

    @Test
    void configuredWebClientRedirectsRemainEnabledOutsideJwksRequests() {
        redirectLocation = "/target";
        OidcTenantConfig tenant = tenant(httpsUri.resolve("jwks"), true, false);
        WebClient client = OidcWebClientFactory.create(tenant);
        try (HttpClientResponse response = client.get().uri(httpsUri.resolve("jwks")).request()) {
            assertThat(response.status(), is(Status.OK_200));
            assertThat(JwkKeys.create(response.as(JsonObject.class)).forKeyId("sign-rsa").isPresent(), is(true));
            assertThat(SOURCE_REQUESTS.get(), is(1));
            assertThat(TARGET_REQUESTS.get(), is(1));
        } finally {
            client.closeResource();
        }
    }

    private static WebServer server(Tls tls) {
        HttpRouting.Builder routing = HttpRouting.builder();
        routing.get("/jwks", (_, response) -> {
            SOURCE_REQUESTS.incrementAndGet();
            String location = redirectLocation;
            if (location != null) {
                response.status(redirectStatus).header(HeaderNames.LOCATION, location).send();
            } else {
                response.header(HeaderValues.CONTENT_TYPE_JSON).send(sourceKeys);
            }
        });
        routing.get("/target", (_, response) -> {
            TARGET_REQUESTS.incrementAndGet();
            response.header(HeaderValues.CONTENT_TYPE_JSON).send(redirectedKeys);
        });
        return WebServer.builder().port(0).tls(tls).addRouting(routing).build().start();
    }

    private static OidcTenantConfig tenant(URI jwksUri, boolean tlsRequired, boolean discovered) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER)
                .endpoints(endpoints -> {
                    endpoints.tlsRequired(tlsRequired);
                    if (!discovered) {
                        endpoints.jwksUri(jwksUri);
                    }
                })
                .protectedResource(resource -> resource.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.JWT)
                        .audience("api://default")))
                .webClient(WebClientConfig.builder()
                                   .followRedirects(true)
                                   .readTimeout(Duration.ofSeconds(5))
                                   .tls(tls -> tls.trust(trust -> trust.keystore(store -> store
                                           .passphrase("password")
                                           .trustStore(true)
                                           .keystore(Resource.create("client.p12")))))
                                   .buildPrototype())
                .buildPrototype();
    }

    private static void assertRedirectFailure(Supplier<JwkKeys> load, int status) {
        IllegalStateException exception = assertThrows(IllegalStateException.class, load::get);
        assertThat(exception.getCause().getMessage(), containsString("JWK Set endpoint returned status: " + status));
    }

    private static void resetResponses() {
        redirectLocation = null;
        redirectStatus = 302;
        sourceKeys = originalKeys;
        SOURCE_REQUESTS.set(0);
        TARGET_REQUESTS.set(0);
    }

    private Stream<DynamicTest> refreshTests(boolean periodic) {
        return targets().stream()
                .flatMap(target -> Stream.of(false, true)
                        .map(stale -> dynamicTest(target.name() + " stale-on-error=" + stale,
                                                 () -> assertRefreshRedirectRejected(target, stale, periodic))));
    }

    private void assertInitialRedirectRejected(int status, RedirectTarget target, boolean tlsRequired, boolean discovered) {
        resetResponses();
        redirectStatus = status;
        redirectLocation = target.location();
        OidcTenantConfig tenant = tenant(httpsUri.resolve("jwks"), tlsRequired, discovered);
        WebClient client = OidcWebClientFactory.create(tenant);
        try {
            OidcJwkSetManager manager = manager(tenant, discovered, client, new MutableClock(), true);
            assertRedirectFailure(manager::jwkKeys, status);
            assertThat(SOURCE_REQUESTS.get(), is(1));
            assertThat(TARGET_REQUESTS.get(), is(0));
        } finally {
            client.closeResource();
        }
    }

    private void assertRefreshRedirectRejected(RedirectTarget target, boolean stale, boolean periodic) {
        resetResponses();
        OidcTenantConfig tenant = tenant(httpsUri.resolve("jwks"), true, true);
        WebClient client = OidcWebClientFactory.create(tenant);
        try {
            MutableClock clock = new MutableClock();
            OidcJwkSetManager manager = manager(tenant, true, client, clock, stale);
            JwkKeys original = manager.jwkKeys();
            assertThat(original.forKeyId("verify-rsa").isPresent(), is(true));
            redirectLocation = target.location();
            clock.advance(periodic ? Duration.ofMinutes(1) : Duration.ofSeconds(1));
            Supplier<JwkKeys> refresh = periodic ? manager::jwkKeys : () -> manager.jwkKeys(Optional.of("sign-rsa"));

            if (stale) {
                JwkKeys retained = refresh.get();
                assertThat(retained, sameInstance(original));
                assertThat(retained.forKeyId("sign-rsa").isPresent(), is(false));
            } else {
                assertRedirectFailure(refresh, 302);
            }
            assertThat(SOURCE_REQUESTS.get(), is(2));
            assertThat(TARGET_REQUESTS.get(), is(0));
        } finally {
            client.closeResource();
        }
    }

    private OidcJwkSetManager manager(OidcTenantConfig tenant,
                                      boolean discovered,
                                      WebClient client,
                                      Clock clock,
                                      boolean staleOnError) {
        OidcProviderMetadata metadata = OidcProviderMetadata.fromStaticConfig(tenant);
        if (discovered) {
            metadata = metadata.mergeWellKnownMetadata(OidcProviderMetadata.fromWellKnownMetadataJson(JsonObject.builder()
                    .set("issuer", ISSUER)
                    .set("jwks_uri", httpsUri.resolve("jwks").toString())
                    .build()));
        }
        return OidcJwkSetManager.create("default",
                                        metadata,
                                        client,
                                        clock,
                                        OidcJwkSetConfig.builder()
                                                .refreshInterval(Duration.ofMinutes(1))
                                                .unknownKeyIdRefreshInterval(Duration.ZERO)
                                                .staleOnError(staleOnError)
                                                .buildPrototype());
    }

    private List<RedirectTarget> targets() {
        return List.of(new RedirectTarget("relative HTTPS", "/target"),
                       new RedirectTarget("same-origin HTTPS", httpsUri.resolve("target").toString()),
                       new RedirectTarget("cross-origin HTTPS", otherHttpsUri.resolve("target").toString()),
                       new RedirectTarget("HTTPS-to-HTTP", httpUri.resolve("target").toString()));
    }

    private record RedirectTarget(String name, String location) {
    }

    private static final class MutableClock extends Clock {
        private Instant instant = START;

        void advance(Duration duration) {
            instant = instant.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return Clock.fixed(instant, zone);
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }
}
