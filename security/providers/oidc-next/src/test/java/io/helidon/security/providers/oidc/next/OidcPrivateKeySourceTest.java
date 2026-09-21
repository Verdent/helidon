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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import io.helidon.common.configurable.Resource;
import io.helidon.common.configurable.ResourceConfig;
import io.helidon.common.parameters.Parameters;
import io.helidon.config.Config;
import io.helidon.config.ConfigSources;
import io.helidon.http.HttpMediaTypes;
import io.helidon.json.JsonObject;
import io.helidon.security.jwt.JwtHeaders;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.webclient.api.WebClient;
import io.helidon.webserver.WebServer;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.io.TempDir;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

class OidcPrivateKeySourceTest {
    private static final List<String> KEY_OPTIONS =
            List.of("client-assertion.jwk", "id-token.decryption-jwk", "user-info.jwt.decryption-jwk");
    private static final URI TOKEN_ENDPOINT = URI.create("https://issuer.example/token");

    @TempDir
    Path directory;

    @TestFactory
    Stream<DynamicTest> configuredPrivateKeyUrisAreRejectedBeforeAnyRequest() {
        return KEY_OPTIONS.stream()
                .map(key -> dynamicTest(key, () -> {
                    AtomicInteger requests = new AtomicInteger();
                    WebServer server = keyServer(requests);
                    try {
                        Config config = Config.builder()
                                .disableEnvironmentVariablesSource().disableSystemPropertiesSource()
                                .sources(ConfigSources.create(Map.of(key + ".uri", "http://localhost:" + server.port() + "/keys")))
                                .build();
                        assertAll(() -> {
                            IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                                                                            () -> configure(key, config));
                            assertThat(failure.getMessage(), containsString(key));
                        }, () -> assertThat(requests.get(), is(0)));
                    } finally {
                        server.stop();
                    }
                }));
    }

    @TestFactory
    Stream<DynamicTest> rootAndNamedTenantsRejectUrisEvenWhenDisabledOrTlsIsRelaxed() {
        return KEY_OPTIONS.stream().flatMap(key -> Stream.of("", "tenants.tenant.")
                .flatMap(prefix -> Stream.of(true, false).map(enabled -> dynamicTest(key + "/" + prefix + "/" + enabled, () -> {
                    AtomicInteger requests = new AtomicInteger();
                    WebServer server = keyServer(requests);
                    try {
                        Config config = configuration(Map.of(
                                prefix + key + ".uri", "http://localhost:" + server.port() + "/keys",
                                prefix + "enabled", Boolean.toString(enabled),
                                prefix + "endpoints.tls-required", "false"));
                        assertAll(() -> {
                            IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                                                                            () -> OidcProviderConfig.create(config));
                            assertThat(failure.getMessage(), containsString(key));
                        }, () -> assertThat(requests.get(), is(0)));
                    } finally {
                        server.stop();
                    }
                }))));
    }

    @TestFactory
    Stream<DynamicTest> programmaticUrisAreRejectedRegardlessOfScheme() {
        return KEY_OPTIONS.stream().flatMap(key -> Stream.of("http://unused.invalid/keys", "https://unused.invalid/keys",
                "file:/unused-key-file", "jar:file:/unused-keys.jar!/keys", "ftp://unused.invalid/keys", "relative-key-file")
                .map(uri -> dynamicTest(key + "/" + uri, () -> {
                    ResourceConfig resource = ResourceConfig.builder().uri(URI.create(uri)).buildPrototype();
                    IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                                                                    () -> configure(key, resource));
                    assertThat(failure.getMessage(), containsString(key));
                    assertThat(failure.getMessage(), containsString("URI sources"));
                })));
    }

    @TestFactory
    Stream<DynamicTest> uriCannotBeHiddenBehindAnotherSourceAndDoesNotLeakInTheError() {
        return KEY_OPTIONS.stream().flatMap(key -> Stream.of("path", "resource-path", "content", "content-plain")
                .map(source -> dynamicTest(key + "/" + source, () -> {
                    ResourceConfig.Builder resource = ResourceConfig.builder()
                            .uri(URI.create("https://user:secret-marker@unused.invalid/keys?credential=secret-marker"));
                    switch (source) {
                    case "path" -> resource.path(directory.resolve("must-not-be-opened"));
                    case "resource-path" -> resource.resourcePath("must-not-be-opened");
                    case "content" -> resource.content("e30=");
                    case "content-plain" -> resource.contentPlain("{}");
                    default -> throw new AssertionError(source);
                    }
                    IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                                                                    () -> configure(key, resource.buildPrototype()));
                    assertThat(failure.getMessage(), containsString(key));
                    assertThat(failure.getMessage(), not(containsString("secret-marker")));
                    assertThat(failure.getMessage(), not(containsString("unused.invalid")));
                })));
    }

    @TestFactory
    Stream<DynamicTest> emptySourceIsRejectedDuringConfiguration() {
        return KEY_OPTIONS.stream().map(key -> dynamicTest(key, () -> {
            IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                    () -> configure(key, ResourceConfig.builder().buildPrototype()));
            assertThat(failure.getMessage(), containsString(key));
            assertThat(failure.getMessage(), containsString("must configure"));
        }));
    }

    @TestFactory
    Stream<DynamicTest> allLocalSourceFormsSupportRepeatedSigningOrDecryption() {
        return KEY_OPTIONS.stream().flatMap(key -> Stream.of("path", "resource-path", "content", "content-plain")
                .flatMap(source -> Stream.of("builder", "config").map(mode -> dynamicTest(key + "/" + source + "/" + mode, () -> {
                    String fixture = "client-assertion.jwk".equals(key)
                            ? "oidc-next-sign-jwk.json"
                            : "oidc-next-encrypt-jwk.json";
                    String keys = Resource.create(fixture).string();
                    String value = switch (source) {
                        case "path" -> Files.writeString(directory.resolve(key + "-" + mode + ".json"), keys).toString();
                        case "resource-path" -> fixture;
                        case "content" -> Base64.getEncoder().encodeToString(keys.getBytes(StandardCharsets.UTF_8));
                        case "content-plain" -> keys;
                        default -> throw new AssertionError(source);
                    };
                    Object configured = "builder".equals(mode)
                            ? configure(key, ResourceConfig.create(configuration(Map.of(source, value))))
                            : configure(key, configuration(Map.of(key + "." + source, value)));
                    JwkKeys fixtureKeys = JwkKeys.builder().resource(Resource.create(fixture)).build();
                    exerciseConsumers(key, configured, fixtureKeys);
                }))));
    }

    @TestFactory
    Stream<DynamicTest> suppliedKeyContentRemainsRedacted() {
        return KEY_OPTIONS.stream().map(key -> dynamicTest(key, () -> {
            String marker = "private-key-material-marker";
            String encoded = Base64.getEncoder().encodeToString(marker.getBytes(StandardCharsets.UTF_8));
            Object plain = configure(key, ResourceConfig.builder().contentPlain(marker).buildPrototype());
            Object base64 = configure(key, ResourceConfig.builder().content(encoded).buildPrototype());
            assertThat(plain.toString(), not(containsString(marker)));
            assertThat(base64.toString(), not(containsString(encoded)));
        }));
    }

    @TestFactory
    Stream<DynamicTest> endpointClientAssertionOverridesRejectUrisBeforeOpening() {
        return Stream.of("introspection", "tenant").map(scope -> dynamicTest(scope, () -> {
            AtomicInteger requests = new AtomicInteger();
            WebServer server = keyServer(requests);
            try {
                String prefix = "tenant".equals(scope) ? "protected-resource.token-validation.introspection." : "";
                Config config = configuration(Map.of(prefix + "client-assertion.jwk.uri",
                                                     "http://localhost:" + server.port() + "/keys"));
                assertAll(() -> {
                    IllegalArgumentException failure = assertThrows(IllegalArgumentException.class, () -> {
                        switch (scope) {
                        case "introspection" -> OidcIntrospectionConfig.create(config);
                        case "tenant" -> OidcTenantConfig.create(config);
                        default -> throw new AssertionError(scope);
                        }
                    });
                    assertThat(failure.getMessage(), containsString("client-assertion.jwk"));
                }, () -> assertThat(requests.get(), is(0)));
            } finally {
                server.stop();
            }
        }));
    }

    @Test
    void runtimeDecryptionLoaderChecksTheSourceBeforeOpening() {
        AtomicInteger requests = new AtomicInteger();
        WebServer server = keyServer(requests);
        try {
            ResourceConfig resource = ResourceConfig.builder().uri(URI.create("http://localhost:" + server.port() + "/keys"))
                    .buildPrototype();
            IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                    () -> OidcJweDecryptor.create(Optional.of(resource), "decryption-jwk", "test token"));
            assertThat(failure.getMessage(), containsString("URI sources"));
            assertThat(requests.get(), is(0));
        } finally {
            server.stop();
        }
    }

    @TestFactory
    Stream<DynamicTest> virtualThreadsCanLoadSharedDecryptionDescriptionsIndependently() {
        return Stream.of("id-token.decryption-jwk", "user-info.jwt.decryption-jwk").map(key -> dynamicTest(key, () -> {
            ResourceConfig resource = ResourceConfig.builder().resourcePath("oidc-next-encrypt-jwk.json").buildPrototype();
            Optional<ResourceConfig> configured = decryptionResource(configure(key, resource));
            JwkKeys fixtureKeys = JwkKeys.builder().resource(Resource.create("oidc-next-encrypt-jwk.json")).build();
            String token = OidcTestJwe.encrypt("shared source", fixtureKeys, false, JsonObject.builder().build());
            CountDownLatch start = new CountDownLatch(1);
            try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
                List<Future<String>> results;
                try {
                    results = IntStream.range(0, 32).mapToObj(_ -> executor.submit(() -> {
                        start.await();
                        assertThat(Thread.currentThread().isVirtual(), is(true));
                        OidcJweDecryptor decryptor = OidcJweDecryptor.create(configured, key, "test token");
                        return new String(decryptor.decrypt(token, JwtHeaders.parseToken(token)), StandardCharsets.UTF_8);
                    })).toList();
                } finally {
                    start.countDown();
                }
                for (Future<String> result : results) {
                    assertThat(result.get(10, TimeUnit.SECONDS), is("shared source"));
                }
            }
        }));
    }

    private static WebServer keyServer(AtomicInteger requests) {
        return WebServer.builder().port(0).routing(routing -> routing.get("/keys", (_, response) -> {
            requests.incrementAndGet();
            response.headers().contentType(HttpMediaTypes.JSON);
            response.send("{\"keys\":[]}");
        })).build().start();
    }

    private static Config configuration(Map<String, String> values) {
        return Config.builder().disableEnvironmentVariablesSource().disableSystemPropertiesSource()
                .sources(ConfigSources.create(values)).build();
    }

    private static Object configure(String key, Config config) {
        return switch (key) {
            case "client-assertion.jwk" -> OidcClientAssertionConfig.create(config.get("client-assertion"));
            case "id-token.decryption-jwk" -> OidcIdTokenConfig.create(config.get("id-token"));
            case "user-info.jwt.decryption-jwk" -> OidcUserInfoJwtConfig.create(config.get("user-info.jwt"));
            default -> throw new AssertionError(key);
        };
    }

    private static Object configure(String key, ResourceConfig resource) {
        return switch (key) {
            case "client-assertion.jwk" -> OidcClientAssertionConfig.builder().jwk(resource).buildPrototype();
            case "id-token.decryption-jwk" -> OidcIdTokenConfig.builder().decryptionJwk(resource).buildPrototype();
            case "user-info.jwt.decryption-jwk" -> OidcUserInfoJwtConfig.builder().decryptionJwk(resource).buildPrototype();
            default -> throw new AssertionError(key);
        };
    }

    private static void exerciseConsumers(String key, Object configured, JwkKeys fixtureKeys) throws Exception {
        if (configured instanceof OidcClientAssertionConfig assertion) {
            OidcTenantConfig tenant = OidcTenantConfig.builder().issuer("https://issuer.example").clientId("client")
                    .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.PRIVATE_KEY_JWT)
                    .clientAssertion(OidcClientAssertionConfig.builder(assertion).keyId("sign-rsa").buildPrototype())
                    .endpoints(endpoints -> endpoints.tokenEndpointUri(TOKEN_ENDPOINT)).buildPrototype();
            WebClient client = WebClient.create();
            try {
                Set<String> jwtIds = new HashSet<>();
                for (int i = 0; i < 2; i++) {
                    OidcClientAuthenticationSupport support = OidcClientAuthenticationSupport.tokenEndpoint(tenant);
                    Parameters.Builder form = Parameters.builder("client assertion");
                    support.applyTokenEndpointAuthentication(TOKEN_ENDPOINT, form, client.post().uri(TOKEN_ENDPOINT));
                    SignedJwt jwt = SignedJwt.parseToken(form.build().first("client_assertion").orElseThrow());
                    assertThat(jwt.verifySignature(fixtureKeys).isValid(), is(true));
                    assertThat(jwt.getJwt().issuer().orElseThrow(), is("client"));
                    assertThat(jwtIds.add(jwt.getJwt().jwtId().orElseThrow()), is(true));
                }
            } finally {
                client.closeResource();
            }
        } else {
            Optional<ResourceConfig> resource = decryptionResource(configured);
            String payload = "private-key-source-test";
            String token = OidcTestJwe.encrypt(payload, fixtureKeys, false, JsonObject.builder().build());
            for (int i = 0; i < 2; i++) {
                OidcJweDecryptor decryptor = OidcJweDecryptor.create(resource, key, "test token");
                byte[] decrypted = decryptor.decrypt(token, JwtHeaders.parseToken(token));
                assertThat(new String(decrypted, StandardCharsets.UTF_8), is(payload));
            }
        }
    }

    private static Optional<ResourceConfig> decryptionResource(Object configured) {
        return switch (configured) {
            case OidcIdTokenConfig idToken -> idToken.decryptionJwk();
            case OidcUserInfoJwtConfig userInfo -> userInfo.decryptionJwk();
            default -> throw new AssertionError(configured.getClass());
        };
    }
}
