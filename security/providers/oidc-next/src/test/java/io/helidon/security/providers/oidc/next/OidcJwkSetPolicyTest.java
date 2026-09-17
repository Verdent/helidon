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

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import io.helidon.common.configurable.Resource;
import io.helidon.http.HeaderValues;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.webclient.api.WebClient;
import io.helidon.webserver.WebServer;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

@Execution(ExecutionMode.SAME_THREAD)
class OidcJwkSetPolicyTest {
    private static final String ISSUER = "https://issuer.example";
    private static final String PUBLIC_ONLY_ERROR = "OpenID Provider JWK Set must not contain private or symmetric key values";
    private static final JsonObject PUBLIC_KEY = key("oidc-next-verify-public-jwk.json", 0);
    private static final JsonObject PRIVATE_KEY = key("oidc-next-sign-jwk.json", 0);
    private static final JsonObject SYMMETRIC_KEY = key("oidc-next-verify-jwk.json", 1);
    private static final AtomicReference<String> RESPONSE = new AtomicReference<>();

    @TempDir
    static Path directory;

    private static WebServer server;
    private static WebClient webClient;
    private static URI remoteUri;

    @BeforeAll
    static void init() {
        server = WebServer.builder().routing(routing -> routing.get("/jwks", (_, response) -> {
            response.header(HeaderValues.CONTENT_TYPE_JSON);
            response.send(RESPONSE.get());
        })).build().start();
        remoteUri = URI.create("http://localhost:" + server.port() + "/jwks");
        webClient = WebClient.create();
    }

    @AfterAll
    static void close() {
        try {
            if (webClient != null) {
                webClient.closeResource();
            }
        } finally {
            if (server != null) {
                server.stop();
            }
        }
    }

    @TestFactory
    Stream<DynamicTest> everyProviderKeySourceRejectsPrivateAndSymmetricMaterial() {
        return Arrays.stream(Location.values()).flatMap(location -> Arrays.stream(Provenance.values())
                .flatMap(provenance -> forbiddenKeys().entrySet().stream().map(entry -> dynamicTest(
                        location + "/" + provenance + "/" + entry.getKey(), () -> {
                            OidcJwkSetManager manager = manager(location, provenance, entry.getValue());

                            IllegalStateException failure = assertThrows(IllegalStateException.class, manager::jwkKeys);

                            assertThat(failure.getCause().getMessage(), is(PUBLIC_ONLY_ERROR));
                        }))));
    }

    @TestFactory
    Stream<DynamicTest> everyProviderKeySourceAcceptsPublicKeysAndUnknownParameters() {
        return Arrays.stream(Location.values()).flatMap(location -> Arrays.stream(Provenance.values())
                .map(provenance -> dynamicTest(location + "/" + provenance, () -> {
                    JsonObject publicKey = JsonObject.builder().from(PUBLIC_KEY).set("test-annotation", "public key").build();
                    OidcJwkSetManager manager = manager(location, provenance, publicKey);

                    JwkKeys keys = manager.jwkKeys();

                    assertThat(keys.keys().size(), is(1));
                    assertThat(keys.forKeyId("verify-rsa").isPresent(), is(true));
                })));
    }

    private static JsonObject key(String resource, int index) {
        return JsonParser.create(Resource.create(resource).string()).readJsonObject()
                .arrayValue("keys").orElseThrow().values().get(index).asObject();
    }

    private static Map<String, JsonObject> forbiddenKeys() {
        Map<String, JsonObject> keys = new LinkedHashMap<>();
        for (String parameter : List.of("k", "d", "p", "q", "dp", "dq", "qi", "oth")) {
            String value = parameter.equals("d") ? PRIVATE_KEY.stringValue("d").orElseThrow() : "AQAB";
            keys.put(parameter, JsonObject.builder().from(PUBLIC_KEY).set(parameter, value).build());
        }
        keys.put("complete-private-rsa", PRIVATE_KEY);
        keys.put("complete-symmetric", SYMMETRIC_KEY);
        return keys;
    }

    private static OidcJwkSetManager manager(Location location, Provenance provenance, JsonObject key) throws IOException {
        String json = "{\"keys\":[" + key + "]}";
        URI uri;
        if (location == Location.FILE) {
            Path file = Files.createTempFile(directory, "jwks", ".json");
            Files.writeString(file, json);
            uri = file.toUri();
        } else {
            RESPONSE.set(json);
            uri = remoteUri;
        }
        OidcProviderMetadata staticMetadata = OidcProviderMetadata.fromStaticConfig(OidcTenantConfig.builder()
                .issuer(ISSUER).endpoints(endpoints -> endpoints.jwksUri(uri).tlsRequired(false)).buildPrototype());
        OidcProviderMetadata discovered = OidcProviderMetadata.fromWellKnownMetadataJson(JsonObject.builder()
                .set("issuer", ISSUER).set("jwks_uri", uri.toString()).build());
        OidcProviderMetadata metadata = switch (provenance) {
            case STATIC -> staticMetadata;
            case DISCOVERED -> discovered;
            case OVERRIDE -> staticMetadata.mergeWellKnownMetadata(discovered);
        };
        return OidcJwkSetManager.create("test", metadata, webClient, OidcJwkSetConfig.create());
    }

    private enum Location {
        FILE,
        HTTP
    }

    private enum Provenance {
        STATIC,
        DISCOVERED,
        OVERRIDE
    }
}
