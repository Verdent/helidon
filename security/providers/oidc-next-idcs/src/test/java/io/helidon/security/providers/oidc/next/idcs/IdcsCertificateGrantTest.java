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

package io.helidon.security.providers.oidc.next.idcs;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import io.helidon.common.configurable.Resource;
import io.helidon.common.parameters.Parameters;
import io.helidon.common.pki.Keys;
import io.helidon.common.tls.Tls;
import io.helidon.common.tls.TlsClientAuth;
import io.helidon.config.Config;
import io.helidon.config.ConfigSources;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.security.providers.oidc.next.OidcTenantConfig;
import io.helidon.webclient.api.WebClient;
import io.helidon.webclient.api.WebClientConfig;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.http.HttpRouting;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Execution(ExecutionMode.SAME_THREAD)
class IdcsCertificateGrantTest {
    private static final AtomicInteger TOKEN_REQUESTS = new AtomicInteger();
    private static final AtomicInteger REDIRECT_TARGET_REQUESTS = new AtomicInteger();
    private static final AtomicReference<String> TOKEN_SCOPE = new AtomicReference<>("");
    private static final String JWKS_SCOPE = "urn:opc:idm:__myscopes__";

    private static WebServer server;
    private static URI domainUri;
    private static Keys tlsKeys;
    private static volatile boolean redirectTokenEndpoint;
    private static volatile Status tokenResponseStatus;
    private static volatile String tokenResponseBody;

    @BeforeAll
    static void start() {
        tlsKeys = Keys.builder().pem(pem -> pem
                .key(Resource.create("oidc-next-par-localhost.key"))
                .certChain(Resource.create("oidc-next-par-localhost.crt"))).build();
        Tls tls = Tls.builder()
                .privateKey(tlsKeys)
                .privateKeyCertChain(tlsKeys)
                .trust(tlsKeys.certChain())
                .clientAuth(TlsClientAuth.REQUIRED)
                .build();
        HttpRouting.Builder routing = HttpRouting.builder();
        routing.post("/oauth2/v1/token", (request, response) -> {
            TOKEN_REQUESTS.incrementAndGet();
            if (redirectTokenEndpoint) {
                response.status(Status.TEMPORARY_REDIRECT_307)
                        .header(HeaderNames.LOCATION, "/wrong-target")
                        .send();
                return;
            }
            Parameters form = request.content().as(Parameters.class);
            assertThat(form.first("grant_type").orElseThrow(), is("tls_client_auth"));
            assertThat(form.first("client_id").orElseThrow(), is("client"));
            TOKEN_SCOPE.set(form.first("scope").orElseThrow());
            response.status(tokenResponseStatus)
                    .header(HeaderValues.CONTENT_TYPE_JSON)
                    .send(tokenResponseBody);
        });
        routing.post("/wrong-target", (_, response) -> {
            REDIRECT_TARGET_REQUESTS.incrementAndGet();
            response.status(Status.OK_200).send();
        });
        server = WebServer.builder().port(0).tls(tls).addRouting(routing).build().start();
        domainUri = URI.create("https://localhost:" + server.port());
    }

    @AfterAll
    static void stop() {
        if (server != null) {
            server.stop();
        }
    }

    @BeforeEach
    void reset() {
        TOKEN_REQUESTS.set(0);
        REDIRECT_TARGET_REQUESTS.set(0);
        TOKEN_SCOPE.set("");
        redirectTokenEndpoint = false;
        tokenResponseStatus = Status.OK_200;
        tokenResponseBody = JsonObject.builder()
                .set("access_token", "idcs-key-reader")
                .set("token_type", "Bearer")
                .build().toString();
    }

    @Test
    void certificateGrantObtainsKeyReaderTokenOverMutualTls() {
        IdcsTenantAdapter adapter = IdcsTenantAdapter.builder()
                .domainUri(domainUri)
                .jwkSetGrant(IdcsTenantAdapter.JwkSetGrant.TLS_CLIENT_AUTH)
                .build();
        OidcTenantConfig tenant = tenant(adapter);
        WebClient webClient = WebClient.create(tenant.webClient());
        try {
            String accessToken = adapter.jwkSetAccessToken(tenant,
                                                            domainUri.resolve("/admin/v1/SigningCert/jwk"),
                                                            webClient,
                                                            _ -> {
                                                                throw new AssertionError("must not use standard grant");
                                                            }).orElseThrow();
            assertThat(accessToken, is("idcs-key-reader"));
            assertThat(TOKEN_REQUESTS.get(), is(1));
            assertThat(TOKEN_SCOPE.get(), is(JWKS_SCOPE));
            assertThat(REDIRECT_TARGET_REQUESTS.get(), is(0));
        } finally {
            webClient.closeResource();
        }
    }

    @Test
    void configuredJwkScopeReachesTheCertificateGrantRequest() {
        String scope = "https://idcs.example/jwks.read";
        Config config = Config.builder()
                .sources(ConfigSources.create(Map.of("domain-uri", domainUri.toString(),
                                                     "jwks-grant", "tls_client_auth", "jwks-scope", scope)))
                .build();
        IdcsTenantAdapter adapter = IdcsTenantAdapter.create(config);
        OidcTenantConfig tenant = tenant(adapter);
        WebClient webClient = WebClient.create(tenant.webClient());
        try {
            assertThat(adapter.jwkSetAccessToken(tenant,
                                                 tenant.endpoints().jwksUri().orElseThrow(),
                                                 webClient,
                                                 _ -> {
                                                     throw new AssertionError("must not use standard grant");
                                                 }).orElseThrow(),
                       is("idcs-key-reader"));
            assertThat(TOKEN_REQUESTS.get(), is(1));
            assertThat(TOKEN_SCOPE.get(), is(scope));
        } finally {
            webClient.closeResource();
        }
    }

    @Test
    void certificateGrantDoesNotFollowTokenEndpointRedirect() {
        redirectTokenEndpoint = true;
        IdcsTenantAdapter adapter = IdcsTenantAdapter.builder()
                .domainUri(domainUri)
                .jwkSetGrant(IdcsTenantAdapter.JwkSetGrant.TLS_CLIENT_AUTH)
                .build();
        OidcTenantConfig tenant = tenant(adapter);
        WebClient webClient = WebClient.create(tenant.webClient());
        try {
            IllegalStateException failure = assertThrows(IllegalStateException.class,
                                                         () -> adapter.jwkSetAccessToken(
                                                                 tenant,
                                                                 domainUri.resolve("/admin/v1/SigningCert/jwk"),
                                                                 webClient,
                                                                 _ -> "unused"));
            assertThat(failure.getMessage(), containsString("status=307"));
            assertThat(TOKEN_REQUESTS.get(), is(1));
            assertThat(REDIRECT_TARGET_REQUESTS.get(), is(0));
        } finally {
            webClient.closeResource();
        }
    }

    @Test
    void certificateGrantRejectsTokenResponseWithoutTokenType() {
        tokenResponseBody = JsonObject.builder()
                .set("access_token", "idcs-key-reader")
                .build().toString();
        IdcsTenantAdapter adapter = IdcsTenantAdapter.builder()
                .domainUri(domainUri)
                .jwkSetGrant(IdcsTenantAdapter.JwkSetGrant.TLS_CLIENT_AUTH)
                .build();
        OidcTenantConfig tenant = tenant(adapter);
        WebClient webClient = WebClient.create(tenant.webClient());
        try {
            IllegalStateException failure = assertThrows(IllegalStateException.class,
                                                         () -> adapter.jwkSetAccessToken(
                                                                 tenant,
                                                                 domainUri.resolve("/admin/v1/SigningCert/jwk"),
                                                                 webClient,
                                                                 _ -> "unused"));
            assertThat(failure.getMessage(), containsString("Bearer"));
            assertThat(TOKEN_REQUESTS.get(), is(1));
            assertThat(REDIRECT_TARGET_REQUESTS.get(), is(0));
        } finally {
            webClient.closeResource();
        }
    }

    @Test
    void certificateGrantRejectsInvalidResponsesAndRecovers() {
        IdcsTenantAdapter adapter = IdcsTenantAdapter.builder()
                .domainUri(domainUri)
                .jwkSetGrant(IdcsTenantAdapter.JwkSetGrant.TLS_CLIENT_AUTH)
                .build();
        OidcTenantConfig tenant = tenant(adapter);
        WebClient webClient = WebClient.create(tenant.webClient());
        URI jwkSetUri = domainUri.resolve("/admin/v1/SigningCert/jwk");
        try {
            List<String> invalidResponses = List.of(
                    JsonObject.builder().set("access_token", "idcs-key-reader").set("token_type", "")
                            .build().toString(),
                    JsonObject.builder().set("access_token", "idcs-key-reader").set("token_type", "MAC")
                            .build().toString(),
                    JsonObject.builder().set("access_token", "idcs-key-reader").set("token_type", 42)
                            .build().toString(),
                    JsonObject.builder().set("token_type", "Bearer").build().toString(),
                    JsonObject.builder().set("access_token", " ").set("token_type", "Bearer").build().toString(),
                    "{not-json");
            int attempts = 0;
            for (String invalidResponse : invalidResponses) {
                tokenResponseBody = invalidResponse;
                assertThrows(RuntimeException.class,
                             () -> adapter.jwkSetAccessToken(tenant, jwkSetUri, webClient, _ -> "unused"));
                attempts++;
                assertThat(TOKEN_REQUESTS.get(), is(attempts));
            }

            for (Status errorStatus : List.of(Status.BAD_REQUEST_400, Status.INTERNAL_SERVER_ERROR_500)) {
                tokenResponseStatus = errorStatus;
                IllegalStateException failure = assertThrows(IllegalStateException.class,
                                                             () -> adapter.jwkSetAccessToken(tenant,
                                                                                             jwkSetUri,
                                                                                             webClient,
                                                                                             _ -> "unused"));
                assertThat(failure.getMessage(), containsString("status=" + errorStatus.code()));
                attempts++;
                assertThat(TOKEN_REQUESTS.get(), is(attempts));
            }

            tokenResponseStatus = Status.OK_200;
            tokenResponseBody = JsonObject.builder()
                    .set("access_token", "idcs-key-reader")
                    .set("token_type", "bEaReR")
                    .build().toString();
            assertThat(adapter.jwkSetAccessToken(tenant, jwkSetUri, webClient, _ -> "unused").orElseThrow(),
                       is("idcs-key-reader"));
            assertThat(TOKEN_REQUESTS.get(), is(attempts + 1));
            assertThat(REDIRECT_TARGET_REQUESTS.get(), is(0));
        } finally {
            webClient.closeResource();
        }
    }

    private static OidcTenantConfig tenant(IdcsTenantAdapter adapter) {
        return OidcTenantConfig.builder()
                .adapter(adapter)
                .clientId("client")
                .webClient(WebClientConfig.builder().tls(tls -> tls
                        .privateKey(tlsKeys)
                        .privateKeyCertChain(tlsKeys)
                        .trust(tlsKeys.certChain()))
                                   .buildPrototype())
                .buildPrototype();
    }
}
