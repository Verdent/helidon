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

package io.helidon.tests.integration.security.oidcnext;

import java.net.URI;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import io.helidon.common.parameters.Parameters;
import io.helidon.common.uri.UriQuery;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.security.providers.oidc.next.OidcTokenValidationMethod;
import io.helidon.tests.integration.security.oidcnext.idp.TestOidcServer;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webserver.WebServer;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class OidcAccessTokenValidationIT {
    private static final String SERVICE_CLIENT = "service-client";
    private static final String SERVICE_SECRET = "service-secret";
    private static final String USER_CLIENT = "user-client";
    private static final String USER_SECRET = "user-secret";
    private static final URI REDIRECT_URI = URI.create("http://localhost/callback");

    @Test
    void protectedResourceValidatesJwtAccessTokenThroughJwks() {
        try (TestOidcServer idp = TestOidcServer.builder()
                .client(SERVICE_CLIENT, SERVICE_SECRET)
                .defaultScopes("service.read")
                .build()) {
            String accessToken = OidcIntegrationSupport.clientCredentialsToken(idp, SERVICE_CLIENT, SERVICE_SECRET);
            OidcProviderConfig providerConfig = OidcIntegrationSupport.protectedResourceProviderConfig(idp,
                                                                                                      SERVICE_CLIENT,
                                                                                                      SERVICE_CLIENT);
            WebServer rpServer = OidcIntegrationSupport.rpServer(providerConfig,
                                                                 routing -> OidcIntegrationSupport
                                                                         .protectedRoute(routing, "/api"));
            try {
                URI rpBaseUri = OidcIntegrationSupport.rpBaseUri(rpServer);
                WebClient client = WebClient.builder()
                        .baseUri(rpBaseUri)
                        .build();
                try {
                    try (HttpClientResponse response = client.get("/api")
                            .header(HeaderNames.AUTHORIZATION, "Bearer " + accessToken)
                            .request()) {
                        assertThat(response.status(), is(Status.OK_200));
                        assertThat(response.as(String.class), is("service-client|service-client|"));
                    }

                    assertThat(idp.tokenRequests().getFirst().formParam("grant_type").orElse(""),
                               is("client_credentials"));
                } finally {
                    client.closeResource();
                }
            } finally {
                rpServer.stop();
            }
        }
    }

    @Test
    void protectedResourceReloadsJwksWhenAccessTokenKeyIdIsUnknown() {
        AtomicInteger jwksResponses = new AtomicInteger();
        try (TestOidcServer idp = TestOidcServer.builder()
                .client(SERVICE_CLIENT, SERVICE_SECRET)
                .defaultScopes("service.read")
                .endpoints(endpoints -> endpoints.jwks(ctx -> {
                    if (jwksResponses.getAndIncrement() == 0) {
                        ctx.response()
                                .header(HeaderValues.CONTENT_TYPE_JSON)
                                .send("{\"keys\":[]}");
                        return;
                    }
                    ctx.sendDefault();
                }))
                .build()) {
            String accessToken = OidcIntegrationSupport.clientCredentialsToken(idp, SERVICE_CLIENT, SERVICE_SECRET);
            OidcProviderConfig providerConfig = OidcIntegrationSupport.protectedResourceProviderConfig(
                    idp,
                    SERVICE_CLIENT,
                    null,
                    SERVICE_CLIENT,
                    OidcTokenValidationMethod.JWT,
                    tenant -> tenant.jwkSet(jwkSet -> jwkSet.unknownKeyIdRefreshInterval(Duration.ZERO)));
            WebServer rpServer = OidcIntegrationSupport.rpServer(providerConfig,
                                                                 routing -> OidcIntegrationSupport
                                                                         .protectedRoute(routing, "/api"));
            try {
                URI rpBaseUri = OidcIntegrationSupport.rpBaseUri(rpServer);
                WebClient client = WebClient.builder()
                        .baseUri(rpBaseUri)
                        .build();
                try {
                    try (HttpClientResponse response = client.get("/api")
                            .header(HeaderNames.AUTHORIZATION, "Bearer " + accessToken)
                            .request()) {
                        assertThat(response.status(), is(Status.OK_200));
                        assertThat(response.as(String.class), is("service-client|service-client|"));
                    }

                    assertThat(idp.jwksRequests().size(), is(2));
                } finally {
                    client.closeResource();
                }
            } finally {
                rpServer.stop();
            }
        }
    }

    @Test
    void protectedResourceValidatesOpaqueAccessTokenThroughIntrospection() {
        try (TestOidcServer idp = TestOidcServer.builder()
                .client(SERVICE_CLIENT, SERVICE_SECRET)
                .defaultScopes("service.read")
                .tokenDefaults(tokens -> tokens
                        .accessToken(accessToken -> accessToken.opaque(true)))
                .build()) {
            String accessToken = OidcIntegrationSupport.clientCredentialsToken(idp, SERVICE_CLIENT, SERVICE_SECRET);
            OidcProviderConfig providerConfig = OidcIntegrationSupport.protectedResourceProviderConfig(
                    idp,
                    SERVICE_CLIENT,
                    SERVICE_SECRET,
                    SERVICE_CLIENT,
                    OidcTokenValidationMethod.INTROSPECTION);
            WebServer rpServer = OidcIntegrationSupport.rpServer(providerConfig,
                                                                 routing -> OidcIntegrationSupport
                                                                         .protectedRoute(routing, "/api"));
            try {
                URI rpBaseUri = OidcIntegrationSupport.rpBaseUri(rpServer);
                WebClient client = WebClient.builder()
                        .baseUri(rpBaseUri)
                        .build();
                try {
                    try (HttpClientResponse response = client.get("/api")
                            .header(HeaderNames.AUTHORIZATION, "Bearer " + accessToken)
                            .request()) {
                        assertThat(response.status(), is(Status.OK_200));
                        assertThat(response.as(String.class), is("service-client|service-client|"));
                    }

                    assertThat(accessToken.startsWith("opaque-access-"), is(true));
                    assertThat(accessToken.contains("."), is(false));
                    assertThat(idp.introspectionRequests().size(), is(1));
                    assertThat(idp.introspectionRequests().getFirst().formParam("token").orElse(""), is(accessToken));
                    assertThat(idp.introspectionRequests().getFirst().formParam("token_type_hint").orElse(""),
                               is("access_token"));
                } finally {
                    client.closeResource();
                }
            } finally {
                rpServer.stop();
            }
        }
    }

    @Test
    void introspectionIncludesConfiguredAccessTokenClaims() {
        try (TestOidcServer idp = TestOidcServer.builder()
                .client(USER_CLIENT, USER_SECRET)
                .user("alice", user -> user
                        .subject("alice-id")
                        .claim("email", "alice@example.org")
                        .claim("preferred_username", "alice"))
                .defaultScopes("openid", "profile")
                .tokenDefaults(tokens -> tokens
                        .accessToken(accessToken -> accessToken
                                .opaque(true)
                                .includeUserClaims("email")
                                .claim("tier", "gold")))
                .build()) {
            WebClient client = WebClient.builder()
                    .followRedirects(false)
                    .build();
            try {
                String accessToken = authorizationCodeAccessToken(idp, client);
                JsonObject introspection = introspect(idp, client, USER_CLIENT, USER_SECRET, accessToken);

                assertThat(introspection.booleanValue("active").orElseThrow(), is(true));
                assertThat(introspection.stringValue("sub").orElseThrow(), is("alice-id"));
                assertThat(introspection.stringValue("username").orElseThrow(), is("alice"));
                assertThat(introspection.stringValue("email").orElseThrow(), is("alice@example.org"));
                assertThat(introspection.stringValue("tier").orElseThrow(), is("gold"));
                assertThat(introspection.containsKey("preferred_username"), is(false));
            } finally {
                client.closeResource();
            }
        }
    }

    @Test
    void protectedResourceRejectsUnknownOpaqueAccessTokenThroughIntrospection() {
        try (TestOidcServer idp = TestOidcServer.builder()
                .client(SERVICE_CLIENT, SERVICE_SECRET)
                .build()) {
            OidcProviderConfig providerConfig = OidcIntegrationSupport.protectedResourceProviderConfig(
                    idp,
                    SERVICE_CLIENT,
                    SERVICE_SECRET,
                    SERVICE_CLIENT,
                    OidcTokenValidationMethod.INTROSPECTION);
            WebServer rpServer = OidcIntegrationSupport.rpServer(providerConfig,
                                                                 routing -> OidcIntegrationSupport
                                                                         .protectedRoute(routing, "/api"));
            try {
                URI rpBaseUri = OidcIntegrationSupport.rpBaseUri(rpServer);
                WebClient client = WebClient.builder()
                        .baseUri(rpBaseUri)
                        .build();
                try {
                    try (HttpClientResponse response = client.get("/api")
                            .header(HeaderNames.AUTHORIZATION, "Bearer unknown-opaque-token")
                            .request()) {
                        assertThat(response.status(), is(Status.UNAUTHORIZED_401));
                    }

                    assertThat(idp.introspectionRequests().size(), is(1));
                    assertThat(idp.introspectionRequests().getFirst().formParam("token").orElse(""),
                               is("unknown-opaque-token"));
                } finally {
                    client.closeResource();
                }
            } finally {
                rpServer.stop();
            }
        }
    }

    @Test
    void protectedResourceRejectsExpiredOpaqueAccessTokenThroughIntrospection() {
        try (TestOidcServer idp = TestOidcServer.builder()
                .client(USER_CLIENT, USER_SECRET)
                .user("alice", user -> user.subject("alice-id"))
                .defaultScopes("openid", "profile")
                .tokenDefaults(tokens -> tokens
                        .accessToken(accessToken -> accessToken
                                .opaque(true)
                                .expiresIn(Duration.ZERO)))
                .build()) {
            WebClient client = WebClient.builder()
                    .followRedirects(false)
                    .build();
            try {
                String accessToken = authorizationCodeAccessToken(idp, client);
                OidcProviderConfig providerConfig = OidcIntegrationSupport.protectedResourceProviderConfig(
                        idp,
                        USER_CLIENT,
                        USER_SECRET,
                        USER_CLIENT,
                        OidcTokenValidationMethod.INTROSPECTION);
                WebServer rpServer = OidcIntegrationSupport.rpServer(providerConfig,
                                                                     routing -> OidcIntegrationSupport
                                                                             .protectedRoute(routing, "/api"));
                try {
                    URI resourceUri = OidcIntegrationSupport.rpBaseUri(rpServer).resolve("/api");
                    try (HttpClientResponse response = client.get()
                            .uri(resourceUri)
                            .header(HeaderNames.AUTHORIZATION, "Bearer " + accessToken)
                            .request()) {
                        assertThat(response.status(), is(Status.UNAUTHORIZED_401));
                    }

                    assertThat(idp.introspectionRequests().size(), is(1));
                    assertThat(idp.introspectionRequests().getFirst().formParam("token").orElse(""), is(accessToken));

                    JsonObject introspection = introspect(idp, client, USER_CLIENT, USER_SECRET, accessToken);
                    assertThat(introspection.booleanValue("active").orElseThrow(), is(false));

                    try (HttpClientResponse response = client.get()
                            .uri(idp.userInfoEndpointUri())
                            .header(HeaderNames.AUTHORIZATION, "Bearer " + accessToken)
                            .request()) {
                        assertThat(response.status(), is(Status.UNAUTHORIZED_401));
                    }

                    assertThat(idp.introspectionRequests().size(), is(2));
                    assertThat(idp.introspectionRequests().get(1).formParam("token").orElse(""), is(accessToken));
                } finally {
                    rpServer.stop();
                }
            } finally {
                client.closeResource();
            }
        }
    }

    private static String authorizationCodeAccessToken(TestOidcServer idp, WebClient client) {
        URI authorizationUri = URI.create(idp.authorizationEndpointUri()
                                                  + "?response_type=code"
                                                  + "&client_id=" + USER_CLIENT
                                                  + "&redirect_uri=" + REDIRECT_URI
                                                  + "&scope=openid%20profile");
        URI callback;
        try (HttpClientResponse response = client.get().uri(authorizationUri).request()) {
            assertThat(response.status(), is(Status.SEE_OTHER_303));
            callback = URI.create(response.headers().first(HeaderNames.LOCATION).orElseThrow());
        }

        Parameters form = Parameters.builder("authorization-code-token")
                .add("grant_type", "authorization_code")
                .add("code", UriQuery.create(callback).all("code").getFirst())
                .add("redirect_uri", REDIRECT_URI.toString())
                .build();
        try (HttpClientResponse response = client.post()
                .uri(idp.tokenEndpointUri())
                .header(HeaderNames.AUTHORIZATION, OidcIntegrationSupport.basicAuthorization(USER_CLIENT, USER_SECRET))
                .submit(form)) {
            assertThat(response.status(), is(Status.OK_200));
            JsonObject tokenResponse = JsonParser.create(response.as(String.class)).readJsonObject();
            return tokenResponse.stringValue("access_token").orElseThrow();
        }
    }

    private static JsonObject introspect(TestOidcServer idp,
                                         WebClient client,
                                         String clientId,
                                         String clientSecret,
                                         String accessToken) {
        Parameters form = Parameters.builder("introspection")
                .add("token", accessToken)
                .add("token_type_hint", "access_token")
                .build();
        try (HttpClientResponse response = client.post()
                .uri(idp.introspectionEndpointUri())
                .header(HeaderNames.AUTHORIZATION, OidcIntegrationSupport.basicAuthorization(clientId, clientSecret))
                .submit(form)) {
            assertThat(response.status(), is(Status.OK_200));
            return JsonParser.create(response.as(String.class)).readJsonObject();
        }
    }
}
