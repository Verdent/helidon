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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import io.helidon.common.configurable.Resource;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.SetCookie;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.http.ServerResponse;
import io.helidon.webserver.testing.junit5.ServerTest;
import io.helidon.webserver.testing.junit5.SetUpRoute;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;

@ServerTest
class OidcFeatureRouteTest {
    private static final URI ISSUER = URI.create("https://issuer.example");
    private static final URI AUTHORIZATION_ENDPOINT_URI = URI.create("https://issuer.example/authorize");
    private static final URI TOKEN_ENDPOINT_URI = URI.create("https://issuer.example/token");
    private static final URI CONFIGURED_REDIRECTION_ENDPOINT_URI = URI.create("https://rp.example/oidc/callback");
    private static final String COOKIE_SECRET = "test-cookie-secret";
    private static final String CLIENT_ID = "client-id";
    private static final String CLIENT_SECRET = "client-secret";
    private static final String SUBJECT = "user1-id";
    private static final String STATE = "stored-state";
    private static final String NONCE = "nonce";
    private static final String PKCE_VERIFIER = "pkce-verifier";

    private static JwkKeys signKeys;
    private static String verifyJwkSet;
    private static String tokenEndpointResponseBody;

    @BeforeAll
    static void initClass() {
        signKeys = JwkKeys.builder()
                .resource(Resource.create("oidc-next-sign-jwk.json"))
                .build();
        verifyJwkSet = Resource.create("oidc-next-verify-jwk.json").string();
    }

    @SetUpRoute
    static void routing(HttpRouting.Builder routing) {
        OidcFeature.create(providerConfig()).setup(routing);
        routing.post("/token", (request, response) -> tokenEndpointResponse(response));
        routing.get("/jwks", (request, response) -> response.header(HeaderValues.CONTENT_TYPE_JSON)
                .send(verifyJwkSet));
    }

    @BeforeEach
    void setUp() {
        tokenEndpointResponseBody = tokenEndpointResponse(signedIdToken(NONCE)).toString();
    }

    @Test
    void redirectionEndpointRouteRejectsMissingState(WebClient client) {
        try (HttpClientResponse response = client.get("/oidc/callback")
                .queryParam("code", "authorization-code")
                .request()) {
            assertThat(response.status(), is(Status.BAD_REQUEST_400));
            assertThat(response.as(String.class), is("Authorization Response is invalid"));
        }
    }

    @Test
    void redirectionEndpointRouteHandlesAuthorizationErrorBeforeTokenExchange(WebClient client, URI serverUri) {
        Instant now = Instant.now();
        URI callbackUri = serverUri.resolve("oidc/callback");
        SetCookie stateCookie = OidcCookieStateHandler.create(tenantConfig())
                .createAuthenticationRequestCookie(OidcAuthenticationRequestState.create("default",
                                                                                         "stored-state",
                                                                                         "nonce",
                                                                                         "pkce-verifier",
                                                                                         serverUri.resolve("resource"),
                                                                                         callbackUri,
                                                                                         now.minusSeconds(1),
                                                                                         now.plusSeconds(60)));

        try (HttpClientResponse response = client.get("/oidc/callback")
                .queryParam("error", "access_denied")
                .queryParam("state", "stored-state")
                .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                .request()) {
            assertThat(response.status(), is(Status.BAD_REQUEST_400));
            assertThat(response.as(String.class), is("OpenID Provider returned an Authorization Error Response"));

            List<String> removalCookies = response.headers().get(HeaderNames.SET_COOKIE).allValues();
            assertThat(removalCookies.size(), is(1));
            assertThat(removalCookies.getFirst(), containsString("__Host-helidon-oidc-state="));
            assertThat(removalCookies.getFirst(), containsString("Expires="));
        }
    }

    @Test
    void redirectionEndpointRouteValidatesIdToken(URI serverUri) {
        WebServer rpServer = redirectionEndpointServer(serverUri);
        try {
            URI callbackUri = callbackUri(rpServer);
            SetCookie stateCookie = authenticationRequestCookie(callbackUri, tenantConfig(serverUri));

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .get("/oidc/callback")
                    .queryParam("code", "authorization-code")
                    .queryParam("state", STATE)
                    .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.NOT_IMPLEMENTED_501));
                assertThat(response.as(String.class), is("Local authentication result storage is not implemented yet"));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void redirectionEndpointRouteRejectsInvalidIdToken(URI serverUri) {
        tokenEndpointResponseBody = tokenEndpointResponse(signedIdToken("other-nonce")).toString();
        WebServer rpServer = redirectionEndpointServer(serverUri);
        try {
            URI callbackUri = callbackUri(rpServer);
            SetCookie stateCookie = authenticationRequestCookie(callbackUri, tenantConfig(serverUri));

            try (HttpClientResponse response = WebClient.builder()
                    .baseUri(rpBaseUri(rpServer))
                    .build()
                    .get("/oidc/callback")
                    .queryParam("code", "authorization-code")
                    .queryParam("state", STATE)
                    .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                    .request()) {
                assertThat(response.status(), is(Status.BAD_GATEWAY_502));
                assertThat(response.as(String.class), is("ID Token is invalid"));
            }
        } finally {
            rpServer.stop();
        }
    }

    private static OidcProviderConfig providerConfig() {
        return OidcProviderConfig.builder()
                .putTenant("default", tenantConfig())
                .buildPrototype();
    }

    private static OidcProviderConfig providerConfig(URI openIdProviderUri) {
        return OidcProviderConfig.builder()
                .putTenant("default", tenantConfig(openIdProviderUri))
                .buildPrototype();
    }

    private static OidcTenantConfig tenantConfig() {
        return OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.enabled(true)
                        .redirectionEndpointUri(CONFIGURED_REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret(COOKIE_SECRET))
                .buildPrototype();
    }

    private static OidcTenantConfig tenantConfig(URI openIdProviderUri) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(openIdProviderUri.resolve("token"))
                        .jwksUri(openIdProviderUri.resolve("jwks"))
                        .tlsRequired(false))
                .authorizationCode(it -> it.enabled(true)
                        .redirectionEndpointUri(CONFIGURED_REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret(COOKIE_SECRET))
                .buildPrototype();
    }

    private static void tokenEndpointResponse(ServerResponse response) {
        response.header(HeaderValues.CONTENT_TYPE_JSON)
                .send(tokenEndpointResponseBody);
    }

    private static JsonObject tokenEndpointResponse(String idToken) {
        return JsonObject.builder()
                .set("access_token", "access-token")
                .set("token_type", "Bearer")
                .set("id_token", idToken)
                .build();
    }

    private static WebServer redirectionEndpointServer(URI openIdProviderUri) {
        HttpRouting.Builder routing = HttpRouting.builder();
        OidcFeature.create(providerConfig(openIdProviderUri)).setup(routing);
        return WebServer.builder()
                .addRouting(routing)
                .port(0)
                .build()
                .start();
    }

    private static SetCookie authenticationRequestCookie(URI callbackUri, OidcTenantConfig tenant) {
        Instant now = Instant.now();
        URI originalUri = URI.create("https://rp.example/resource");
        return OidcCookieStateHandler.create(tenant)
                .createAuthenticationRequestCookie(OidcAuthenticationRequestState.create("default",
                                                                                         STATE,
                                                                                         NONCE,
                                                                                         PKCE_VERIFIER,
                                                                                         originalUri,
                                                                                         callbackUri,
                                                                                         now.minusSeconds(1),
                                                                                         now.plusSeconds(60)));
    }

    private static URI rpBaseUri(WebServer server) {
        return URI.create("http://localhost:" + server.port());
    }

    private static URI callbackUri(WebServer server) {
        return rpBaseUri(server).resolve("/oidc/callback");
    }

    private static String signedIdToken(String nonce) {
        Instant now = Instant.now();
        Jwt jwt = Jwt.builder()
                .type("JWT")
                .subject(SUBJECT)
                .issuer(ISSUER.toString())
                .algorithm("RS256")
                .keyId("verify-rsa")
                .issueTime(now)
                .expirationTime(now.plus(1, ChronoUnit.HOURS))
                .addAudience(CLIENT_ID)
                .nonce(nonce)
                .build();
        return SignedJwt.sign(jwt, signKeys.forKeyId("sign-rsa").orElseThrow())
                .tokenContent();
    }
}
