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

import io.helidon.common.uri.UriQuery;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.tests.integration.security.oidcnext.OidcIntegrationSupport.BrowserSession;
import io.helidon.tests.integration.security.oidcnext.idp.TestOidcServer;
import io.helidon.tests.integration.security.oidcnext.idp.TestOidcTokenResponse;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webserver.WebServer;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class OidcNegativeFlowIT {
    private static final String SERVICE_CLIENT = "service-client";
    private static final String SERVICE_SECRET = "service-secret";

    @Test
    void authorizationCallbackWithTamperedStateIsRejected() {
        int rpPort = OidcIntegrationSupport.reservePort();
        URI rpBaseUri = URI.create("http://localhost:" + rpPort);
        URI callbackUri = rpBaseUri.resolve("/oidc/callback");

        try (TestOidcServer idp = TestOidcServer.builder()
                .client(OidcIntegrationSupport.CLIENT_ID, client -> client
                        .clientSecret(OidcIntegrationSupport.CLIENT_SECRET)
                        .redirectUri(callbackUri))
                .user("alice", user -> user.subject("alice-id"))
                .defaultScopes("openid", "profile")
                .build()) {
            OidcProviderConfig providerConfig = OidcIntegrationSupport.authorizationCodeProviderConfig(idp,
                                                                                                      callbackUri,
                                                                                                      it -> {
                                                                                                      });
            WebServer rpServer = OidcIntegrationSupport.rpServer(providerConfig,
                                                                 rpPort,
                                                                 routing -> OidcIntegrationSupport
                                                                         .protectedRoute(routing, "/resource"));
            try {
                BrowserSession browser = new BrowserSession();
                URI callback = authorizeWithoutBrowser(browser, rpBaseUri.resolve("/resource"));
                URI tamperedCallback = callbackWithState(callbackUri, callback, "tampered-state");

                try (HttpClientResponse response = browser.get(tamperedCallback)) {
                    assertThat(response.status(), is(Status.BAD_REQUEST_400));
                    assertThat(response.as(String.class), containsString("Authorization Response is invalid"));
                }

                assertThat(idp.tokenRequests().size(), is(0));
            } finally {
                rpServer.stop();
            }
        }
    }

    @Test
    void tokenEndpointErrorResponseFailsAuthorizationCallback() {
        int rpPort = OidcIntegrationSupport.reservePort();
        URI rpBaseUri = URI.create("http://localhost:" + rpPort);
        URI callbackUri = rpBaseUri.resolve("/oidc/callback");

        try (TestOidcServer idp = TestOidcServer.builder()
                .client(OidcIntegrationSupport.CLIENT_ID, client -> client
                        .clientSecret(OidcIntegrationSupport.CLIENT_SECRET)
                        .redirectUri(callbackUri))
                .user("alice", user -> user.subject("alice-id"))
                .defaultScopes("openid", "profile")
                .endpoints(endpoints -> endpoints.token(ctx -> ctx.response()
                        .status(Status.BAD_REQUEST_400)
                        .header(HeaderValues.CONTENT_TYPE_JSON)
                        .send(JsonObject.builder()
                                      .set("error", "invalid_grant")
                                      .set("error_description", "test failure")
                                      .build()
                                      .toString())))
                .build()) {
            OidcProviderConfig providerConfig = OidcIntegrationSupport.authorizationCodeProviderConfig(idp,
                                                                                                      callbackUri,
                                                                                                      it -> {
                                                                                                      });
            WebServer rpServer = OidcIntegrationSupport.rpServer(providerConfig,
                                                                 rpPort,
                                                                 routing -> OidcIntegrationSupport
                                                                         .protectedRoute(routing, "/resource"));
            try {
                BrowserSession browser = new BrowserSession();
                URI callback = authorizeWithoutBrowser(browser, rpBaseUri.resolve("/resource"));

                try (HttpClientResponse response = browser.get(callback)) {
                    assertThat(response.status(), is(Status.BAD_GATEWAY_502));
                    assertThat(response.as(String.class), containsString("Token Endpoint returned an Error Response"));
                }

                assertThat(idp.tokenRequests().size(), is(1));
            } finally {
                rpServer.stop();
            }
        }
    }

    @Test
    void invalidIdTokenFailsAuthorizationCallback() {
        int rpPort = OidcIntegrationSupport.reservePort();
        URI rpBaseUri = URI.create("http://localhost:" + rpPort);
        URI callbackUri = rpBaseUri.resolve("/oidc/callback");

        try (TestOidcServer idp = TestOidcServer.builder()
                .client(OidcIntegrationSupport.CLIENT_ID, client -> client
                        .clientSecret(OidcIntegrationSupport.CLIENT_SECRET)
                        .redirectUri(callbackUri))
                .user("alice", user -> user.subject("alice-id"))
                .defaultScopes("openid", "profile")
                .endpoints(endpoints -> endpoints.token(ctx -> {
                    TestOidcTokenResponse tokenResponse = ctx.issueTokens();
                    JsonObject.Builder body = JsonObject.builder()
                            .set("access_token", tokenResponse.accessToken())
                            .set("token_type", tokenResponse.tokenType())
                            .set("id_token", tokenResponse.accessToken());
                    tokenResponse.expiresIn().ifPresent(expiresIn -> body.set("expires_in", expiresIn));
                    tokenResponse.scope().ifPresent(scope -> body.set("scope", scope));
                    tokenResponse.refreshToken().ifPresent(refreshToken -> body.set("refresh_token", refreshToken));
                    ctx.response()
                            .status(Status.OK_200)
                            .header(HeaderValues.CONTENT_TYPE_JSON)
                            .header(HeaderNames.CACHE_CONTROL, "no-store")
                            .header(HeaderNames.PRAGMA, "no-cache")
                            .send(body.build().toString());
                }))
                .build()) {
            OidcProviderConfig providerConfig = OidcIntegrationSupport.authorizationCodeProviderConfig(idp,
                                                                                                      callbackUri,
                                                                                                      it -> {
                                                                                                      });
            WebServer rpServer = OidcIntegrationSupport.rpServer(providerConfig,
                                                                 rpPort,
                                                                 routing -> OidcIntegrationSupport
                                                                         .protectedRoute(routing, "/resource"));
            try {
                BrowserSession browser = new BrowserSession();
                URI callback = authorizeWithoutBrowser(browser, rpBaseUri.resolve("/resource"));

                try (HttpClientResponse response = browser.get(callback)) {
                    assertThat(response.status(), is(Status.BAD_GATEWAY_502));
                    assertThat(response.as(String.class), containsString("ID Token is invalid"));
                }

                assertThat(idp.tokenRequests().size(), is(1));
            } finally {
                rpServer.stop();
            }
        }
    }

    @Test
    void protectedResourceRejectsJwtAccessTokenWithWrongAudience() {
        int rpPort = OidcIntegrationSupport.reservePort();
        URI rpBaseUri = URI.create("http://localhost:" + rpPort);

        try (TestOidcServer idp = TestOidcServer.builder()
                .client(SERVICE_CLIENT, SERVICE_SECRET)
                .defaultScopes("service.read")
                .tokenDefaults(tokens -> tokens
                        .accessToken(accessToken -> accessToken.audience("other-service")))
                .build()) {
            String accessToken = OidcIntegrationSupport.clientCredentialsToken(idp, SERVICE_CLIENT, SERVICE_SECRET);
            OidcProviderConfig providerConfig = OidcIntegrationSupport.protectedResourceProviderConfig(idp,
                                                                                                      SERVICE_CLIENT,
                                                                                                      SERVICE_CLIENT);
            WebServer rpServer = OidcIntegrationSupport.rpServer(providerConfig,
                                                                 rpPort,
                                                                 routing -> OidcIntegrationSupport
                                                                         .protectedRoute(routing, "/api"));
            try {
                WebClient client = WebClient.builder()
                        .baseUri(rpBaseUri)
                        .build();

                try (HttpClientResponse response = client.get("/api")
                        .header(HeaderNames.AUTHORIZATION, "Bearer " + accessToken)
                        .request()) {
                    assertThat(response.status(), is(Status.UNAUTHORIZED_401));
                }

                assertThat(idp.tokenRequests().getFirst().formParam("grant_type").orElse(""),
                           is("client_credentials"));
            } finally {
                rpServer.stop();
            }
        }
    }

    private static URI authorizeWithoutBrowser(BrowserSession browser, URI resourceUri) {
        try (HttpClientResponse start = browser.get(resourceUri)) {
            assertThat(start.status(), is(Status.SEE_OTHER_303));
            URI authorizationUri = URI.create(start.headers().first(HeaderNames.LOCATION).orElseThrow());

            try (HttpClientResponse authorization = browser.get(authorizationUri)) {
                assertThat(authorization.status(), is(Status.SEE_OTHER_303));
                return URI.create(authorization.headers().first(HeaderNames.LOCATION).orElseThrow());
            }
        }
    }

    private static URI callbackWithState(URI callbackUri, URI callback, String state) {
        UriQuery query = UriQuery.create(callback);
        return URI.create(callbackUri + "?code=" + query.all("code").getFirst() + "&state=" + state);
    }
}
