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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

import io.helidon.common.uri.UriQuery;
import io.helidon.http.HeaderNames;
import io.helidon.http.Status;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.tests.integration.security.oidcnext.OidcIntegrationSupport.BrowserSession;
import io.helidon.tests.integration.security.oidcnext.idp.TestOidcServer;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webserver.WebServer;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class OidcAuthorizationCodeFlowIT {
    @Test
    void browserAuthorizationCodeFlowAuthenticatesProtectedResource() {
        try (TestOidcServer idp = TestOidcServer.builder()
                .client(OidcIntegrationSupport.CLIENT_ID, client -> client
                        .clientSecret(OidcIntegrationSupport.CLIENT_SECRET))
                .user("alice", user -> user
                        .subject("alice-id")
                        .password("secret")
                        .claim("preferred_username", "alice")
                        .claim("email", "alice@example.org"))
                .defaultScopes("openid", "profile")
                .tokenDefaults(tokens -> tokens
                        .idToken(id -> id.includeUserClaims("preferred_username")))
                .browserLogin(true)
                .build()) {
            OidcProviderConfig providerConfig = OidcIntegrationSupport.authorizationCodeProviderConfig(idp,
                                                                                                      it -> {
                                                                                                      });
            WebServer rpServer = OidcIntegrationSupport.rpServer(providerConfig,
                                                                 routing -> OidcIntegrationSupport
                                                                         .protectedRoute(routing, "/resource"));
            try {
                BrowserSession browser = new BrowserSession();
                URI rpBaseUri = OidcIntegrationSupport.rpBaseUri(rpServer);

                URI resourceUri = rpBaseUri.resolve("/resource");
                try (HttpClientResponse response = browser.get(resourceUri)) {
                    assertThat(response.status(), is(Status.SEE_OTHER_303));
                    URI authorizationUri = URI.create(response.headers()
                                                              .first(HeaderNames.LOCATION)
                                                              .orElseThrow());
                    assertThat(authorizationUri.getPath(), is("/authorize"));

                    try (HttpClientResponse loginForm = browser.get(authorizationUri)) {
                        assertThat(loginForm.status(), is(Status.OK_200));
                        assertThat(loginForm.as(String.class), containsString("<form method=\"post\""));
                    }

                    try (HttpClientResponse login = browser.post(idp.issuer().resolve("/authorize/login"),
                                                                 OidcIntegrationSupport.loginForm(authorizationUri,
                                                                                                  "alice",
                                                                                                  "secret"))) {
                        assertThat(login.status(), is(Status.SEE_OTHER_303));
                        URI callback = URI.create(login.headers().first(HeaderNames.LOCATION).orElseThrow());
                        assertThat(callback.getPath(), is("/oidc/callback"));

                        try (HttpClientResponse callbackResponse = browser.get(callback)) {
                            assertThat(callbackResponse.status(), is(Status.SEE_OTHER_303));
                            assertThat(URI.create(callbackResponse.headers()
                                                          .first(HeaderNames.LOCATION)
                                                          .orElseThrow())
                                               .getPath(),
                                       is("/resource"));
                        }
                    }
                }

                try (HttpClientResponse authenticated = browser.get(resourceUri)) {
                    assertThat(authenticated.status(), is(Status.OK_200));
                    assertThat(authenticated.as(String.class), is("alice-id|alice|alice@example.org"));
                }

                assertThat(idp.tokenRequests().size(), is(1));
                assertThat(idp.userInfoRequests().size(), is(1));
            } finally {
                rpServer.stop();
            }
        }
    }

    @Test
    void authorizationCodeFlowAuthenticatesWithOpaqueAccessToken() {
        try (TestOidcServer idp = TestOidcServer.builder()
                .client(OidcIntegrationSupport.CLIENT_ID, client -> client
                        .clientSecret(OidcIntegrationSupport.CLIENT_SECRET))
                .user("alice", user -> user
                        .subject("alice-id")
                        .claim("preferred_username", "alice")
                        .claim("email", "alice@example.org"))
                .defaultScopes("openid", "profile")
                .tokenDefaults(tokens -> tokens
                        .accessToken(accessToken -> accessToken.opaque(true))
                        .idToken(id -> id.includeUserClaims("preferred_username")))
                .build()) {
            OidcProviderConfig providerConfig = OidcIntegrationSupport.authorizationCodeProviderConfig(idp,
                                                                                                      it -> {
                                                                                                      });
            WebServer rpServer = OidcIntegrationSupport.rpServer(providerConfig,
                                                                 routing -> OidcIntegrationSupport
                                                                         .protectedRoute(routing, "/resource"));
            try {
                BrowserSession browser = new BrowserSession();
                URI rpBaseUri = OidcIntegrationSupport.rpBaseUri(rpServer);
                URI resourceUri = rpBaseUri.resolve("/resource");
                URI callback = authorizeWithoutBrowser(browser, resourceUri);

                try (HttpClientResponse callbackResponse = browser.get(callback)) {
                    assertThat(callbackResponse.status(), is(Status.SEE_OTHER_303));
                }

                try (HttpClientResponse authenticated = browser.get(resourceUri)) {
                    assertThat(authenticated.status(), is(Status.OK_200));
                    assertThat(authenticated.as(String.class), is("alice-id|alice|alice@example.org"));
                }

                assertThat(idp.tokenRequests().size(), is(1));
                assertThat(idp.tokenRequests().getFirst().formParam("grant_type").orElse(""),
                           is("authorization_code"));
                assertThat(idp.userInfoRequests().size(), is(1));
                String userInfoToken = idp.userInfoRequests().getFirst().bearerToken().orElseThrow();
                assertThat(userInfoToken.startsWith("opaque-access-"), is(true));
                assertThat(userInfoToken.contains("."), is(false));
            } finally {
                rpServer.stop();
            }
        }
    }

    @Test
    void authorizationCodeFlowValidatesSupportedAuthorizationResponseIssuer() {
        try (TestOidcServer idp = TestOidcServer.builder()
                .client(OidcIntegrationSupport.CLIENT_ID, client -> client
                        .clientSecret(OidcIntegrationSupport.CLIENT_SECRET))
                .user("alice", user -> user
                        .subject("alice-id")
                        .claim("preferred_username", "alice")
                        .claim("email", "alice@example.org"))
                .defaultScopes("openid", "profile")
                .metadata("authorization_response_iss_parameter_supported", true)
                .tokenDefaults(tokens -> tokens
                        .idToken(id -> id.includeUserClaims("preferred_username")))
                .build()) {
            OidcProviderConfig providerConfig = OidcIntegrationSupport.authorizationCodeProviderConfigFromWellKnown(idp,
                                                                                                                    it -> {
                                                                                                                    });
            WebServer rpServer = OidcIntegrationSupport.rpServer(providerConfig,
                                                                 routing -> OidcIntegrationSupport
                                                                         .protectedRoute(routing, "/resource"));
            try {
                BrowserSession browser = new BrowserSession();
                URI resourceUri = OidcIntegrationSupport.rpBaseUri(rpServer).resolve("/resource");
                URI callback = authorizeWithoutBrowser(browser, resourceUri);

                assertThat(UriQuery.create(callback).all("iss").getFirst(), is(idp.issuer().toString()));

                try (HttpClientResponse callbackResponse = browser.get(callback)) {
                    assertThat(callbackResponse.status(), is(Status.SEE_OTHER_303));
                }

                try (HttpClientResponse authenticated = browser.get(resourceUri)) {
                    assertThat(authenticated.status(), is(Status.OK_200));
                    assertThat(authenticated.as(String.class), is("alice-id|alice|alice@example.org"));
                }

                assertThat(idp.tokenRequests().size(), is(1));
            } finally {
                rpServer.stop();
            }
        }
    }

    @Test
    void authorizationCodeFlowRejectsWrongAuthorizationResponseIssuer() {
        try (TestOidcServer idp = TestOidcServer.builder()
                .client(OidcIntegrationSupport.CLIENT_ID, client -> client
                        .clientSecret(OidcIntegrationSupport.CLIENT_SECRET))
                .user("alice", user -> user
                        .subject("alice-id")
                        .claim("preferred_username", "alice")
                        .claim("email", "alice@example.org"))
                .defaultScopes("openid", "profile")
                .metadata("authorization_response_iss_parameter_supported", true)
                .tokenDefaults(tokens -> tokens
                        .idToken(id -> id.includeUserClaims("preferred_username")))
                .build()) {
            OidcProviderConfig providerConfig = OidcIntegrationSupport.authorizationCodeProviderConfigFromWellKnown(idp,
                                                                                                                    it -> {
                                                                                                                    });
            WebServer rpServer = OidcIntegrationSupport.rpServer(providerConfig,
                                                                 routing -> OidcIntegrationSupport
                                                                         .protectedRoute(routing, "/resource"));
            try {
                BrowserSession browser = new BrowserSession();
                URI resourceUri = OidcIntegrationSupport.rpBaseUri(rpServer).resolve("/resource");
                URI callback = callbackWithIssuer(authorizeWithoutBrowser(browser, resourceUri),
                                                  "https://other.example");

                try (HttpClientResponse callbackResponse = browser.get(callback)) {
                    assertThat(callbackResponse.status(), is(Status.BAD_REQUEST_400));
                    assertThat(callbackResponse.as(String.class), is("Authorization Response is invalid"));
                }

                assertThat(idp.tokenRequests().size(), is(0));
            } finally {
                rpServer.stop();
            }
        }
    }

    @Test
    void authorizationCodeFlowRejectsMissingSupportedAuthorizationResponseIssuer() {
        try (TestOidcServer idp = TestOidcServer.builder()
                .client(OidcIntegrationSupport.CLIENT_ID, client -> client
                        .clientSecret(OidcIntegrationSupport.CLIENT_SECRET))
                .user("alice", user -> user
                        .subject("alice-id")
                        .claim("preferred_username", "alice")
                        .claim("email", "alice@example.org"))
                .defaultScopes("openid", "profile")
                .metadata("authorization_response_iss_parameter_supported", true)
                .tokenDefaults(tokens -> tokens
                        .idToken(id -> id.includeUserClaims("preferred_username")))
                .build()) {
            OidcProviderConfig providerConfig = OidcIntegrationSupport.authorizationCodeProviderConfigFromWellKnown(idp,
                                                                                                                    it -> {
                                                                                                                    });
            WebServer rpServer = OidcIntegrationSupport.rpServer(providerConfig,
                                                                 routing -> OidcIntegrationSupport
                                                                         .protectedRoute(routing, "/resource"));
            try {
                BrowserSession browser = new BrowserSession();
                URI resourceUri = OidcIntegrationSupport.rpBaseUri(rpServer).resolve("/resource");
                URI callback = callbackWithoutIssuer(authorizeWithoutBrowser(browser, resourceUri));

                try (HttpClientResponse callbackResponse = browser.get(callback)) {
                    assertThat(callbackResponse.status(), is(Status.BAD_REQUEST_400));
                    assertThat(callbackResponse.as(String.class), is("Authorization Response is invalid"));
                }

                assertThat(idp.tokenRequests().size(), is(0));
            } finally {
                rpServer.stop();
            }
        }
    }

    @Test
    void authorizationCodeFlowRefreshesOpaqueAccessToken() {
        try (TestOidcServer idp = TestOidcServer.builder()
                .client(OidcIntegrationSupport.CLIENT_ID, client -> client
                        .clientSecret(OidcIntegrationSupport.CLIENT_SECRET))
                .user("alice", user -> user
                        .subject("alice-id")
                        .claim("preferred_username", "alice")
                        .claim("email", "alice@example.org"))
                .defaultScopes("openid", "profile")
                .tokenDefaults(tokens -> tokens
                        .accessToken(accessToken -> accessToken
                                .opaque(true)
                                .expiresIn(Duration.ofSeconds(30)))
                        .idToken(id -> id.includeUserClaims("preferred_username"))
                        .refreshToken(refresh -> refresh
                                .enabled(true)
                                .idTokenEnabled(true)))
                .build()) {
            OidcProviderConfig providerConfig = OidcIntegrationSupport.authorizationCodeProviderConfig(idp,
                                                                                                      it -> {
                                                                                                      });
            WebServer rpServer = OidcIntegrationSupport.rpServer(providerConfig,
                                                                 routing -> OidcIntegrationSupport
                                                                         .protectedRoute(routing, "/resource"));
            try {
                BrowserSession browser = new BrowserSession();
                URI rpBaseUri = OidcIntegrationSupport.rpBaseUri(rpServer);
                URI resourceUri = rpBaseUri.resolve("/resource");
                URI callback = authorizeWithoutBrowser(browser, resourceUri);

                try (HttpClientResponse callbackResponse = browser.get(callback)) {
                    assertThat(callbackResponse.status(), is(Status.SEE_OTHER_303));
                }

                try (HttpClientResponse authenticated = browser.get(resourceUri)) {
                    assertThat(authenticated.status(), is(Status.OK_200));
                    assertThat(authenticated.as(String.class), is("alice-id|alice|alice@example.org"));
                }

                assertThat(idp.tokenRequests().size(), is(2));
                assertThat(idp.tokenRequests().getFirst().formParam("grant_type").orElse(""),
                           is("authorization_code"));
                assertThat(idp.tokenRequests().get(1).formParam("grant_type").orElse(""), is("refresh_token"));
                assertThat(idp.userInfoRequests().size(), is(2));
                String initialUserInfoToken = idp.userInfoRequests().getFirst().bearerToken().orElseThrow();
                String refreshedUserInfoToken = idp.userInfoRequests().get(1).bearerToken().orElseThrow();
                assertThat(initialUserInfoToken.startsWith("opaque-access-"), is(true));
                assertThat(refreshedUserInfoToken.startsWith("opaque-access-"), is(true));
                assertThat(initialUserInfoToken.equals(refreshedUserInfoToken), is(false));
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

    private static URI callbackWithIssuer(URI callback, String issuer) {
        return callback(callback, issuer);
    }

    private static URI callbackWithoutIssuer(URI callback) {
        return callback(callback, null);
    }

    private static URI callback(URI callback, String issuer) {
        UriQuery query = UriQuery.create(callback);
        String baseUri = callback.toString().substring(0, callback.toString().indexOf('?'));
        StringBuilder result = new StringBuilder(baseUri)
                .append("?code=")
                .append(urlEncode(query.all("code", List::of).getFirst()))
                .append("&state=")
                .append(urlEncode(query.all("state", List::of).getFirst()));
        if (issuer != null) {
            result.append("&iss=").append(urlEncode(issuer));
        }
        return URI.create(result.toString());
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
