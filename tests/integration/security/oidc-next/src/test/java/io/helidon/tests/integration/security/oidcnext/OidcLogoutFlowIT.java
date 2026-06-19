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

import io.helidon.common.parameters.Parameters;
import io.helidon.common.uri.UriQuery;
import io.helidon.http.HeaderNames;
import io.helidon.http.Status;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.tests.integration.security.oidcnext.OidcIntegrationSupport.BrowserSession;
import io.helidon.tests.integration.security.oidcnext.idp.TestOidcServer;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webserver.WebServer;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class OidcLogoutFlowIT {
    private static final URI POST_LOGOUT_REDIRECT_URI = URI.create("http://localhost/post-logout");

    @Test
    void localLogoutClearsAuthenticationCookieAndRedirectsToEndSessionEndpoint() {
        try (TestOidcServer idp = TestOidcServer.builder()
                .client(OidcIntegrationSupport.CLIENT_ID, client -> client
                        .clientSecret(OidcIntegrationSupport.CLIENT_SECRET))
                .user("alice", user -> user
                        .subject("alice-id")
                        .password("secret")
                        .claim("preferred_username", "alice"))
                .defaultScopes("openid", "profile")
                .tokenDefaults(tokens -> tokens
                        .idToken(id -> id.includeUserClaims("preferred_username")))
                .browserLogin(true)
                .build()) {
            OidcProviderConfig providerConfig = OidcIntegrationSupport.authorizationCodeProviderConfig(
                    idp,
                    authorizationCode -> {
                    },
                    tenant -> tenant
                            .endpoints(endpoints -> {
                                OidcIntegrationSupport.authorizationCodeEndpoints(idp, endpoints);
                                endpoints.endSessionEndpointUri(idp.logoutEndpointUri());
                            })
                            .logout(logout -> logout.endSession(endSession -> endSession
                                    .postLogoutRedirectUri(POST_LOGOUT_REDIRECT_URI))));
            WebServer rpServer = OidcIntegrationSupport.rpServer(providerConfig,
                                                                 routing -> OidcIntegrationSupport
                                                                         .protectedRoute(routing, "/resource"));
            try {
                BrowserSession browser = new BrowserSession();
                URI rpBaseUri = OidcIntegrationSupport.rpBaseUri(rpServer);
                URI resourceUri = rpBaseUri.resolve("/resource");
                authenticate(browser, idp, resourceUri);

                try (HttpClientResponse authenticated = browser.get(resourceUri)) {
                    assertThat(authenticated.status(), is(Status.OK_200));
                    assertThat(authenticated.as(String.class), is("alice-id|alice|"));
                }

                URI localLogout = rpBaseUri.resolve("/oidc/logout?state=logout-state");
                URI endSessionUri;
                try (HttpClientResponse logout = browser.post(localLogout,
                                                              Parameters.empty("logout"),
                                                              request -> request.header(HeaderNames.ORIGIN,
                                                                                        rpBaseUri.toString()))) {
                    assertThat(logout.status(), is(Status.SEE_OTHER_303));
                    endSessionUri = URI.create(logout.headers().first(HeaderNames.LOCATION).orElseThrow());
                    assertThat(endSessionUri.getPath(), is("/logout"));
                }

                UriQuery endSessionQuery = UriQuery.create(endSessionUri);
                assertThat(endSessionQuery.contains("id_token_hint"), is(true));
                assertThat(endSessionQuery.get("post_logout_redirect_uri"), is(POST_LOGOUT_REDIRECT_URI.toString()));
                assertThat(endSessionQuery.get("state"), is("logout-state"));

                try (HttpClientResponse opLogout = browser.get(endSessionUri)) {
                    assertThat(opLogout.status(), is(Status.SEE_OTHER_303));
                    assertThat(opLogout.headers().first(HeaderNames.LOCATION).orElseThrow(),
                               is(POST_LOGOUT_REDIRECT_URI.toString()));
                }
                assertThat(idp.logoutRequests().size(), is(1));

                try (HttpClientResponse afterLogout = browser.get(resourceUri)) {
                    assertThat(afterLogout.status(), is(Status.SEE_OTHER_303));
                    URI authorizationUri = URI.create(afterLogout.headers().first(HeaderNames.LOCATION).orElseThrow());
                    assertThat(authorizationUri.getPath(), is("/authorize"));
                }
            } finally {
                rpServer.stop();
            }
        }
    }

    private static void authenticate(BrowserSession browser, TestOidcServer idp, URI resourceUri) {
        URI authorizationUri;
        try (HttpClientResponse start = browser.get(resourceUri)) {
            assertThat(start.status(), is(Status.SEE_OTHER_303));
            authorizationUri = URI.create(start.headers().first(HeaderNames.LOCATION).orElseThrow());
        }

        try (HttpClientResponse loginForm = browser.get(authorizationUri)) {
            assertThat(loginForm.status(), is(Status.OK_200));
        }

        URI callback;
        try (HttpClientResponse login = browser.post(idp.issuer().resolve("/authorize/login"),
                                                     OidcIntegrationSupport.loginForm(authorizationUri,
                                                                                      "alice",
                                                                                      "secret"))) {
            assertThat(login.status(), is(Status.SEE_OTHER_303));
            callback = URI.create(login.headers().first(HeaderNames.LOCATION).orElseThrow());
        }

        try (HttpClientResponse callbackResponse = browser.get(callback)) {
            assertThat(callbackResponse.status(), is(Status.SEE_OTHER_303));
        }
    }
}
