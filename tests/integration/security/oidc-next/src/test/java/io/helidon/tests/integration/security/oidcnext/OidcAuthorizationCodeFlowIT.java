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
        int rpPort = OidcIntegrationSupport.reservePort();
        URI rpBaseUri = URI.create("http://localhost:" + rpPort);
        URI callbackUri = rpBaseUri.resolve("/oidc/callback");

        try (TestOidcServer idp = TestOidcServer.builder()
                .client(OidcIntegrationSupport.CLIENT_ID, client -> client
                        .clientSecret(OidcIntegrationSupport.CLIENT_SECRET)
                        .redirectUri(callbackUri))
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
                                                                                                      callbackUri,
                                                                                                      it -> {
                                                                                                      });
            WebServer rpServer = OidcIntegrationSupport.rpServer(providerConfig,
                                                                 rpPort,
                                                                 routing -> OidcIntegrationSupport
                                                                         .protectedRoute(routing, "/resource"));
            try {
                BrowserSession browser = new BrowserSession();

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
}
