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
import io.helidon.http.HeaderValues;
import io.helidon.http.Status;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.tests.integration.security.oidcnext.OidcIntegrationSupport.BrowserSession;
import io.helidon.tests.integration.security.oidcnext.idp.TestOidcServer;
import io.helidon.tests.integration.security.oidcnext.idp.TestOidcTokenResponse;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webserver.WebServer;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class OidcEndpointOverrideIT {
    @Test
    void tokenEndpointOverrideCanBreakResponseExactly() {
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
                        .status(Status.OK_200)
                        .header(HeaderValues.CONTENT_TYPE_TEXT_PLAIN)
                        .send("{\"access_token\":\"literal\",\"token_type\":\"Bearer\"}")))
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
                }

                assertThat(idp.tokenRequests().size(), is(1));
            } finally {
                rpServer.stop();
            }
        }
    }

    @Test
    void tokenEndpointOverrideCanReuseDefaultTokenIssuer() {
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
                    ctx.send(tokenResponse);
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
                    assertThat(response.status(), is(Status.SEE_OTHER_303));
                }

                try (HttpClientResponse authenticated = browser.get(rpBaseUri.resolve("/resource"))) {
                    assertThat(authenticated.status(), is(Status.OK_200));
                    assertThat(authenticated.as(String.class), is("alice-id|alice-id|"));
                }

                assertThat(idp.tokenRequests().size(), is(1));
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
}
