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
import java.util.List;

import io.helidon.http.HeaderNames;
import io.helidon.http.Status;
import io.helidon.security.providers.oidc.next.OidcAuthenticationFailureResponse;
import io.helidon.security.providers.oidc.next.OidcEndpointCredential;
import io.helidon.security.providers.oidc.next.OidcEndpointPolicyConfig;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.security.providers.oidc.next.OidcTokenValidationMethod;
import io.helidon.tests.integration.security.oidcnext.OidcIntegrationSupport.BrowserSession;
import io.helidon.tests.integration.security.oidcnext.idp.TestOidcServer;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webserver.WebServer;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class OidcEndpointPolicyIT {
    private static final String SERVICE_CLIENT = "service-client";
    private static final String SERVICE_SECRET = "service-secret";

    @Test
    void mixedTenantDefaultsToUnauthorizedAndRouteCanRedirectForAuthenticationCookie() {
        try (TestOidcServer idp = TestOidcServer.builder()
                .client(OidcIntegrationSupport.CLIENT_ID, client -> client
                        .clientSecret(OidcIntegrationSupport.CLIENT_SECRET))
                .client(SERVICE_CLIENT, SERVICE_SECRET)
                .user("alice", user -> user
                        .subject("alice-id")
                        .password("secret")
                        .claim("preferred_username", "alice"))
                .defaultScopes("openid", "profile")
                .tokenDefaults(tokens -> tokens
                        .idToken(id -> id.includeUserClaims("preferred_username")))
                .browserLogin(true)
                .build()) {
            String accessToken = OidcIntegrationSupport.clientCredentialsToken(idp, SERVICE_CLIENT, SERVICE_SECRET);
            OidcProviderConfig providerConfig = mixedProviderConfig(idp);
            OidcEndpointPolicyConfig browserPolicy = OidcEndpointPolicyConfig.builder()
                    .acceptedCredentials(List.of(OidcEndpointCredential.AUTHENTICATION_COOKIE))
                    .buildPrototype();
            WebServer rpServer = OidcIntegrationSupport.rpServer(providerConfig, routing -> {
                OidcIntegrationSupport.protectedRoute(routing, "/api");
                OidcIntegrationSupport.protectedRoute(routing, "/page", browserPolicy);
            });
            try {
                URI rpBaseUri = OidcIntegrationSupport.rpBaseUri(rpServer);
                WebClient client = WebClient.builder()
                        .baseUri(rpBaseUri)
                        .build();
                try {
                    try (HttpClientResponse missingApiCredential = client.get("/api").request()) {
                        assertThat(missingApiCredential.status(), is(Status.UNAUTHORIZED_401));
                        assertThat(missingApiCredential.headers().first(HeaderNames.WWW_AUTHENTICATE).orElse(""),
                                   is("Bearer realm=\"helidon\""));
                    }

                    try (HttpClientResponse bearerApi = client.get("/api")
                            .header(HeaderNames.AUTHORIZATION, "Bearer " + accessToken)
                            .request()) {
                        assertThat(bearerApi.status(), is(Status.OK_200));
                        assertThat(bearerApi.as(String.class), is("service-client|service-client|"));
                    }
                } finally {
                    client.closeResource();
                }

                BrowserSession browser = new BrowserSession();
                URI pageUri = rpBaseUri.resolve("/page");
                URI authorizationUri;
                try (HttpClientResponse start = browser.get(pageUri)) {
                    assertThat(start.status(), is(Status.SEE_OTHER_303));
                    authorizationUri = URI.create(start.headers().first(HeaderNames.LOCATION).orElseThrow());
                    assertThat(authorizationUri.getPath(), is("/authorize"));
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
                    assertThat(URI.create(callbackResponse.headers().first(HeaderNames.LOCATION).orElseThrow()).getPath(),
                               is("/page"));
                }

                try (HttpClientResponse page = browser.get(pageUri)) {
                    assertThat(page.status(), is(Status.OK_200));
                    assertThat(page.as(String.class), is("alice-id|alice|"));
                }
            } finally {
                rpServer.stop();
            }
        }
    }

    @Test
    void authenticationCookieEndpointCanReturnUnauthorized() {
        try (TestOidcServer idp = TestOidcServer.builder()
                .client(OidcIntegrationSupport.CLIENT_ID, client -> client
                        .clientSecret(OidcIntegrationSupport.CLIENT_SECRET))
                .defaultScopes("openid", "profile")
                .build()) {
            OidcEndpointPolicyConfig apiCookiePolicy = OidcEndpointPolicyConfig.builder()
                    .acceptedCredentials(List.of(OidcEndpointCredential.AUTHENTICATION_COOKIE))
                    .authenticationFailureResponse(OidcAuthenticationFailureResponse.UNAUTHORIZED)
                    .buildPrototype();
            WebServer rpServer = OidcIntegrationSupport.rpServer(mixedProviderConfig(idp),
                                                                 routing -> OidcIntegrationSupport
                                                                         .protectedRoute(routing,
                                                                                         "/cookie-api",
                                                                                         apiCookiePolicy));
            try {
                WebClient client = WebClient.builder()
                        .baseUri(OidcIntegrationSupport.rpBaseUri(rpServer))
                        .build();
                try {
                    try (HttpClientResponse response = client.get("/cookie-api").request()) {
                        assertThat(response.status(), is(Status.UNAUTHORIZED_401));
                        assertThat(response.headers().contains(HeaderNames.LOCATION), is(false));
                        assertThat(response.headers().contains(HeaderNames.WWW_AUTHENTICATE), is(false));
                    }
                } finally {
                    client.closeResource();
                }
            } finally {
                rpServer.stop();
            }
        }
    }

    private static OidcProviderConfig mixedProviderConfig(TestOidcServer idp) {
        return OidcIntegrationSupport.authorizationCodeProviderConfig(idp,
                                                                      it -> {
                                                                      },
                                                                      tenant -> tenant
                                                                              .tokenTransport(transport -> transport
                                                                                      .secureTransportRequired(false))
                                                                              .protectedResource(resource -> resource
                                                                                      .tokenValidation(validation -> validation
                                                                                              .method(OidcTokenValidationMethod.JWT)
                                                                                              .audience(SERVICE_CLIENT))));
    }
}
