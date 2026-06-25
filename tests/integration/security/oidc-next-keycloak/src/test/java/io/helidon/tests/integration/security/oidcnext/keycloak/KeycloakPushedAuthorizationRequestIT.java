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

package io.helidon.tests.integration.security.oidcnext.keycloak;

import java.net.URI;

import io.helidon.common.uri.UriQuery;
import io.helidon.http.HeaderNames;
import io.helidon.http.Status;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.security.providers.oidc.next.OidcPushedAuthorizationRequestMode;
import io.helidon.tests.integration.security.oidcnext.keycloak.KeycloakOidcIntegrationSupport.BrowserSession;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webserver.WebServer;

import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

@Testcontainers(disabledWithoutDocker = true)
class KeycloakPushedAuthorizationRequestIT {
    @Container
    static final GenericContainer<?> CONTAINER = KeycloakOidcContainer.CONTAINER;

    @Test
    void authorizationCodeFlowUsesKeycloakPushedAuthorizationRequestEndpointFromDiscovery() {
        OidcProviderConfig providerConfig = KeycloakOidcIntegrationSupport.authorizationCodeProviderConfig(
                authorizationCode -> authorizationCode.pushedAuthorizationRequests(OidcPushedAuthorizationRequestMode.REQUIRED));
        WebServer rpServer = KeycloakOidcIntegrationSupport.rpServer(
                providerConfig,
                routing -> KeycloakOidcIntegrationSupport.protectedRoute(routing, "/resource"));
        try (BrowserSession browser = new BrowserSession()) {
            URI resourceUri = KeycloakOidcIntegrationSupport.rpBaseUri(rpServer).resolve("/resource");
            URI authorizationUri;
            try (HttpClientResponse start = browser.get(resourceUri)) {
                assertThat(start.status(), is(Status.SEE_OTHER_303));
                authorizationUri = URI.create(start.headers().first(HeaderNames.LOCATION).orElseThrow());
            }

            UriQuery authorizationQuery = UriQuery.create(authorizationUri);
            assertThat(authorizationQuery.contains("request_uri"), is(true));
            assertThat(authorizationQuery.contains("scope"), is(false));
            assertThat(authorizationQuery.contains("state"), is(false));

            try (HttpClientResponse authorization = browser.get(authorizationUri)) {
                if (authorization.status().equals(Status.FOUND_302)) {
                    URI loginUri = authorizationUri.resolve(authorization.headers().first(HeaderNames.LOCATION).orElseThrow());
                    try (HttpClientResponse loginPage = browser.get(loginUri)) {
                        assertThat(loginPage.status(), is(Status.OK_200));
                    }
                } else {
                    assertThat(authorization.status(), is(Status.OK_200));
                }
            }
        } finally {
            rpServer.stop();
        }
    }
}
