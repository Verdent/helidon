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
import java.util.List;

import io.helidon.http.HeaderNames;
import io.helidon.http.Status;
import io.helidon.security.providers.oidc.next.OidcEndpointCredential;
import io.helidon.security.providers.oidc.next.OidcEndpointPolicyConfig;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
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
class KeycloakRefreshTokenIT {
    @Container
    static final GenericContainer<?> CONTAINER = KeycloakOidcContainer.CONTAINER;

    @Test
    void authorizationCodeFlowRefreshesKeycloakAccessTokenAndUpdatesLocalCookie() {
        OidcEndpointPolicyConfig browserPolicy = OidcEndpointPolicyConfig.builder()
                .acceptedCredentials(List.of(OidcEndpointCredential.AUTHENTICATION_COOKIE))
                .buildPrototype();
        OidcProviderConfig providerConfig = KeycloakOidcIntegrationSupport.authorizationCodeRefreshProviderConfig();
        WebServer rpServer = KeycloakOidcIntegrationSupport.rpServer(
                providerConfig,
                routing -> KeycloakOidcIntegrationSupport.protectedRoute(routing, "/resource", browserPolicy));
        try (BrowserSession browser = new BrowserSession()) {
            URI resourceUri = KeycloakOidcIntegrationSupport.rpBaseUri(rpServer).resolve("/resource");
            KeycloakOidcIntegrationSupport.authenticate(browser, resourceUri);

            try (HttpClientResponse authenticated = browser.get(resourceUri)) {
                assertThat(authenticated.status(), is(Status.OK_200));
                assertThat(authenticated.as(String.class),
                           is("11111111-1111-1111-1111-111111111111|alice|alice@example.org"));
                assertThat(authenticated.headers().contains(HeaderNames.SET_COOKIE), is(true));
            }
        } finally {
            rpServer.stop();
        }
    }
}
