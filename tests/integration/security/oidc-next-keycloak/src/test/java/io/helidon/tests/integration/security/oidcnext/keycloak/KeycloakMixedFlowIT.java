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
import io.helidon.webclient.api.WebClient;
import io.helidon.webserver.WebServer;

import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

@Testcontainers(disabledWithoutDocker = true)
class KeycloakMixedFlowIT {
    @Container
    static final GenericContainer<?> CONTAINER = KeycloakOidcContainer.CONTAINER;

    @Test
    void providerCanServeBearerApiAndBrowserPageWithKeycloak() {
        String accessToken = KeycloakOidcIntegrationSupport.passwordAccessToken();
        OidcEndpointPolicyConfig browserPolicy = OidcEndpointPolicyConfig.builder()
                .acceptedCredentials(List.of(OidcEndpointCredential.AUTHENTICATION_COOKIE))
                .buildPrototype();
        OidcProviderConfig providerConfig = KeycloakOidcIntegrationSupport.mixedProviderConfig();
        WebServer rpServer = KeycloakOidcIntegrationSupport.rpServer(providerConfig, routing -> {
            KeycloakOidcIntegrationSupport.protectedRoute(routing, "/api");
            KeycloakOidcIntegrationSupport.protectedRoute(routing, "/page", browserPolicy);
        });
        try (BrowserSession browser = new BrowserSession()) {
            URI rpBaseUri = KeycloakOidcIntegrationSupport.rpBaseUri(rpServer);
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
                    assertThat(bearerApi.as(String.class), is("alice|alice|alice@example.org"));
                }
            } finally {
                client.closeResource();
            }

            URI pageUri = rpBaseUri.resolve("/page");
            KeycloakOidcIntegrationSupport.authenticate(browser, pageUri);

            try (HttpClientResponse page = browser.get(pageUri)) {
                assertThat(page.status(), is(Status.OK_200));
                assertThat(page.as(String.class),
                           is("11111111-1111-1111-1111-111111111111|alice|alice@example.org"));
            }
        } finally {
            rpServer.stop();
        }
    }
}
