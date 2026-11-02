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

import io.helidon.http.Status;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.tests.integration.security.oidcnext.keycloak.KeycloakOidcIntegrationSupport.BrowserSession;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.security.SecurityFeature;

import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

@Testcontainers(disabledWithoutDocker = true)
class KeycloakUserInfoIT {
    @Container
    static final GenericContainer<?> CONTAINER = KeycloakOidcContainer.CONTAINER;

    /*
     * Spec: OpenID Connect Core 1.0, 5.3.2, Successful UserInfo Response.
     * https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
     * Quote: "The Claims defined in Section 5.1 (Standard Claims) can be returned, as can additional Claims not
     * specified there."
     * The fixture's userinfo_source claim is absent from the ID Token and access token.
     */
    @Test
    void authorizationCodeFlowStoresMappedUserInfoClaimsFromKeycloak() {
        OidcProviderConfig providerConfig = KeycloakOidcIntegrationSupport.authorizationCodeProviderConfig();
        WebServer rpServer = KeycloakOidcIntegrationSupport.rpServer(
                providerConfig,
                routing -> {
                    KeycloakOidcIntegrationSupport.protectedRoute(routing, "/resource");
                    routing.get("/userinfo-only", SecurityFeature.authenticate(), (_, response) ->
                            response.send(String.valueOf(KeycloakOidcIntegrationSupport.currentSubject()
                                                                 .principal().abacAttributeRaw("userinfo_source"))));
                });
        try (BrowserSession browser = new BrowserSession()) {
            URI resourceUri = KeycloakOidcIntegrationSupport.rpBaseUri(rpServer).resolve("/resource");
            KeycloakOidcIntegrationSupport.authenticate(browser, resourceUri);

            try (HttpClientResponse authenticated = browser.get(resourceUri)) {
                assertThat(authenticated.status(), is(Status.OK_200));
                assertThat(authenticated.as(String.class).endsWith("|alice|alice@example.org"), is(true));
            }
            try (HttpClientResponse userInfoClaim = browser.get(resourceUri.resolve("/userinfo-only"))) {
                assertThat(userInfoClaim.status(), is(Status.OK_200));
                assertThat(userInfoClaim.as(String.class), is("alice@example.org"));
            }
        } finally {
            rpServer.stop();
        }
    }
}
