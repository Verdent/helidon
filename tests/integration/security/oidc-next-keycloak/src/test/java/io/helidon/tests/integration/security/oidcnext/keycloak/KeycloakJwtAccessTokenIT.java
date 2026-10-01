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
import java.util.function.Consumer;

import io.helidon.config.Config;
import io.helidon.config.ConfigSources;
import io.helidon.http.HeaderNames;
import io.helidon.http.Status;
import io.helidon.security.providers.oidc.next.OidcJwtAccessTokenConfig;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.security.providers.oidc.next.OidcTokenValidationConfig;
import io.helidon.security.providers.oidc.next.OidcTokenValidationMethod;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webserver.WebServer;

import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

@Testcontainers(disabledWithoutDocker = true)
class KeycloakJwtAccessTokenIT {
    @Container
    static final GenericContainer<?> CONTAINER = KeycloakOidcContainer.CONTAINER;

    private static final OidcTokenValidationConfig CUSTOM_VALIDATION = OidcTokenValidationConfig.create(Config.create(
            ConfigSources.classpath("keycloak-jwt-custom.yaml")).get("protected-resource.token-validation"));

    @Test
    void protectedResourceRejectsKeycloakDefaultJwtAccessTokenBecauseItIsNotRfc9068() {
        String accessToken = KeycloakOidcIntegrationSupport.passwordAccessToken();
        OidcProviderConfig providerConfig = KeycloakOidcIntegrationSupport
                .protectedResourceProviderConfig(OidcTokenValidationMethod.JWT);
        WebServer rpServer = KeycloakOidcIntegrationSupport.rpServer(
                providerConfig,
                routing -> KeycloakOidcIntegrationSupport.protectedRoute(routing, "/api"));
        try {
            URI rpBaseUri = KeycloakOidcIntegrationSupport.rpBaseUri(rpServer);
            WebClient client = WebClient.builder()
                    .baseUri(rpBaseUri)
                    .build();
            try {
                try (HttpClientResponse response = client.get("/api")
                        .header(HeaderNames.AUTHORIZATION, "Bearer " + accessToken)
                        .request()) {
                    assertThat(response.status(), is(Status.UNAUTHORIZED_401));
                }
            } finally {
                client.closeResource();
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void protectedResourceRejectsInvalidJwtAccessToken() {
        OidcProviderConfig providerConfig = KeycloakOidcIntegrationSupport
                .protectedResourceProviderConfig(OidcTokenValidationMethod.JWT);
        WebServer rpServer = KeycloakOidcIntegrationSupport.rpServer(
                providerConfig,
                routing -> KeycloakOidcIntegrationSupport.protectedRoute(routing, "/api"));
        try {
            URI rpBaseUri = KeycloakOidcIntegrationSupport.rpBaseUri(rpServer);
            WebClient client = WebClient.builder()
                    .baseUri(rpBaseUri)
                    .build();
            try {
                try (HttpClientResponse response = client.get("/api")
                        .header(HeaderNames.AUTHORIZATION, "Bearer invalid-token")
                        .request()) {
                    assertThat(response.status(), is(Status.UNAUTHORIZED_401));
                }
            } finally {
                client.closeResource();
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void yamlCustomProfileAuthenticatesDefaultKeycloakUserAccessToken() {
        String token = KeycloakOidcIntegrationSupport.passwordAccessToken();

        assertCustomBearerResponse(CUSTOM_VALIDATION, token, response -> {
            assertThat(response.status(), is(Status.OK_200));
            assertThat(response.as(String.class), is(KeycloakOidcIntegrationSupport.alicePrincipalResponse()));
        });
    }

    @Test
    void yamlCustomProfileAuthenticatesDefaultKeycloakClientCredentialsToken() {
        String token = KeycloakOidcIntegrationSupport.clientCredentialsAccessToken();

        assertCustomBearerResponse(CUSTOM_VALIDATION, token, response -> {
            assertThat(response.status(), is(Status.OK_200));
            assertThat(response.as(String.class), containsString("|service-account-helidon-service|"));
        });
    }

    @Test
    void yamlCustomProfileRejectsKeycloakIdTokenEvenWithMatchingAudience() {
        String idToken = KeycloakOidcIntegrationSupport.passwordTokenResponse().stringValue("id_token").orElseThrow();
        OidcTokenValidationConfig validation = OidcTokenValidationConfig.builder().from(CUSTOM_VALIDATION)
                .audience(KeycloakOidcIntegrationSupport.WEB_CLIENT_ID)
                .jwt(OidcJwtAccessTokenConfig.builder().from(CUSTOM_VALIDATION.jwt())
                             .requiredClaims(List.of()).buildPrototype())
                .buildPrototype();

        assertCustomBearerResponse(validation, idToken,
                                   response -> assertThat(response.status(), is(Status.UNAUTHORIZED_401)));
    }

    @Test
    void yamlCustomProfileRejectsDefaultKeycloakTokenForWrongAudience() {
        String token = KeycloakOidcIntegrationSupport.passwordAccessToken();
        OidcTokenValidationConfig validation = OidcTokenValidationConfig.builder().from(CUSTOM_VALIDATION)
                .audience("other-api").buildPrototype();

        assertCustomBearerResponse(validation, token,
                                   response -> assertThat(response.status(), is(Status.UNAUTHORIZED_401)));
    }

    private static void assertCustomBearerResponse(OidcTokenValidationConfig validation,
                                                   String token,
                                                   Consumer<HttpClientResponse> assertions) {
        OidcProviderConfig providerConfig = OidcProviderConfig.builder()
                .issuer(KeycloakOidcContainer.issuer().toString())
                .endpoints(endpoints -> endpoints.wellKnownUri(KeycloakOidcContainer.metadataUri()).tlsRequired(false))
                .tokenTransport(transport -> transport.secureTransportRequired(false))
                .protectedResource(resource -> resource.tokenValidation(validation))
                .buildPrototype();
        WebServer server = KeycloakOidcIntegrationSupport.rpServer(
                providerConfig, routing -> KeycloakOidcIntegrationSupport.protectedRoute(routing, "/api"));
        WebClient client = WebClient.builder().baseUri(KeycloakOidcIntegrationSupport.rpBaseUri(server)).build();
        try {
            try (HttpClientResponse response = client.get("/api")
                    .header(HeaderNames.AUTHORIZATION, "Bearer " + token).request()) {
                assertions.accept(response);
            }
        } finally {
            client.closeResource();
            server.stop();
        }
    }
}
