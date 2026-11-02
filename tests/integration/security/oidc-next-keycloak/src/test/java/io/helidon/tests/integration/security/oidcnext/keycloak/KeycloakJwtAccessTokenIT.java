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
import io.helidon.security.jwt.SignedJwt;
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
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

@Testcontainers(disabledWithoutDocker = true)
class KeycloakJwtAccessTokenIT {
    @Container
    static final GenericContainer<?> CONTAINER = KeycloakOidcContainer.CONTAINER;

    private static final OidcTokenValidationConfig CUSTOM_VALIDATION = OidcTokenValidationConfig.create(Config.create(
            ConfigSources.classpath("keycloak-jwt-custom.yaml")).get("protected-resource.token-validation"));

    // RFC 9068 §4 (https://www.rfc-editor.org/rfc/rfc9068.html#section-4):
    // "The resource server MUST verify that the \"typ\" header value is \"at+jwt\" or \"application/at+jwt\"".
    // Keycloak's default token has typ=JWT, whereas the deliberately configured CUSTOM profile accepts it.
    @Test
    void protectedResourceRejectsKeycloakDefaultJwtAccessTokenBecauseItIsNotRfc9068() {
        String accessToken = KeycloakOidcIntegrationSupport.passwordAccessToken();
        var jwt = SignedJwt.parseToken(accessToken).getJwt();
        assertThat(jwt.type().orElseThrow(), is("JWT"));
        assertThat(jwt.audience().orElseThrow(), hasItems(KeycloakOidcIntegrationSupport.API_AUDIENCE));
        // A positive control rules out invalid signature, issuer, or audience as the reason for a 401.
        assertCustomBearerResponse(CUSTOM_VALIDATION, accessToken,
                                   response -> assertThat(response.status(), is(Status.OK_200)));
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

    // RFC 9068 §4 (https://www.rfc-editor.org/rfc/rfc9068.html#section-4):
    // "The resource server MUST verify that the \"typ\" header value is \"at+jwt\" or \"application/at+jwt\""
    // for the RFC profile. CUSTOM intentionally relaxes this; its separate configured payload
    // constraints must still reject Keycloak's ID Token, even if the configured audience matches.
    @Test
    void yamlCustomProfileRejectsKeycloakIdTokenEvenWithMatchingAudience() {
        String idToken = KeycloakOidcIntegrationSupport.passwordTokenResponse().stringValue("id_token").orElseThrow();
        var jwt = SignedJwt.parseToken(idToken).getJwt();
        assertThat(jwt.audience().orElseThrow(), hasItems(KeycloakOidcIntegrationSupport.WEB_CLIENT_ID));
        OidcTokenValidationConfig validation = OidcTokenValidationConfig.builder().from(CUSTOM_VALIDATION)
                .audience(KeycloakOidcIntegrationSupport.WEB_CLIENT_ID)
                .jwt(OidcJwtAccessTokenConfig.builder().from(CUSTOM_VALIDATION.jwt().orElseThrow())
                             .requiredClaims(List.of()).buildPrototype())
                .buildPrototype();

        assertCustomBearerResponse(validation, idToken,
                                   response -> assertThat(response.status(), is(Status.UNAUTHORIZED_401)));
    }

    // RFC 9700 §2.3 (https://www.rfc-editor.org/rfc/rfc9700.html#section-2.3):
    // when the token was not intended for this resource server, "the resource server MUST
    // refuse to serve the respective request." First accept this *same* native token
    // under the correct audience; only the resource-audience configuration then changes.
    @Test
    void yamlCustomProfileRejectsDefaultKeycloakTokenForWrongAudience() {
        String token = KeycloakOidcIntegrationSupport.passwordAccessToken();
        OidcTokenValidationConfig validation = OidcTokenValidationConfig.builder().from(CUSTOM_VALIDATION)
                .audience("other-api").buildPrototype();

        assertCustomBearerResponse(CUSTOM_VALIDATION, token,
                                   response -> assertThat(response.status(), is(Status.OK_200)));
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
