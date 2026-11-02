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

import io.helidon.http.HeaderNames;
import io.helidon.http.Status;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.security.providers.oidc.next.OidcTokenValidationMethod;
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
class KeycloakIntrospectionIT {
    @Container
    static final GenericContainer<?> CONTAINER = KeycloakOidcContainer.CONTAINER;

    @Test
    void protectedResourceValidatesAccessTokenThroughKeycloakIntrospection() {
        // RFC 7662 §2.2 (https://www.rfc-editor.org/rfc/rfc7662.html#section-2.2):
        // active is "REQUIRED. Boolean indicator of whether or not the presented token is currently active."
        // This test exercises RP acceptance of a live token.
        String accessToken = KeycloakOidcIntegrationSupport.passwordAccessToken();
        OidcProviderConfig providerConfig = KeycloakOidcIntegrationSupport
                .protectedResourceProviderConfig(OidcTokenValidationMethod.INTROSPECTION);
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
                    assertThat(response.status(), is(Status.OK_200));
                    assertThat(response.as(String.class), is(KeycloakOidcIntegrationSupport.alicePrincipalResponse()));
                }
            } finally {
                client.closeResource();
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void protectedResourceValidatesAccessTokenAudienceThroughKeycloakIntrospection() {
        // RFC 9700 §2.3 (https://www.rfc-editor.org/rfc/rfc9700.html#section-2.3):
        // resource servers must check whether a token "was meant to be used for that particular resource server".
        // Keycloak provides audience data in this fixture; RFC 7662 does not require every OP to return aud.
        String accessToken = KeycloakOidcIntegrationSupport.passwordAccessToken();
        OidcProviderConfig providerConfig = KeycloakOidcIntegrationSupport
                .protectedResourceProviderConfig(OidcTokenValidationMethod.INTROSPECTION,
                                                 KeycloakOidcIntegrationSupport.API_AUDIENCE,
                                                 true);
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
                    assertThat(response.status(), is(Status.OK_200));
                    assertThat(response.as(String.class), is(KeycloakOidcIntegrationSupport.alicePrincipalResponse()));
                }
            } finally {
                client.closeResource();
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void protectedResourceRejectsWrongAudienceThroughKeycloakIntrospection() {
        // RFC 9700 §2.3 (https://www.rfc-editor.org/rfc/rfc9700.html#section-2.3):
        // "If it was not, the resource server MUST refuse to serve the respective request."
        String accessToken = KeycloakOidcIntegrationSupport.passwordAccessToken();
        OidcProviderConfig providerConfig = KeycloakOidcIntegrationSupport
                .protectedResourceProviderConfig(OidcTokenValidationMethod.INTROSPECTION, "other-api", true);
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
    void protectedResourceRejectsUnknownAccessTokenThroughKeycloakIntrospection() {
        // RFC 7662 §2.2 (https://www.rfc-editor.org/rfc/rfc7662.html#section-2.2):
        // for a token that "does not exist on this server", the OP MUST return active=false.
        // The protected resource must not accept that inactive token as authentication.
        OidcProviderConfig providerConfig = KeycloakOidcIntegrationSupport
                .protectedResourceProviderConfig(OidcTokenValidationMethod.INTROSPECTION);
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
                        .header(HeaderNames.AUTHORIZATION, "Bearer unknown-token")
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
}
