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
                    assertThat(response.as(String.class), is("alice|alice|alice@example.org"));
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
                    assertThat(response.as(String.class), is("alice|alice|alice@example.org"));
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
