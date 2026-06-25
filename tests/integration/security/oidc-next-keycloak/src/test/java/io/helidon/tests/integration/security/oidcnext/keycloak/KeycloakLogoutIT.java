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

import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;

import io.helidon.common.parameters.Parameters;
import io.helidon.common.uri.UriQuery;
import io.helidon.http.HeaderNames;
import io.helidon.http.HttpMediaTypes;
import io.helidon.http.Status;
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
class KeycloakLogoutIT {
    @Container
    static final GenericContainer<?> CONTAINER = KeycloakOidcContainer.CONTAINER;

    @Test
    void localLogoutRedirectsToKeycloakEndSessionEndpointAndClearsLocalCookie() {
        OidcProviderConfig providerConfig = KeycloakOidcIntegrationSupport.authorizationCodeProviderConfig(
                authorizationCode -> {
                });
        WebServer rpServer = KeycloakOidcIntegrationSupport.rpServer(
                providerConfig,
                routing -> KeycloakOidcIntegrationSupport.protectedRoute(routing, "/resource"));
        try (BrowserSession browser = new BrowserSession()) {
            URI rpBaseUri = KeycloakOidcIntegrationSupport.rpBaseUri(rpServer);
            URI resourceUri = rpBaseUri.resolve("/resource");
            KeycloakOidcIntegrationSupport.authenticate(browser, resourceUri);

            URI localLogout = rpBaseUri.resolve("/oidc/logout");
            URI endSessionUri;
            try (HttpClientResponse logout = browser.post(localLogout,
                                                          Parameters.empty("logout"),
                                                          request -> request.header(HeaderNames.ORIGIN,
                                                                                    rpBaseUri.toString()))) {
                assertThat(logout.status(), is(Status.SEE_OTHER_303));
                endSessionUri = URI.create(logout.headers().first(HeaderNames.LOCATION).orElseThrow());
            }

            UriQuery endSessionQuery = UriQuery.create(endSessionUri);
            assertThat(endSessionQuery.contains("id_token_hint"), is(true));

            try (HttpClientResponse afterLogout = browser.get(resourceUri)) {
                assertThat(afterLogout.status(), is(Status.SEE_OTHER_303));
                URI authorizationUri = URI.create(afterLogout.headers().first(HeaderNames.LOCATION).orElseThrow());
                assertThat(authorizationUri.getPath().endsWith("/protocol/openid-connect/auth"), is(true));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void localLogoutCanCompleteKeycloakEndSessionAndReturnToPostLogoutRedirectUri() throws IOException {
        int rpPort = availablePort();
        URI postLogoutRedirectUri = URI.create("http://localhost:" + rpPort + "/logged-out");
        OidcProviderConfig providerConfig = KeycloakOidcIntegrationSupport.authorizationCodeProviderConfig(
                authorizationCode -> {
                },
                tenant -> tenant.logout(logout -> logout.endSession(endSession -> endSession
                        .postLogoutRedirectUri(postLogoutRedirectUri))));
        WebServer rpServer = KeycloakOidcIntegrationSupport.rpServer(
                rpPort,
                providerConfig,
                routing -> {
                    KeycloakOidcIntegrationSupport.protectedRoute(routing, "/resource");
                    routing.get("/logged-out", (request, response) -> {
                        response.headers().contentType(HttpMediaTypes.PLAINTEXT_UTF_8);
                        response.send("logged-out");
                    });
                });
        try (BrowserSession browser = new BrowserSession()) {
            URI rpBaseUri = KeycloakOidcIntegrationSupport.rpBaseUri(rpServer);
            URI resourceUri = rpBaseUri.resolve("/resource");
            KeycloakOidcIntegrationSupport.authenticate(browser, resourceUri);

            URI localLogout = rpBaseUri.resolve("/oidc/logout?state=logout-state");
            URI endSessionUri;
            try (HttpClientResponse logout = browser.post(localLogout,
                                                          Parameters.empty("logout"),
                                                          request -> request.header(HeaderNames.ORIGIN,
                                                                                    rpBaseUri.toString()))) {
                assertThat(logout.status(), is(Status.SEE_OTHER_303));
                endSessionUri = URI.create(logout.headers().first(HeaderNames.LOCATION).orElseThrow());
            }

            UriQuery endSessionQuery = UriQuery.create(endSessionUri);
            assertThat(endSessionQuery.first("post_logout_redirect_uri").orElse(""), is(postLogoutRedirectUri.toString()));
            assertThat(endSessionQuery.first("state").orElse(""), is("logout-state"));

            URI loggedOutUri;
            try (HttpClientResponse endSession = browser.get(endSessionUri)) {
                int status = endSession.status().code();
                assertThat(status == Status.FOUND_302.code() || status == Status.SEE_OTHER_303.code(), is(true));
                loggedOutUri = endSessionUri.resolve(endSession.headers().first(HeaderNames.LOCATION).orElseThrow());
            }

            assertThat(loggedOutUri.getPath(), is("/logged-out"));
            assertThat(UriQuery.create(loggedOutUri).first("state").orElse(""), is("logout-state"));
            try (HttpClientResponse loggedOut = browser.get(loggedOutUri)) {
                assertThat(loggedOut.status(), is(Status.OK_200));
                assertThat(loggedOut.as(String.class), is("logged-out"));
            }
        } finally {
            rpServer.stop();
        }
    }

    private static int availablePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
