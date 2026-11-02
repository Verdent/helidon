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
import java.util.concurrent.atomic.AtomicReference;

import io.helidon.http.HeaderNames;
import io.helidon.http.Status;
import io.helidon.security.providers.common.OutboundTarget;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.security.SecurityFeature;

import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;

@Testcontainers(disabledWithoutDocker = true)
class KeycloakClientCredentialsIT {
    @Container
    static final GenericContainer<?> CONTAINER = KeycloakOidcContainer.CONTAINER;

    @Test
    void outboundTargetObtainsClientCredentialsTokenFromKeycloak() {
        // RFC 6749 §4.4.3, https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4.3:
        // "If the access token request is valid and authorized, the authorization server issues an access token".
        // This integration test proves the outbound token is usable against the actual OP via introspection;
        // provider unit tests independently check the exact client_credentials grant parameters.
        AtomicReference<String> downstreamAuthorization = new AtomicReference<>();
        WebServer downstream = KeycloakOidcIntegrationSupport.introspectingDownstream(downstreamAuthorization, false);
        String inboundToken = KeycloakOidcIntegrationSupport.clientCredentialsAccessToken();
        URI downstreamUri = URI.create("http://localhost:" + downstream.port() + "/downstream");
        OutboundTarget outboundTarget = KeycloakOidcIntegrationSupport.clientCredentialsOutboundTarget(downstreamUri);
        OidcProviderConfig providerConfig = KeycloakOidcIntegrationSupport
                .outboundClientCredentialsProviderConfig(outboundTarget);
        WebServer rpServer = proxyServer(providerConfig, downstreamUri);
        try {
            WebClient client = WebClient.builder()
                    .baseUri(KeycloakOidcIntegrationSupport.rpBaseUri(rpServer))
                    .build();
            try {
                // Control: this downstream is not merely accepting any Bearer string.
                try (HttpClientResponse rejected = client.get().uri(downstreamUri)
                        .header(HeaderNames.AUTHORIZATION, "Bearer invalid-token").request()) {
                    assertThat(rejected.status(), is(Status.UNAUTHORIZED_401));
                }
                try (HttpClientResponse response = client.get("/proxy")
                        .header(HeaderNames.AUTHORIZATION, "Bearer " + inboundToken)
                        .request()) {
                    assertThat(response.status(), is(Status.OK_200));
                    assertThat(response.as(String.class), is("downstream"));
                }
            } finally {
                client.closeResource();
            }

            assertThat(downstreamAuthorization.get().startsWith("Bearer "), is(true));
            assertThat(downstreamAuthorization.get(), not("Bearer " + inboundToken));
        } finally {
            rpServer.stop();
            downstream.stop();
        }
    }

    private static WebServer proxyServer(OidcProviderConfig providerConfig, URI downstreamUri) {
        return KeycloakOidcIntegrationSupport.rpServer(
                providerConfig,
                routing -> routing.get("/proxy", SecurityFeature.authenticate(), (_, response) -> {
                    WebClient outbound = KeycloakOidcIntegrationSupport.outboundClient();
                    try (HttpClientResponse downstreamResponse = outbound.get()
                            .uri(downstreamUri)
                            .request()) {
                        response.status(downstreamResponse.status())
                                .send(downstreamResponse.as(String.class));
                    } finally {
                        outbound.closeResource();
                    }
                }));
    }
}
