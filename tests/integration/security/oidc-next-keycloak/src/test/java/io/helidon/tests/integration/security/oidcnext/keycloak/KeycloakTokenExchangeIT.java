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
class KeycloakTokenExchangeIT {
    @Container
    static final GenericContainer<?> CONTAINER = KeycloakOidcContainer.CONTAINER;

    @Test
    void outboundTargetExchangesCurrentBearerTokenWithKeycloak() {
        // RFC 8693 §2.1, https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1:
        // audience: "OPTIONAL. The logical name of the target service where the client intends to use
        // the requested security token." Helidon configures it here and the downstream RP checks that audience;
        // provider unit tests independently check the exact token-exchange grant parameters.
        AtomicReference<String> downstreamAuthorization = new AtomicReference<>();
        WebServer downstream = KeycloakOidcIntegrationSupport.introspectingDownstream(downstreamAuthorization, true);
        String inboundToken = KeycloakOidcIntegrationSupport.passwordAccessToken();
        URI downstreamUri = URI.create("http://localhost:" + downstream.port() + "/downstream");
        OutboundTarget outboundTarget = KeycloakOidcIntegrationSupport.tokenExchangeOutboundTarget(downstreamUri);
        OidcProviderConfig providerConfig = KeycloakOidcIntegrationSupport.tokenExchangeProviderConfig(outboundTarget);
        WebServer rpServer = proxyServer(providerConfig, downstreamUri);
        try {
            WebClient client = WebClient.builder()
                    .baseUri(KeycloakOidcIntegrationSupport.rpBaseUri(rpServer))
                    .build();
            try {
                // Control: authentication and the requested resource audience are enforced downstream.
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
