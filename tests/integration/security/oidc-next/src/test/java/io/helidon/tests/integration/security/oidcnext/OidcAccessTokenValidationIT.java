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

package io.helidon.tests.integration.security.oidcnext;

import java.net.URI;

import io.helidon.http.HeaderNames;
import io.helidon.http.Status;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.tests.integration.security.oidcnext.idp.TestOidcServer;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webserver.WebServer;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class OidcAccessTokenValidationIT {
    private static final String SERVICE_CLIENT = "service-client";
    private static final String SERVICE_SECRET = "service-secret";

    @Test
    void protectedResourceValidatesJwtAccessTokenThroughJwks() {
        int rpPort = OidcIntegrationSupport.reservePort();
        URI rpBaseUri = URI.create("http://localhost:" + rpPort);

        try (TestOidcServer idp = TestOidcServer.builder()
                .client(SERVICE_CLIENT, SERVICE_SECRET)
                .defaultScopes("service.read")
                .build()) {
            String accessToken = OidcIntegrationSupport.clientCredentialsToken(idp, SERVICE_CLIENT, SERVICE_SECRET);
            OidcProviderConfig providerConfig = OidcIntegrationSupport.protectedResourceProviderConfig(idp,
                                                                                                      SERVICE_CLIENT,
                                                                                                      SERVICE_CLIENT);
            WebServer rpServer = OidcIntegrationSupport.rpServer(providerConfig,
                                                                 rpPort,
                                                                 routing -> OidcIntegrationSupport
                                                                         .protectedRoute(routing, "/api"));
            try {
                WebClient client = WebClient.builder()
                        .baseUri(rpBaseUri)
                        .build();

                try (HttpClientResponse response = client.get("/api")
                        .header(HeaderNames.AUTHORIZATION, "Bearer " + accessToken)
                        .request()) {
                    assertThat(response.status(), is(Status.OK_200));
                    assertThat(response.as(String.class), is("service-client|service-client|"));
                }

                assertThat(idp.tokenRequests().getFirst().formParam("grant_type").orElse(""),
                           is("client_credentials"));
            } finally {
                rpServer.stop();
            }
        }
    }
}
