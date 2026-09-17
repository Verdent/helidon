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

import java.util.concurrent.atomic.AtomicReference;

import io.helidon.http.HeaderName;
import io.helidon.http.HeaderNames;
import io.helidon.http.Status;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.security.providers.oidc.next.OidcTenantConfig;
import io.helidon.security.providers.oidc.next.OidcTokenValidationMethod;
import io.helidon.tests.integration.security.oidcnext.idp.TestOidcServer;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.security.SecurityFeature;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;

class OidcPrincipalIdentityIT {
    private static final String CLIENT_ID = "service-client";
    private static final String CLIENT_SECRET = "service-secret";
    private static final String TENANT_HEADER_NAME = "X-Test-Tenant";
    private static final HeaderName TENANT_HEADER = HeaderNames.create(TENANT_HEADER_NAME);

    @Test
    void jwtIdentityDoesNotAuthorizeAnotherIssuersSubject() {
        verifyOwnershipIsolation(OidcTokenValidationMethod.JWT);
    }

    @Test
    void introspectedIdentityDoesNotAuthorizeAnotherIssuersSubject() {
        verifyOwnershipIsolation(OidcTokenValidationMethod.INTROSPECTION);
    }

    @Test
    void jwtAndIntrospectionGiveTheSameIdentityForTheSameToken() {
        try (TestOidcServer idp = identityProvider()) {
            String token = OidcIntegrationSupport.clientCredentialsToken(idp, CLIENT_ID, CLIENT_SECRET);
            OidcProviderConfig config = OidcProviderConfig.builder()
                    .putTenant("jwt", tenant(idp, OidcTokenValidationMethod.JWT))
                    .putTenant("introspection", tenant(idp, OidcTokenValidationMethod.INTROSPECTION))
                    .tenantResolution(resolution -> resolution.headerName(TENANT_HEADER_NAME))
                    .buildPrototype();
            WebServer rp = OidcIntegrationSupport.rpServer(config,
                                                          routing -> OidcIntegrationSupport.protectedRoute(routing, "/identity"));
            WebClient client = WebClient.builder().baseUri(OidcIntegrationSupport.rpBaseUri(rp)).build();
            try {
                String jwtIdentity = identity(client, "jwt", token);
                String introspectedIdentity = identity(client, "introspection", token);

                assertThat(introspectedIdentity, is(jwtIdentity));
                assertThat(jwtIdentity, not(CLIENT_ID));
            } finally {
                client.closeResource();
                rp.stop();
            }
        }
    }

    private static void verifyOwnershipIsolation(OidcTokenValidationMethod method) {
        // Both configured authorities legitimately issue the same subject value; no token is forged or edited.
        try (TestOidcServer first = identityProvider(); TestOidcServer second = identityProvider()) {
            String ownerToken = OidcIntegrationSupport.clientCredentialsToken(first, CLIENT_ID, CLIENT_SECRET);
            String otherToken = OidcIntegrationSupport.clientCredentialsToken(second, CLIENT_ID, CLIENT_SECRET);
            OidcProviderConfig config = OidcProviderConfig.builder()
                    .putTenant("first", tenant(first, method))
                    .putTenant("second", tenant(second, method))
                    .tenantResolution(resolution -> resolution.headerName(TENANT_HEADER_NAME))
                    .buildPrototype();
            AtomicReference<String> recordOwner = new AtomicReference<>();
            WebServer rp = OidcIntegrationSupport.rpServer(config, routing -> {
                OidcIntegrationSupport.protectedRoute(routing, "/identity");
                routing.get("/record", SecurityFeature.authenticate(), (_, response) -> {
                    String currentId = OidcIntegrationSupport.currentSubject().principal().id();
                    if (currentId.equals(recordOwner.get())) {
                        response.send("owner-only data");
                    } else {
                        response.status(Status.FORBIDDEN_403).send();
                    }
                });
            });
            WebClient client = WebClient.builder().baseUri(OidcIntegrationSupport.rpBaseUri(rp)).build();
            try {
                String ownerId = identity(client, "first", ownerToken);
                String otherId = identity(client, "second", otherToken);
                recordOwner.set(ownerId);

                try (HttpClientResponse response = client.get("/record")
                        .header(TENANT_HEADER, "first")
                        .header(HeaderNames.AUTHORIZATION, "Bearer " + ownerToken)
                        .request()) {
                    assertThat(response.status(), is(Status.OK_200));
                    assertThat(response.as(String.class), is("owner-only data"));
                }
                try (HttpClientResponse response = client.get("/record")
                        .header(TENANT_HEADER, "second")
                        .header(HeaderNames.AUTHORIZATION, "Bearer " + otherToken)
                        .request()) {
                    assertThat(response.status(), is(Status.FORBIDDEN_403));
                }
                try (HttpClientResponse response = client.get("/record")
                        .header(TENANT_HEADER, "first")
                        .header(HeaderNames.AUTHORIZATION, "Bearer " + otherToken)
                        .request()) {
                    assertThat(response.status(), is(Status.UNAUTHORIZED_401));
                }
                assertThat(otherId, not(ownerId));
            } finally {
                client.closeResource();
                rp.stop();
            }
        }
    }

    private static TestOidcServer identityProvider() {
        return TestOidcServer.builder().client(CLIENT_ID, CLIENT_SECRET).defaultScopes("service.read").build();
    }

    private static OidcTenantConfig tenant(TestOidcServer idp, OidcTokenValidationMethod method) {
        return OidcIntegrationSupport.protectedResourceProviderConfig(idp, CLIENT_ID, CLIENT_SECRET, CLIENT_ID, method)
                .tenants()
                .get("default");
    }

    private static String identity(WebClient client, String tenant, String token) {
        try (HttpClientResponse response = client.get("/identity")
                .header(TENANT_HEADER, tenant)
                .header(HeaderNames.AUTHORIZATION, "Bearer " + token)
                .request()) {
            assertThat(response.status(), is(Status.OK_200));
            return response.as(String.class).split("\\|", -1)[0];
        }
    }
}
