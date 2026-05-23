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

package io.helidon.security.providers.oidc.next;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import io.helidon.http.HeaderValues;
import io.helidon.json.JsonObject;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.providers.common.OutboundTarget;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.testing.junit5.ServerTest;
import io.helidon.webserver.testing.junit5.SetUpRoute;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

@ServerTest
class OidcProviderMetadataDiscoveryTest {
    private static final URI REDIRECTION_ENDPOINT_URI = URI.create("https://rp.example/oidc/callback");
    private static final AtomicReference<String> PROVIDER_METADATA = new AtomicReference<>();

    private URI issuer;
    private URI authorizationEndpointUri;
    private URI tokenEndpointUri;
    private URI jwksUri;
    private URI userInfoEndpointUri;

    @SetUpRoute
    static void routing(HttpRouting.Builder routing) {
        routing.get("/.well-known/openid-configuration", (request, response) -> response
                .header(HeaderValues.CONTENT_TYPE_JSON)
                .send(PROVIDER_METADATA.get()));
    }

    @BeforeEach
    void setUp(URI serverUri) {
        issuer = URI.create(serverUri.toString().substring(0, serverUri.toString().length() - 1));
        authorizationEndpointUri = serverUri.resolve("authorize");
        tokenEndpointUri = serverUri.resolve("token");
        jwksUri = serverUri.resolve("jwks");
        userInfoEndpointUri = serverUri.resolve("userinfo");
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", authorizationEndpointUri.toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .set("jwks_uri", jwksUri.toString())
                .set("userinfo_endpoint", userInfoEndpointUri.toString())
                .build()
                .toString());
    }

    @Test
    void authorizationCodeTenantLoadsDiscoveredEndpoints() {
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer)
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.ready(), is(true));
        assertThat(context.metadata().issuer(), is(Optional.of(issuer)));
        assertThat(context.metadata().discoveryUri(), is(Optional.of(issuer.resolve("/.well-known/openid-configuration"))));
        assertThat(context.metadata().authorizationEndpointUri(), is(Optional.of(authorizationEndpointUri)));
        assertThat(context.metadata().tokenEndpointUri(), is(Optional.of(tokenEndpointUri)));
        assertThat(context.jwkSetManager().jwkSetUri(), is(Optional.of(jwksUri)));
        assertThat(context.metadata().userInfoEndpointUri(), is(Optional.of(userInfoEndpointUri)));
    }

    @Test
    void jwtProtectedResourceTenantLoadsJwkSetUriFromDiscovery() {
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer)
                .endpoints(it -> it.tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience("api://default")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.ready(), is(true));
        assertThat(context.metadata().issuer(), is(Optional.of(issuer)));
        assertThat(context.jwkSetManager().jwkSetUri(), is(Optional.of(jwksUri)));
    }

    @Test
    void targetClientCredentialsGrantTenantLoadsTokenEndpointFromDiscovery() {
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer)
                .clientId("client-id")
                .clientSecret("client-secret")
                .endpoints(it -> it.tlsRequired(false))
                .buildPrototype();
        OidcProviderConfig providerConfig = OidcProviderConfig.builder()
                .putTenant("tenant", tenantConfig)
                .outboundTargets(List.of(clientCredentialsTarget()))
                .buildPrototype();

        OidcTenantContext context = OidcTenantRuntimeRegistry.create(providerConfig)
                .tenantContext(OidcProviderTest.request(null, SecurityEnvironment.create()))
                .orElseThrow();

        assertThat(context.ready(), is(true));
        assertThat(context.metadata().tokenEndpointUri(), is(Optional.of(tokenEndpointUri)));
    }

    private static OutboundTarget clientCredentialsTarget() {
        return OutboundTarget.builder("api")
                .customObject(OidcOutboundTargetConfig.class,
                              OidcOutboundTargetConfig.builder()
                                      .clientCredentialsGrantEnabled(true)
                                      .buildPrototype())
                .build();
    }

    @Test
    void jwtProtectedResourceTenantFailsWhenDiscoveredJwkSetUriIsMissing() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer)
                .endpoints(it -> it.tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience("api://default")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    private static OidcTenantContext tenantContext(OidcTenantConfig tenantConfig) {
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(OidcProviderConfig.builder()
                .putTenant("tenant", tenantConfig)
                .buildPrototype());
        return registry.tenantContext(OidcProviderTest.request(null, SecurityEnvironment.create()))
                .orElseThrow();
    }
}
