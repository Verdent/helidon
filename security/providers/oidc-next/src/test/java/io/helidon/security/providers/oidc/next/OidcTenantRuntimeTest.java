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

import io.helidon.security.EndpointConfig;
import io.helidon.security.ProviderRequest;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.MatcherAssert.assertThat;

class OidcTenantRuntimeTest {
    private static final URI ISSUER = URI.create("https://issuer.example");
    private static final URI JWKS_URI = URI.create("https://issuer.example/jwks");
    private static final URI TOKEN_ENDPOINT_URI = URI.create("https://issuer.example/token");
    private static final String AUDIENCE = "api://default";

    @Test
    void defaultTenantResolutionReturnsCachedRuntimeContext() {
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(OidcProviderConfig.builder()
                .defaultTenant("api")
                .putTenant("api", protectedResourceTenant())
                .putTenant("other", OidcTenantConfig.create())
                .buildPrototype());

        OidcTenantContext first = registry.tenantContext(request(SecurityEnvironment.create())).orElseThrow();
        OidcTenantContext second = registry.tenantContext(request(SecurityEnvironment.create())).orElseThrow();

        assertThat(first.tenantId(), is("api"));
        assertThat(first.state(), is(OidcTenantState.READY));
        assertThat(first.endpointPolicy().orElseThrow().bearerTokenAuthenticationEnabled(), is(true));
        assertThat(second, sameInstance(first));
        assertThat(registry.cachedTenantCount(), is(1));
    }

    @Test
    void headerTenantResolutionSelectsConfiguredTenant() {
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(OidcProviderConfig.builder()
                .tenantResolution(it -> it.headerName("X-Tenant"))
                .putTenant("api", protectedResourceTenant())
                .putTenant("other", OidcTenantConfig.create())
                .buildPrototype());

        OidcTenantContext context = registry.tenantContext(request(SecurityEnvironment.builder()
                                                                          .header("X-Tenant", "api")
                                                                          .build()))
                .orElseThrow();

        assertThat(context.tenantId(), is("api"));
    }

    @Test
    void pathTenantResolutionSelectsConfiguredTenant() {
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(OidcProviderConfig.builder()
                .tenantResolution(it -> it.pathSegment(1))
                .putTenant("api", protectedResourceTenant())
                .putTenant("other", OidcTenantConfig.create())
                .buildPrototype());

        OidcTenantContext context = registry.tenantContext(request(SecurityEnvironment.builder()
                                                                          .path("/tenants/api/resource")
                                                                          .build()))
                .orElseThrow();

        assertThat(context.tenantId(), is("api"));
    }

    @Test
    void pathTemplateTenantResolutionSelectsConfiguredTenant() {
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(OidcProviderConfig.builder()
                .tenantResolution(it -> it.pathTemplate("/tenants/{tenant}/resource"))
                .putTenant("api", protectedResourceTenant())
                .putTenant("other", OidcTenantConfig.create())
                .buildPrototype());

        OidcTenantContext context = registry.tenantContext(request(SecurityEnvironment.builder()
                                                                          .path("/tenants/api/resource")
                                                                          .build()))
                .orElseThrow();

        assertThat(context.tenantId(), is("api"));
        assertThat(registry.tenantContext(request(SecurityEnvironment.builder()
                                                          .path("/tenants/api/nested/resource")
                                                          .build()))
                           .isEmpty(),
                   is(true));
    }

    @Test
    void hostTemplateTenantResolutionSelectsConfiguredTenant() {
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(OidcProviderConfig.builder()
                .tenantResolution(it -> it.hostTemplate("{tenant}.example.com"))
                .putTenant("api", protectedResourceTenant())
                .putTenant("other", OidcTenantConfig.create())
                .buildPrototype());

        OidcTenantContext context = registry.tenantContext(request(SecurityEnvironment.builder()
                                                                          .targetUri(URI.create("https://api.example.com"))
                                                                          .build()))
                .orElseThrow();

        assertThat(context.tenantId(), is("api"));
    }

    @Test
    void tenantResolutionUsesConfiguredStrategyOrder() {
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(OidcProviderConfig.builder()
                .tenantResolution(it -> it.headerName("X-Tenant")
                        .pathSegment(1)
                        .pathTemplate("/{tenant}")
                        .hostTemplate("{tenant}.example.com"))
                .putTenant("header", OidcTenantConfig.create())
                .putTenant("path", OidcTenantConfig.create())
                .putTenant("template", OidcTenantConfig.create())
                .putTenant("host", OidcTenantConfig.create())
                .buildPrototype());

        OidcTenantContext headerContext = registry.tenantContext(request(SecurityEnvironment.builder()
                                                                                 .header("X-Tenant", "header")
                                                                                 .path("/tenants/path/resource")
                                                                                 .targetUri(URI.create("https://host.example.com"))
                                                                                 .build()))
                .orElseThrow();
        OidcTenantContext pathContext = registry.tenantContext(request(SecurityEnvironment.builder()
                                                                               .path("/tenants/path/resource")
                                                                               .targetUri(URI.create("https://host.example.com"))
                                                                               .build()))
                .orElseThrow();
        OidcTenantContext pathTemplateContext = registry.tenantContext(request(SecurityEnvironment.builder()
                                                                                       .path("/template")
                                                                                       .targetUri(URI.create("https://host.example.com"))
                                                                                       .build()))
                .orElseThrow();
        OidcTenantContext hostContext = registry.tenantContext(request(SecurityEnvironment.builder()
                                                                               .targetUri(URI.create("https://host.example.com"))
                                                                               .build()))
                .orElseThrow();

        assertThat(headerContext.tenantId(), is("header"));
        assertThat(pathContext.tenantId(), is("path"));
        assertThat(pathTemplateContext.tenantId(), is("template"));
        assertThat(hostContext.tenantId(), is("host"));
    }

    @Test
    void requestSpecificUnknownTenantDoesNotFallBackToDefaultTenant() {
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(OidcProviderConfig.builder()
                .defaultTenant("default")
                .tenantResolution(it -> it.headerName("X-Tenant"))
                .putTenant("default", protectedResourceTenant())
                .putTenant("api", protectedResourceTenant())
                .buildPrototype());

        assertThat(registry.tenantContext(request(SecurityEnvironment.builder()
                                                         .header("X-Tenant", "missing")
                                                         .build()))
                           .isEmpty(),
                   is(true));

        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                .defaultTenant("default")
                .tenantResolution(it -> it.headerName("X-Tenant"))
                .putTenant("default", protectedResourceTenant())
                .putTenant("api", protectedResourceTenant())
                .buildPrototype());
        var response = provider.authenticate(request(SecurityEnvironment.builder()
                                                            .header("X-Tenant", "missing")
                                                            .header("Authorization", "Bearer access-token")
                                                            .build()));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void customPoliciesRequireResolvedTenantContext() {
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                .defaultTenant("default")
                .tenantResolution(it -> it.headerName("X-Tenant"))
                .putTenant("default", protectedResourceTenant())
                .putTenant("api", protectedResourceTenant())
                .buildPrototype());
        ProviderRequest request = request(OidcEndpointPolicy.protectedResource(),
                                          SecurityEnvironment.builder()
                                                  .header("X-Tenant", "missing")
                                                  .header("Authorization", "Bearer access-token")
                                                  .build());
        EndpointConfig outboundConfig = EndpointConfig.builder()
                .customObject(OidcOutboundPolicy.class, OidcOutboundPolicy.clientCredentialsGrant())
                .build();

        assertThat(provider.authenticate(request).status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
        assertThat(provider.isOutboundSupported(request, SecurityEnvironment.create(), outboundConfig), is(false));
        assertThat(provider.outboundSecurity(request, SecurityEnvironment.create(), outboundConfig).status(),
                   is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void resolvedTenantDrivesInboundClassification() {
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                .tenantResolution(it -> it.headerName("X-Tenant"))
                .putTenant("api", protectedResourceTenant())
                .putTenant("other", OidcTenantConfig.create())
                .buildPrototype());

        var resolvedTenantResponse = provider.authenticate(request(SecurityEnvironment.builder()
                                                                          .header("X-Tenant", "api")
                                                                          .build()));
        var unresolvedTenantResponse = provider.authenticate(request(SecurityEnvironment.create()));

        assertThat(resolvedTenantResponse.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(resolvedTenantResponse.statusCode().orElse(-1), is(401));
        assertThat(unresolvedTenantResponse.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void resolvedTenantDrivesOutboundClassification() {
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                .tenantResolution(it -> it.headerName("X-Tenant"))
                .putTenant("client", clientCredentialsTenant())
                .putTenant("other", OidcTenantConfig.create())
                .buildPrototype());

        var providerRequest = request(SecurityEnvironment.builder()
                                              .header("X-Tenant", "client")
                                              .build());
        assertThat(provider.isOutboundSupported(providerRequest, outboundEnvironment(), EndpointConfig.create()),
                   is(true));
    }

    private static OidcTenantConfig protectedResourceTenant() {
        return OidcTenantConfig.builder()
                .issuer(ISSUER)
                .endpoints(it -> it.jwksUri(JWKS_URI))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience(AUDIENCE)))
                .buildPrototype();
    }

    private static OidcTenantConfig clientCredentialsTenant() {
        return OidcTenantConfig.builder()
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .endpoints(it -> it.tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .outbound(it -> it.clientCredentialsGrantEnabled(true))
                .buildPrototype();
    }

    private static ProviderRequest request(SecurityEnvironment environment) {
        return OidcProviderTest.request(null, environment);
    }

    private static ProviderRequest request(OidcEndpointPolicy endpointPolicy, SecurityEnvironment environment) {
        return OidcProviderTest.request(endpointPolicy, environment);
    }

    private static SecurityEnvironment outboundEnvironment() {
        return SecurityEnvironment.builder()
                .targetUri(URI.create("https://api.example.com/resource"))
                .transport("https")
                .path("/resource")
                .method("GET")
                .build();
    }
}
