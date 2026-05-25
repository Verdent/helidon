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
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import io.helidon.config.Config;
import io.helidon.config.ConfigSources;
import io.helidon.http.HeaderNames;
import io.helidon.json.JsonObject;
import io.helidon.security.EndpointConfig;
import io.helidon.security.Principal;
import io.helidon.security.ProviderRequest;
import io.helidon.security.SecurityContext;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;
import io.helidon.security.Subject;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.providers.common.OutboundTarget;
import io.helidon.security.providers.common.TokenCredential;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class OidcTokenPropagationTest {
    private static final String ACCESS_TOKEN = "access-token";
    private static final String EXISTING_HEADER_NAME = "X-Existing";
    private static final String EXISTING_HEADER_VALUE = "existing-value";

    @Test
    void tokenPropagationOnlyAppliesToMatchingOutboundTarget() {
        OidcProvider provider = provider(tenantWithTokenPropagation(), ordersTarget());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(request, outboundEnv, EndpointConfig.create()), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer " + ACCESS_TOKEN)));
        assertThat(response.requestHeaders().get(EXISTING_HEADER_NAME), is(List.of(EXISTING_HEADER_VALUE)));
    }

    @Test
    void tokenPropagationReplacesExistingAuthorizationHeaderCaseInsensitively() {
        OidcProvider provider = provider(tenantWithTokenPropagation(), ordersTarget());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = SecurityEnvironment.builder()
                .targetUri(URI.create("https://api.example.com/orders/42"))
                .transport("https")
                .path("/orders/42")
                .method("GET")
                .header("authorization", "Bearer stale-token")
                .build();

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer " + ACCESS_TOKEN)));
        assertThat(response.requestHeaders().containsKey("authorization"), is(false));
    }

    @Test
    void tokenPropagationCanUseRawTokenCredentialWithoutParsedClaims() {
        OidcProvider provider = provider(tenantWithTokenPropagation(), ordersTarget());
        ProviderRequest request = providerRequest(subjectWithRawToken());
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer " + ACCESS_TOKEN)));
    }

    @Test
    void tokenPropagationMatchesHttpsUriWhenEnvironmentTransportIsStale() {
        OidcProvider provider = provider(tenantWithTokenPropagation(), ordersTarget());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = SecurityEnvironment.builder()
                .targetUri(URI.create("https://api.example.com/orders/42"))
                .transport("http")
                .path("/orders/42")
                .method("GET")
                .build();

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(request, outboundEnv, EndpointConfig.create()), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer " + ACCESS_TOKEN)));
    }

    @Test
    void tokenPropagationMatchesUppercaseHttpsUriScheme() {
        OidcProvider provider = provider(tenantWithTokenPropagation(), ordersTarget());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = outboundEnvironment("HTTPS://api.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(request, outboundEnv, EndpointConfig.create()), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer " + ACCESS_TOKEN)));
    }

    @Test
    void tokenPropagationDoesNotApplyToArbitraryHost() {
        OidcProvider provider = provider(tenantWithTokenPropagation(), ordersTarget());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = outboundEnvironment("https://other.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(request, outboundEnv, EndpointConfig.create()), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void tokenPropagationDoesNotApplyWhenTransportDiffersFromUriScheme() {
        OidcProvider provider = provider(tenantWithTokenPropagation(), ordersTarget());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = SecurityEnvironment.builder()
                .targetUri(URI.create("http://api.example.com/orders/42"))
                .transport("https")
                .path("/orders/42")
                .method("GET")
                .build();

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(request, outboundEnv, EndpointConfig.create()), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void tokenPropagationDoesNotApplyToHttpTargetWhenTlsIsRequired() {
        OidcProvider provider = provider(tenantWithTokenPropagation(), ordersTargetForAllTransports());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = outboundEnvironment("http://api.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(request, outboundEnv, EndpointConfig.create()), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void endpointTokenPropagationDoesNotApplyWhenTargetUriIsMissingAndTlsIsRequired() {
        OidcProvider provider = provider(OidcTenantConfig.create());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = SecurityEnvironment.builder()
                .transport("https")
                .path("/orders/42")
                .method("GET")
                .build();
        EndpointConfig outboundConfig = EndpointConfig.builder()
                .customObject(OidcOutboundPolicy.class, OidcOutboundPolicy.tokenPropagation())
                .build();

        var response = provider.outboundSecurity(request, outboundEnv, outboundConfig);

        assertThat(provider.isOutboundSupported(request, outboundEnv, outboundConfig), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void endpointTokenPropagationDoesNotApplyWhenTargetUriHasNoSchemeAndTlsIsRequired() {
        OidcProvider provider = provider(OidcTenantConfig.create());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = SecurityEnvironment.builder()
                .targetUri(URI.create("/orders/42"))
                .transport("https")
                .path("/orders/42")
                .method("GET")
                .build();
        EndpointConfig outboundConfig = EndpointConfig.builder()
                .customObject(OidcOutboundPolicy.class, OidcOutboundPolicy.tokenPropagation())
                .build();

        var response = provider.outboundSecurity(request, outboundEnv, outboundConfig);

        assertThat(provider.isOutboundSupported(request, outboundEnv, outboundConfig), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void tokenPropagationDoesNotApplyToOtherPath() {
        OidcProvider provider = provider(tenantWithTokenPropagation(), ordersTarget());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/billing/42", "/billing/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(request, outboundEnv, EndpointConfig.create()), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void tokenPropagationDoesNotApplyToOtherMethod() {
        OidcProvider provider = provider(tenantWithTokenPropagation(), ordersTarget());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/orders/42", "/orders/42", "POST");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(request, outboundEnv, EndpointConfig.create()), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void tokenPropagationRequiresConfiguredTarget() {
        OidcProvider provider = provider(tenantWithTokenPropagation());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(request, outboundEnv, EndpointConfig.create()), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void audienceRestrictionAllowsMatchingToken() {
        OidcProvider provider = provider(OidcTenantConfig.create(), ordersTarget("api://orders"));
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer " + ACCESS_TOKEN)));
    }

    @Test
    void audienceRestrictionAllowsIntrospectionClaims() {
        OidcProvider provider = provider(OidcTenantConfig.create(), ordersTarget("api://orders"));
        ProviderRequest request = providerRequest(subjectWithJsonAudience("api://orders"));
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer " + ACCESS_TOKEN)));
    }

    @Test
    void audienceRestrictionRejectsMismatchedToken() {
        OidcProvider provider = provider(OidcTenantConfig.create(), ordersTarget("api://billing"));
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(request, outboundEnv, EndpointConfig.create()), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void audienceRestrictionRejectsRawTokenWithoutParsedClaims() {
        OidcProvider provider = provider(OidcTenantConfig.create(), ordersTarget("api://orders"));
        ProviderRequest request = providerRequest(subjectWithRawToken());
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(request, outboundEnv, EndpointConfig.create()), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void targetAudienceRestrictsTenantTokenPropagation() {
        OidcProvider provider = provider(tenantWithTokenPropagation(), ordersTargetAudienceOnly("api://billing"));
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(request, outboundEnv, EndpointConfig.create()), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void targetConfigurationCanSelectTokenPropagationAndAudience() {
        Config config = Config.builder()
                .sources(ConfigSources.create(Map.ofEntries(
                        Map.entry("tenants.default.enabled", "true"),
                        Map.entry("tenants.default.outbound.targets.0.name", "orders"),
                        Map.entry("tenants.default.outbound.targets.0.transports.0", "https"),
                        Map.entry("tenants.default.outbound.targets.0.hosts.0", "api.example.com"),
                        Map.entry("tenants.default.outbound.targets.0.paths.0", "/orders/.*"),
                        Map.entry("tenants.default.outbound.targets.0.methods.0", "GET"),
                        Map.entry("tenants.default.outbound.targets.0.token-propagation-enabled", "true"),
                        Map.entry("tenants.default.outbound.targets.0.audience", "api://orders"))))
                .build();
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.create(config));
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer " + ACCESS_TOKEN)));
    }

    private static OidcTenantConfig tenantWithTokenPropagation() {
        return OidcTenantConfig.builder()
                .outbound(it -> it.tokenPropagationEnabled(true))
                .buildPrototype();
    }

    private static OidcProvider provider(OidcTenantConfig tenant, OutboundTarget... outboundTargets) {
        OidcTenantConfig tenantWithTargets = OidcTenantConfig.builder()
                .from(tenant)
                .outbound(it -> it.from(tenant.outbound())
                        .targets(List.of(outboundTargets)))
                .buildPrototype();
        return OidcProvider.create(OidcProviderConfig.builder()
                                           .putTenant("default", tenantWithTargets)
                                           .buildPrototype());
    }

    private static OutboundTarget ordersTarget() {
        return OutboundTarget.builder("orders")
                .addTransport("https")
                .addHost("api.example.com")
                .addPath("/orders/.*")
                .addMethod("GET")
                .build();
    }

    private static OutboundTarget ordersTargetForAllTransports() {
        return OutboundTarget.builder("orders")
                .addHost("api.example.com")
                .addPath("/orders/.*")
                .addMethod("GET")
                .build();
    }

    private static OutboundTarget ordersTargetAudienceOnly(String audience) {
        return OutboundTarget.builder("orders")
                .addTransport("https")
                .addHost("api.example.com")
                .addPath("/orders/.*")
                .addMethod("GET")
                .customObject(OidcOutboundTargetConfig.class,
                              OidcOutboundTargetConfig.builder()
                                      .audience(audience)
                                      .buildPrototype())
                .build();
    }

    private static OutboundTarget ordersTarget(String audience) {
        return OutboundTarget.builder("orders")
                .addTransport("https")
                .addHost("api.example.com")
                .addPath("/orders/.*")
                .addMethod("GET")
                .customObject(OidcOutboundTargetConfig.class,
                              OidcOutboundTargetConfig.builder()
                                      .tokenPropagationEnabled(true)
                                      .audience(audience)
                                      .buildPrototype())
                .build();
    }

    private static SecurityEnvironment outboundEnvironment(String targetUri, String path) {
        return outboundEnvironment(targetUri, path, "GET");
    }

    private static SecurityEnvironment outboundEnvironment(String targetUri, String path, String method) {
        URI uri = URI.create(targetUri);
        return SecurityEnvironment.builder()
                .targetUri(uri)
                .transport(uri.getScheme())
                .path(path)
                .method(method)
                .header(EXISTING_HEADER_NAME, EXISTING_HEADER_VALUE)
                .build();
    }

    private static Subject subject(String audience) {
        Jwt jwt = Jwt.builder()
                .issuer("https://issuer.example")
                .subject("user1")
                .audience(List.of(audience))
                .issueTime(Instant.now().minusSeconds(60))
                .expirationTime(Instant.now().plusSeconds(600))
                .build();
        TokenCredential credential = TokenCredential.builder()
                .token(ACCESS_TOKEN)
                .addToken(Jwt.class, jwt)
                .build();
        return Subject.builder()
                .principal(Principal.create("user1"))
                .addPublicCredential(TokenCredential.class, credential)
                .build();
    }

    private static Subject subjectWithRawToken() {
        TokenCredential credential = TokenCredential.builder()
                .token(ACCESS_TOKEN)
                .build();
        return Subject.builder()
                .principal(Principal.create("user1"))
                .addPublicCredential(TokenCredential.class, credential)
                .build();
    }

    private static Subject subjectWithJsonAudience(String audience) {
        JsonObject claims = JsonObject.builder()
                .setStrings("aud", List.of(audience))
                .build();
        TokenCredential credential = TokenCredential.builder()
                .token(ACCESS_TOKEN)
                .addToken(JsonObject.class, claims)
                .build();
        return Subject.builder()
                .principal(Principal.create("user1"))
                .addPublicCredential(TokenCredential.class, credential)
                .build();
    }

    private static ProviderRequest providerRequest(Subject subject) {
        return new TestProviderRequest(subject);
    }

    private static final class TestProviderRequest implements ProviderRequest {
        private final Subject subject;

        private TestProviderRequest(Subject subject) {
            this.subject = subject;
        }

        @Override
        public EndpointConfig endpointConfig() {
            return EndpointConfig.create();
        }

        @Override
        public SecurityContext securityContext() {
            return null;
        }

        @Override
        public Optional<Subject> subject() {
            return Optional.of(subject);
        }

        @Override
        public Optional<Subject> service() {
            return Optional.empty();
        }

        @Override
        public SecurityEnvironment env() {
            return SecurityEnvironment.create();
        }

        @Override
        public Optional<Object> getObject() {
            return Optional.empty();
        }

        @Override
        public Object abacAttributeRaw(String key) {
            return null;
        }

        @Override
        public Collection<String> abacAttributeNames() {
            return List.of();
        }
    }
}
