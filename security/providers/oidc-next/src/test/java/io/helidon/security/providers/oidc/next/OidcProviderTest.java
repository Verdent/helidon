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
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.function.Consumer;

import io.helidon.common.uri.UriQuery;
import io.helidon.config.Config;
import io.helidon.http.SetCookie;
import io.helidon.security.EndpointConfig;
import io.helidon.security.AuthenticationResponse;
import io.helidon.security.OutboundSecurityResponse;
import io.helidon.security.ProviderRequest;
import io.helidon.security.SecurityContext;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;
import io.helidon.security.Subject;
import io.helidon.security.spi.SecurityProviderService;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;

class OidcProviderTest {
    private static final String CURRENT_PROVIDER_CONFIG_KEY = "oidc";
    private static final String OIDC_NEXT_PACKAGE = "io.helidon.security.providers.oidc.next";
    private static final URI ISSUER = URI.create("https://issuer.example");
    private static final URI AUTHORIZATION_ENDPOINT_URI = URI.create("https://issuer.example/authorize");
    private static final URI TOKEN_ENDPOINT_URI = URI.create("https://issuer.example/token");
    private static final URI REDIRECTION_ENDPOINT_URI = URI.create("https://rp.example/oidc/callback");
    private static final URI ORIGINAL_URI = URI.create("https://rp.example/resource?name=value");

    @Test
    void serviceCreatesProvider() {
        OidcProviderService service = new OidcProviderService();

        assertThat(service.providerConfigKey(), is("oidc-next"));
        assertThat(service.providerClass() == OidcProvider.class, is(true));
        assertThat(service.create(Config.empty()), instanceOf(OidcProvider.class));
    }

    @Test
    void serviceIsDiscoverable() {
        boolean found = false;

        for (SecurityProviderService service : ServiceLoader.load(SecurityProviderService.class)) {
            if (OidcProviderService.PROVIDER_CONFIG_KEY.equals(service.providerConfigKey())) {
                assertThat(service.providerClass() == OidcProvider.class, is(true));
                found = true;
            }
        }

        assertThat(found, is(true));
    }

    @Test
    void stage0KeepsNewProviderIsolatedFromCurrentProvider() {
        assertThat(OidcProvider.class.getPackageName(), is(OIDC_NEXT_PACKAGE));
        assertThat(OidcProviderService.PROVIDER_CONFIG_KEY, is("oidc-next"));
        assertThat(OidcProviderService.PROVIDER_CONFIG_KEY, is(not(CURRENT_PROVIDER_CONFIG_KEY)));
    }

    @Test
    void providerAbstainsUntilFlowsAreImplemented() {
        OidcProvider provider = OidcProvider.create();

        assertThat(provider.authenticate(null).status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
        assertThat(provider.isOutboundSupported(null, null, null), is(false));
        assertThat(provider.outboundSecurity(null, null, null).status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void protectedResourceMissingBearerTokenReturnsChallenge() {
        OidcProvider provider = providerWithTenant();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.protectedResource(), SecurityEnvironment.create()));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.statusCode().orElse(-1), is(401));
        assertThat(response.responseHeaders().get("WWW-Authenticate"), is(List.of("Bearer")));
    }

    @Test
    void bearerTokenEvidenceSelectsBearerTokenAuthenticationWhenBothOperationsArePossible() {
        OidcProvider provider = providerWithTenant();
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .header("Authorization", "Bearer access-token")
                .build();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.protectedResourceAndAuthorizationCodeFlow(), environment));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.statusCode().orElse(-1), is(401));
        assertThat(response.description().orElse(""), is("Bearer Token validation is not implemented yet"));
        assertThat(response.responseHeaders().get("WWW-Authenticate").get(0).startsWith("Bearer "), is(true));
    }

    @Test
    void invalidBearerTokenRequestFailsSafely() {
        OidcProvider provider = providerWithQueryParameterTransport();
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .header("Authorization", "Bearer header-token")
                .queryParam("access_token", "query-token")
                .build();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.protectedResource(), environment));

        assertInvalidBearerTokenRequest(response, "Multiple Bearer Token credential sources found");
    }

    @Test
    void multipleAuthorizationHeaderBearerTokensFailSafely() {
        OidcProvider provider = providerWithTenant();
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .header("Authorization", List.of("Bearer first-token", "Bearer second-token"))
                .build();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.protectedResource(), environment));

        assertInvalidBearerTokenRequest(response, "Multiple Bearer Tokens found in Authorization header");
    }

    @Test
    void multipleQueryParameterBearerTokensFailSafely() {
        OidcProvider provider = providerWithQueryParameterTransport();
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .queryParam("access_token", List.of("first-token", "second-token"))
                .build();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.protectedResource(), environment));

        assertInvalidBearerTokenRequest(response, "Multiple Bearer Tokens found in query parameter");
    }

    @Test
    void malformedQueryParameterBearerTokenFailsSafely() {
        OidcProvider provider = providerWithQueryParameterTransport();
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .queryParam("access_token", " ")
                .build();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.protectedResource(), environment));

        assertInvalidBearerTokenRequest(response, "Malformed Bearer Token in query parameter");
    }

    @Test
    void bareQueryParameterBearerTokenFailsSafely() {
        OidcProvider provider = providerWithQueryParameterTransport();
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .queryParams(UriQuery.create("access_token"))
                .build();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.protectedResource(), environment));

        assertInvalidBearerTokenRequest(response, "Malformed Bearer Token in query parameter");
    }

    @Test
    void bareQueryParameterWithAnotherBearerTokenFailsSafely() {
        OidcProvider provider = providerWithQueryParameterTransport();
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .targetUri(URI.create("https://rp.example/resource?access_token&access_token=access-token"))
                .queryParams(UriQuery.create("access_token&access_token=access-token"))
                .build();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.protectedResource(), environment));

        assertInvalidBearerTokenRequest(response, "Multiple Bearer Tokens found in query parameter");
    }

    @Test
    void disabledTransportCredentialIsIgnoredWhenEnabledTransportHasBearerToken() {
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                                                  .putTenant("default", OidcTenantConfig.builder()
                                                          .tokenTransport(it -> it.authorizationHeaderEnabled(false)
                                                                  .queryParameterEnabled(true))
                                                          .buildPrototype())
                                                  .buildPrototype());
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .header("Authorization", "Bearer disabled-header-token")
                .queryParam("access_token", "query-token")
                .build();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.protectedResource(), environment));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.statusCode().orElse(-1), is(401));
        assertThat(response.description().orElse(""), is("Bearer Token validation is not implemented yet"));
    }

    @Test
    void malformedBearerTokenFailsEvenWhenProviderIsOptional() {
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                                                  .optional(true)
                                                  .putTenant("default", OidcTenantConfig.create())
                                                  .buildPrototype());
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .header("Authorization", "Bearer ")
                .build();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.protectedResource(), environment));

        assertInvalidBearerTokenRequest(response, "Malformed Bearer Token in Authorization header");
    }

    @Test
    void bothProtocolOperationsWithoutEvidenceFailsSafely() {
        OidcProvider provider = providerWithTenant();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.protectedResourceAndAuthorizationCodeFlow(), SecurityEnvironment.create()));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.statusCode().orElse(-1), is(400));
        assertThat(response.description().orElse(""), is("OIDC request cannot be classified by protocol operation"));
    }

    @Test
    void authorizationCodeFlowInitiationRedirectsToAuthorizationEndpoint() {
        OidcTenantConfig tenant = authorizationCodeTenant();
        OidcProvider provider = provider(tenant);
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .targetUri(ORIGINAL_URI)
                .path("/resource")
                .transport("https")
                .build();

        AuthenticationResponse response = provider.authenticate(
                request(null, environment));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE_FINISH));
        assertThat(response.statusCode().orElse(-1), is(303));

        URI location = URI.create(response.responseHeaders().get("Location").get(0));
        assertThat(location.getScheme(), is("https"));
        assertThat(location.getHost(), is("issuer.example"));
        assertThat(location.getPath(), is("/authorize"));

        UriQuery query = UriQuery.create(location);
        assertThat(query.get("response_type"), is("code"));
        assertThat(query.get("client_id"), is("client-id"));
        assertThat(query.get("redirect_uri"), is(REDIRECTION_ENDPOINT_URI.toString()));
        assertThat(query.get("scope"), is("openid profile"));
        assertThat(query.contains("state"), is(true));
        assertThat(query.contains("nonce"), is(true));
        assertThat(query.get("code_challenge_method"), is("S256"));

        OidcAuthenticationRequestState state = authenticationRequestState(response, tenant);
        assertThat(state.tenantId(), is("default"));
        assertThat(state.state(), is(query.get("state")));
        assertThat(state.nonce(), is(query.get("nonce")));
        assertThat(state.originalUri(), is(ORIGINAL_URI));
        assertThat(state.redirectionEndpointUri(), is(REDIRECTION_ENDPOINT_URI));
        assertThat(state.pkceVerifier().isPresent(), is(true));
        assertThat(query.get("code_challenge"),
                   is(OidcAuthenticationRequestFactory.codeChallenge(state.pkceVerifier().orElseThrow(),
                                                                     OidcPkceMethod.S256)));
    }

    @Test
    void authorizationCodeFlowCanDisablePkce() {
        OidcTenantConfig tenant = authorizationCodeTenant(code -> code.pkceRequired(false));
        OidcProvider provider = provider(tenant);

        AuthenticationResponse response = provider.authenticate(
                request(null, SecurityEnvironment.builder()
                        .targetUri(ORIGINAL_URI)
                        .build()));

        URI location = URI.create(response.responseHeaders().get("Location").get(0));
        UriQuery query = UriQuery.create(location);
        assertThat(query.contains("code_challenge"), is(false));
        assertThat(query.contains("code_challenge_method"), is(false));
        assertThat(authenticationRequestState(response, tenant).pkceVerifier().isEmpty(), is(true));
    }

    @Test
    void authenticationRequestStateCookieIsProtectedAndScoped() {
        OidcTenantConfig tenant = authorizationCodeTenant();
        OidcProvider provider = provider(tenant);

        AuthenticationResponse response = provider.authenticate(
                request(null, SecurityEnvironment.builder()
                        .targetUri(ORIGINAL_URI)
                        .build()));

        SetCookie cookie = SetCookie.parse(response.responseHeaders().get("Set-Cookie").get(0));
        assertThat(cookie.name(), is("__Host-helidon-oidc-state"));
        assertThat(cookie.value().startsWith("v1."), is(true));
        assertThat(cookie.path().orElse(""), is("/"));
        assertThat(cookie.httpOnly(), is(true));
        assertThat(cookie.secure(), is(true));
        assertThat(cookie.sameSite().orElseThrow(), is(SetCookie.SameSite.LAX));
        assertThat(cookie.maxAge().orElseThrow().getSeconds(), is(300L));
        assertThat(authenticationRequestState(response, tenant).expiresAt().isAfter(Instant.now()), is(true));
    }

    @Test
    void authorizationResponseProcessingIsLeftToFeatureEndpoint() {
        OidcProvider provider = OidcProvider.create();
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .queryParam("code", "authorization-code")
                .queryParam("state", "stored-state")
                .build();

        AuthenticationResponse response = provider.authenticate(request(null, environment));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void outboundWithoutPolicyAbstains() {
        OidcProvider provider = OidcProvider.create();
        ProviderRequest providerRequest = request(null, SecurityEnvironment.create());
        EndpointConfig outboundConfig = EndpointConfig.create();

        assertThat(provider.isOutboundSupported(providerRequest, SecurityEnvironment.create(), outboundConfig), is(false));
        assertThat(provider.outboundSecurity(providerRequest, SecurityEnvironment.create(), outboundConfig).status(),
                   is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void tokenPropagationIsClassifiedButDeferred() {
        OidcProvider provider = providerWithTenant();
        ProviderRequest providerRequest = request(null, SecurityEnvironment.create());
        EndpointConfig outboundConfig = outboundConfig(OidcOutboundPolicy.tokenPropagation());

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest,
                                                                      SecurityEnvironment.create(),
                                                                      outboundConfig);

        assertThat(provider.isOutboundSupported(providerRequest, SecurityEnvironment.create(), outboundConfig), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.description().orElse(""), is("Token Propagation is not implemented yet"));
    }

    @Test
    void clientCredentialsGrantIsClassifiedButDeferred() {
        OidcProvider provider = providerWithTenant();
        ProviderRequest providerRequest = request(null, SecurityEnvironment.create());
        EndpointConfig outboundConfig = outboundConfig(OidcOutboundPolicy.clientCredentialsGrant());

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest,
                                                                      SecurityEnvironment.create(),
                                                                      outboundConfig);

        assertThat(provider.isOutboundSupported(providerRequest, SecurityEnvironment.create(), outboundConfig), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.description().orElse(""), is("Client Credentials Grant is not implemented yet"));
    }

    @Test
    void outboundProtocolOperationAmbiguityFailsSafely() {
        OidcProvider provider = providerWithTenant();
        ProviderRequest providerRequest = request(null, SecurityEnvironment.create());
        EndpointConfig outboundConfig = outboundConfig(OidcOutboundPolicy.tokenPropagationAndClientCredentialsGrant());

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest,
                                                                      SecurityEnvironment.create(),
                                                                      outboundConfig);

        assertThat(provider.isOutboundSupported(providerRequest, SecurityEnvironment.create(), outboundConfig), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.description().orElse(""),
                   is("OIDC outbound request cannot be classified by protocol operation"));
    }

    static ProviderRequest request(OidcEndpointPolicy endpointPolicy, SecurityEnvironment environment) {
        EndpointConfig.Builder endpointConfig = EndpointConfig.builder();
        if (endpointPolicy != null) {
            endpointConfig.customObject(OidcEndpointPolicy.class, endpointPolicy);
        }
        return new TestProviderRequest(endpointConfig.build(), environment);
    }

    private static EndpointConfig outboundConfig(OidcOutboundPolicy outboundPolicy) {
        return EndpointConfig.builder()
                .customObject(OidcOutboundPolicy.class, outboundPolicy)
                .build();
    }

    private static OidcProvider providerWithTenant() {
        return provider(OidcTenantConfig.create());
    }

    private static OidcProvider providerWithQueryParameterTransport() {
        return provider(OidcTenantConfig.builder()
                                .tokenTransport(it -> it.queryParameterEnabled(true))
                                .buildPrototype());
    }

    private static OidcProvider provider(OidcTenantConfig tenant) {
        return OidcProvider.create(OidcProviderConfig.builder()
                                           .putTenant("default", tenant)
                                           .buildPrototype());
    }

    private static OidcTenantConfig authorizationCodeTenant() {
        return authorizationCodeTenant(it -> { });
    }

    private static OidcTenantConfig authorizationCodeTenant(Consumer<OidcAuthorizationCodeConfig.Builder> customizer) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> {
                    it.enabled(true)
                            .redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                            .scopes(List.of("openid", "profile"));
                    customizer.accept(it);
                })
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();
    }

    private static OidcAuthenticationRequestState authenticationRequestState(AuthenticationResponse response,
                                                                             OidcTenantConfig tenant) {
        SetCookie cookie = SetCookie.parse(response.responseHeaders().get("Set-Cookie").get(0));
        return OidcCookieStateHandler.create(tenant)
                .readAuthenticationRequestState(cookie.value(), Instant.now())
                .orElseThrow();
    }

    private static void assertInvalidBearerTokenRequest(AuthenticationResponse response, String description) {
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.statusCode().orElse(-1), is(400));
        assertThat(response.description().orElse(""), is(description));
        assertThat(response.responseHeaders().get("WWW-Authenticate").get(0).contains("invalid_request"), is(true));
    }

    private static final class TestProviderRequest implements ProviderRequest {
        private final EndpointConfig endpointConfig;
        private final SecurityEnvironment environment;

        private TestProviderRequest(EndpointConfig endpointConfig, SecurityEnvironment environment) {
            this.endpointConfig = endpointConfig;
            this.environment = environment;
        }

        @Override
        public EndpointConfig endpointConfig() {
            return endpointConfig;
        }

        @Override
        public SecurityContext securityContext() {
            return null;
        }

        @Override
        public Optional<Subject> subject() {
            return Optional.empty();
        }

        @Override
        public Optional<Subject> service() {
            return Optional.empty();
        }

        @Override
        public SecurityEnvironment env() {
            return environment;
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
