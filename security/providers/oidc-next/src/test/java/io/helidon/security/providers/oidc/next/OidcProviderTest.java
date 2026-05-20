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

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.ServiceLoader;

import io.helidon.config.Config;
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
        OidcProvider provider = OidcProvider.create();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.protectedResource(), SecurityEnvironment.create()));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.statusCode().orElse(-1), is(401));
        assertThat(response.responseHeaders().get("WWW-Authenticate"), is(List.of("Bearer")));
    }

    @Test
    void bearerTokenEvidenceSelectsBearerTokenAuthenticationWhenBothOperationsArePossible() {
        OidcProvider provider = OidcProvider.create();
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
    void bothProtocolOperationsWithoutEvidenceFailsSafely() {
        OidcProvider provider = OidcProvider.create();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.protectedResourceAndAuthorizationCodeFlow(), SecurityEnvironment.create()));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.statusCode().orElse(-1), is(400));
        assertThat(response.description().orElse(""), is("OIDC request cannot be classified by protocol operation"));
    }

    @Test
    void authorizationCodeFlowInitiationIsClassifiedButDeferred() {
        OidcProvider provider = OidcProvider.create();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.authorizationCodeFlow(), SecurityEnvironment.create()));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.statusCode().orElse(-1), is(501));
        assertThat(response.description().orElse(""), is("Authorization Code Flow initiation is not implemented yet"));
        assertThat(response.responseHeaders().containsKey("Location"), is(false));
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
        OidcProvider provider = OidcProvider.create();
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
        OidcProvider provider = OidcProvider.create();
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
        OidcProvider provider = OidcProvider.create();
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

    private static ProviderRequest request(OidcEndpointPolicy endpointPolicy, SecurityEnvironment environment) {
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
