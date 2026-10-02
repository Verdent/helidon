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
import java.util.Map;

import io.helidon.config.Config;
import io.helidon.config.ConfigSources;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OidcIssuerUniquenessConfigTest {
    private static final String ISSUER = "https://identity.oraclecloud.com/";

    @Test
    void defaultRejectsDistinctAuthorizationServersSharingIssuer() {
        assertThat(OidcProviderConfig.create().issuerUniquenessValidationEnabled(), is(true));
        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                                                        () -> provider(true,
                                                                       tenant("https://idcs-a.example", "/oidc/a"),
                                                                       tenant("https://idcs-b.example", "/oidc/b")));
        assertThat(failure.getMessage(), containsString("must use matching authorization-endpoint-uri"));
    }

    @Test
    void explicitExceptionRequiresDistinctCallbackAndPinnedEndpoints() {
        OidcProviderConfig config = provider(false,
                                             tenant("https://idcs-a.example", "/oidc/a"),
                                             tenant("https://idcs-b.example", "/oidc/b"));
        assertThat(config.issuerUniquenessValidationEnabled(), is(false));
        assertThat(OidcMixUpProtection.issuerParameterRequiredTenants(config).isEmpty(), is(true));

        IllegalArgumentException samePath = assertThrows(IllegalArgumentException.class,
                                                         () -> provider(false,
                                                                        tenant("https://idcs-a.example", "/oidc/a"),
                                                                        tenant("https://idcs-b.example", "/oidc/a")));
        assertThat(samePath.getMessage(), containsString("distinct redirection-endpoint-uri"));
    }

    @Test
    void explicitExceptionDoesNotTurnQueryOnlyDifferencesIntoDistinctCallbacks() {
        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                                                        () -> provider(false,
                                                                       tenant("https://idcs-a.example", "/oidc/a?op=a"),
                                                                       tenant("https://idcs-b.example", "/oidc/a?op=b")));
        assertThat(failure.getMessage(), containsString("distinct redirection-endpoint-uri"));
    }

    @Test
    void explicitExceptionRejectsHonestAuthorizationWithWrongTokenEndpoint() {
        OidcTenantConfig honest = tenant("https://idcs-a.example", "/oidc/a");
        OidcTenantConfig attacker = OidcTenantConfig.builder()
                .from(tenant("https://idcs-b.example", "/oidc/b"))
                .endpoints(it -> it.authorizationEndpointUri(URI.create("https://idcs-a.example/authorize"))
                        .tokenEndpointUri(URI.create("https://idcs-b.example/token"))
                        .jwksUri(URI.create("https://idcs-b.example/jwks")))
                .buildPrototype();
        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                                                        () -> provider(false, honest, attacker));
        assertThat(failure.getMessage(), containsString("one Authorization Endpoint origin"));

        OidcTenantConfig queryVariant = OidcTenantConfig.builder()
                .from(attacker)
                .endpoints(it -> it.authorizationEndpointUri(URI.create("https://idcs-a.example/authorize?different=true"))
                        .tokenEndpointUri(URI.create("https://idcs-b.example/token"))
                        .jwksUri(URI.create("https://idcs-b.example/jwks")))
                .buildPrototype();
        assertThrows(IllegalArgumentException.class, () -> provider(false, honest, queryVariant));
    }

    @Test
    void explicitExceptionLoadsFromConfig() {
        Config config = Config.builder()
                .sources(ConfigSources.create(Map.ofEntries(
                        Map.entry("issuer-uniqueness-validation-enabled", "false"),
                        Map.entry("tenants.first.issuer", ISSUER),
                        Map.entry("tenants.first.client-id", "client-a"),
                        Map.entry("tenants.first.client-secret", "secret-a"),
                        Map.entry("tenants.first.endpoints.authorization-endpoint-uri", "https://idcs-a.example/authorize"),
                        Map.entry("tenants.first.endpoints.token-endpoint-uri", "https://idcs-a.example/token"),
                        Map.entry("tenants.first.endpoints.jwks-uri", "https://idcs-a.example/jwks"),
                        Map.entry("tenants.first.authorization-code.redirection-endpoint-uri", "/oidc/a"),
                        Map.entry("tenants.first.cookies.protection.password", "a-long-enough-unique-test-password"),
                        Map.entry("tenants.second.issuer", ISSUER),
                        Map.entry("tenants.second.client-id", "client-b"),
                        Map.entry("tenants.second.client-secret", "secret-b"),
                        Map.entry("tenants.second.endpoints.authorization-endpoint-uri", "https://idcs-b.example/authorize"),
                        Map.entry("tenants.second.endpoints.token-endpoint-uri", "https://idcs-b.example/token"),
                        Map.entry("tenants.second.endpoints.jwks-uri", "https://idcs-b.example/jwks"),
                        Map.entry("tenants.second.authorization-code.redirection-endpoint-uri", "/oidc/b"),
                        Map.entry("tenants.second.cookies.protection.password", "another-unique-test-password"))))
                .build();
        OidcProviderConfig provider = OidcProviderConfig.create(config);
        assertThat(provider.issuerUniquenessValidationEnabled(), is(false));
        assertThat(provider.tenants().size(), is(2));
    }

    private static OidcProviderConfig provider(boolean issuerUniquenessValidationEnabled,
                                               OidcTenantConfig first,
                                               OidcTenantConfig second) {
        return OidcProviderConfig.builder()
                .issuerUniquenessValidationEnabled(issuerUniquenessValidationEnabled)
                .putTenant("first", first)
                .putTenant("second", second)
                .buildPrototype();
    }

    private static OidcTenantConfig tenant(String authority, String callback) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client")
                .clientSecret("secret")
                .endpoints(it -> it.authorizationEndpointUri(URI.create(authority + "/authorize"))
                        .tokenEndpointUri(URI.create(authority + "/token"))
                        .jwksUri(URI.create(authority + "/jwks")))
                .authorizationCode(it -> it.redirectionEndpointUri(URI.create(callback)))
                .cookies(it -> it.protection(protection -> protection.password("a-long-enough-unique-test-password")))
                .buildPrototype();
    }
}
