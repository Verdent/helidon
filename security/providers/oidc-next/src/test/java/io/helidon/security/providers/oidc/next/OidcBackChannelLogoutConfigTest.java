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

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OidcBackChannelLogoutConfigTest {
    private static final String ISSUER = "https://issuer.example";

    @Test
    void backChannelIsOptInAndAnExplicitStoreAllowsAnIndependentFeature() {
        OidcTenantConfig tenant = tenant(URI.create("https://rp.example/oidc/backchannel"));
        assertThat(tenant.logout().orElseThrow().backChannel().orElseThrow().sessionRequired(), is(false));
        OidcProviderConfig config = OidcProviderConfig.builder().putTenant("default", tenant).buildPrototype();

        assertThrows(IllegalArgumentException.class, () -> OidcFeature.create(config));
        OidcTenantConfig shared = OidcTenantConfig.builder(tenant)
                .logout(logout -> logout.backChannel(backChannel -> backChannel
                        .uri(URI.create("https://rp.example/oidc/backchannel"))
                        .store(new OidcInMemoryLogoutStore())))
                .buildPrototype();
        OidcFeature.create(OidcProviderConfig.builder().putTenant("default", shared).buildPrototype());
    }

    @Test
    void invalidOrAmbiguousLogoutUriFailsConfiguration() {
        for (String uri : new String[] {"/oidc/backchannel", "https://rp.example/oidc/backchannel#fragment",
                "https://user:pass@rp.example/oidc/backchannel", "https://rp.example/oidc/callback",
                "https://rp.example/oidc/logout"}) {
            assertThrows(IllegalArgumentException.class, () -> tenant(URI.create(uri)), uri);
        }
        OidcTenantConfig first = tenant(URI.create("https://rp.example/oidc/backchannel"));
        OidcTenantConfig second = OidcTenantConfig.builder(first).clientId("second-client")
                .issuer("https://second-issuer.example").buildPrototype();
        assertThrows(IllegalArgumentException.class,
                     () -> OidcProviderConfig.builder().putTenant("one", first).putTenant("two", second)
                             .buildPrototype());
    }

    private static OidcTenantConfig tenant(URI uri) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client-id")
                .clientSecret("client-secret")
                .endpoints(endpoints -> endpoints.authorizationEndpointUri(URI.create(ISSUER + "/authorize"))
                        .tokenEndpointUri(URI.create(ISSUER + "/token"))
                        .jwksUri(URI.create(ISSUER + "/jwks")))
                .authorizationCode(code -> code.redirectionEndpointUri(URI.create("https://rp.example/oidc/callback")))
                .logout(logout -> logout.backChannel(backChannel -> backChannel.uri(uri)))
                .cookies(cookies -> cookies.password("test-cookie-password"))
                .buildPrototype();
    }
}
