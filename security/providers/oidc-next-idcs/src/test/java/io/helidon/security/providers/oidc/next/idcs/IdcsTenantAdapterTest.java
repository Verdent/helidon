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

package io.helidon.security.providers.oidc.next.idcs;

import java.net.URI;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import io.helidon.config.Config;
import io.helidon.config.ConfigSources;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.security.providers.oidc.next.OidcTenantConfig;
import io.helidon.webclient.api.WebClient;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class IdcsTenantAdapterTest {
    private static final URI DOMAIN = URI.create("https://idcs-one.identity.oraclecloud.com");
    private static final String COOKIE_PASSWORD = "this-password-is-long-enough-for-tests";

    @Test
    void programmaticAdapterSuppliesDefaultsButKeepsExplicitEndpoints() {
        IdcsTenantAdapter adapter = IdcsTenantAdapter.builder().domainUri(DOMAIN).build();
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .adapter(adapter)
                .clientId("idcs-client")
                .clientSecret("idcs-secret")
                .endpoints(endpoints -> endpoints.userInfoEndpointUri(URI.create("https://idcs-one.identity.oraclecloud.com/custom")))
                .authorizationCode(code -> code.redirectionEndpointUri(URI.create("/oidc/idcs-callback")))
                .cookies(cookies -> cookies.protection(protection -> protection.password(COOKIE_PASSWORD)))
                .buildPrototype();

        assertThat(tenant.issuer().orElseThrow(), is("https://identity.oraclecloud.com/"));
        assertThat(tenant.endpoints().authorizationEndpointUri().orElseThrow(),
                   is(DOMAIN.resolve("/oauth2/v1/authorize")));
        assertThat(tenant.endpoints().tokenEndpointUri().orElseThrow(), is(DOMAIN.resolve("/oauth2/v1/token")));
        assertThat(tenant.endpoints().jwksUri().orElseThrow(), is(DOMAIN.resolve("/admin/v1/SigningCert/jwk")));
        assertThat(tenant.endpoints().userInfoEndpointUri().orElseThrow(),
                   is(URI.create("https://idcs-one.identity.oraclecloud.com/custom")));
        assertThat(tenant.adapter().orElseThrow(), is(adapter));
    }

    @Test
    void namedIdcsAndStandardOidcTenantsLoadTogetherFromConfig() {
        Config config = Config.builder()
                .sources(ConfigSources.create(Map.ofEntries(
                        Map.entry("tenants.oracle.adapter.idcs.domain-uri", DOMAIN.toString()),
                        Map.entry("tenants.oracle.client-id", "idcs-client"),
                        Map.entry("tenants.oracle.client-secret", "idcs-secret"),
                        Map.entry("tenants.oracle.authorization-code.redirection-endpoint-uri", "/oidc/idcs-callback"),
                        Map.entry("tenants.oracle.cookies.protection.password", COOKIE_PASSWORD),
                        Map.entry("tenants.regular.issuer", "https://regular.example"),
                        Map.entry("tenants.regular.client-id", "regular-client"),
                        Map.entry("tenants.regular.client-secret", "regular-secret"),
                        Map.entry("tenants.regular.endpoints.authorization-endpoint-uri", "https://regular.example/auth"),
                        Map.entry("tenants.regular.endpoints.token-endpoint-uri", "https://regular.example/token"),
                        Map.entry("tenants.regular.endpoints.jwks-uri", "https://regular.example/jwks"),
                        Map.entry("tenants.regular.authorization-code.redirection-endpoint-uri", "/oidc/regular-callback"),
                        Map.entry("tenants.regular.cookies.protection.password", COOKIE_PASSWORD))))
                .build();

        OidcProviderConfig provider = OidcProviderConfig.create(config);
        assertThat(provider.tenants().size(), is(2));
        assertThat(provider.tenants().get("oracle").adapter().orElseThrow().type(), is("idcs"));
        assertThat(provider.tenants().get("oracle").endpoints().jwksUri().orElseThrow(),
                   is(DOMAIN.resolve("/admin/v1/SigningCert/jwk")));
        assertThat(provider.tenants().get("regular").adapter().isEmpty(), is(true));
        assertThat(provider.tenants().get("regular").issuer().orElseThrow(), is("https://regular.example"));
    }

    @Test
    void providerRootConfigCanSelectIdcsAdapter() {
        Config config = Config.builder()
                .sources(ConfigSources.create(Map.of(
                        "adapter.idcs.domain-uri", DOMAIN.toString(),
                        "client-id", "client",
                        "client-secret", "secret",
                        "authorization-code.redirection-endpoint-uri", "/oidc/callback",
                        "cookies.protection.password", COOKIE_PASSWORD)))
                .build();

        OidcProviderConfig provider = OidcProviderConfig.create(config);
        assertThat(provider.tenants().size(), is(1));
        assertThat(provider.tenants().get(provider.defaultTenant().orElseThrow()).adapter().orElseThrow().type(), is("idcs"));
    }

    @Test
    void configuredSecureDomainSelectsCertificateGrantEndpointsWithoutChangingBrowserEndpoint() {
        URI secureDomain = URI.create("https://idcs-one.secure.identity.oraclecloud.com");
        Config config = Config.builder()
                .sources(ConfigSources.create(Map.of(
                        "domain-uri", DOMAIN.toString(),
                        "secure-domain-uri", secureDomain.toString(),
                        "jwks-grant", "TLS_CLIENT_AUTH",
                        "jwks-scope", "urn:opc:idm:__myscopes__")))
                .build();
        IdcsTenantAdapter adapter = IdcsTenantAdapter.create(config);
        OidcTenantConfig tenant = OidcTenantConfig.builder().adapter(adapter).clientId("client").buildPrototype();

        assertThat(tenant.endpoints().authorizationEndpointUri().orElseThrow(),
                   is(DOMAIN.resolve("/oauth2/v1/authorize")));
        assertThat(tenant.endpoints().tokenEndpointUri().orElseThrow(),
                   is(secureDomain.resolve("/oauth2/v1/token")));
        assertThat(tenant.endpoints().jwksUri().orElseThrow(),
                   is(secureDomain.resolve("/admin/v1/SigningCert/jwk")));
        assertThat(adapter.principalIdentityNamespace().orElseThrow(), is(DOMAIN.toString()));
    }

    @Test
    void twoIdcsDomainsRequireExplicitIssuerExceptionAndDistinctCallbacks() {
        Config config = Config.builder()
                .sources(ConfigSources.create(Map.ofEntries(
                        Map.entry("issuer-uniqueness-validation-enabled", "false"),
                        Map.entry("tenants.first.adapter.idcs.domain-uri", DOMAIN.toString()),
                        Map.entry("tenants.first.client-id", "client-one"),
                        Map.entry("tenants.first.client-secret", "secret-one"),
                        Map.entry("tenants.first.authorization-code.redirection-endpoint-uri", "/oidc/idcs-one"),
                        Map.entry("tenants.first.cookies.protection.password", COOKIE_PASSWORD),
                        Map.entry("tenants.second.adapter.idcs.domain-uri", "https://idcs-two.identity.oraclecloud.com"),
                        Map.entry("tenants.second.client-id", "client-two"),
                        Map.entry("tenants.second.client-secret", "secret-two"),
                        Map.entry("tenants.second.authorization-code.redirection-endpoint-uri", "/oidc/idcs-two"),
                        Map.entry("tenants.second.cookies.protection.password", COOKIE_PASSWORD))))
                .build();

        OidcProviderConfig provider = OidcProviderConfig.create(config);
        assertThat(provider.tenants().size(), is(2));
        assertThat(provider.tenants().get("first").endpoints().tokenEndpointUri().orElseThrow(),
                   is(DOMAIN.resolve("/oauth2/v1/token")));
        assertThat(provider.tenants().get("second").endpoints().tokenEndpointUri().orElseThrow(),
                   is(URI.create("https://idcs-two.identity.oraclecloud.com/oauth2/v1/token")));

        IllegalArgumentException strict = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcProviderConfig.builder()
                                                               .putTenant("first", provider.tenants().get("first"))
                                                               .putTenant("second", provider.tenants().get("second"))
                                                               .buildPrototype());
        assertThat(strict.getMessage(), containsString("must use matching authorization-endpoint-uri"));
    }

    @Test
    void protectedJwkCredentialIsScopedToSelectedDomainAndRequestedOnlyOnChallenge() {
        IdcsTenantAdapter adapter = IdcsTenantAdapter.builder().domainUri(DOMAIN).build();
        OidcTenantConfig tenant = OidcTenantConfig.builder().adapter(adapter).buildPrototype();
        AtomicInteger acquisitions = new AtomicInteger();
        WebClient client = WebClient.create();
        try {
            assertThat(adapter.jwkSetAccessToken(tenant,
                                                 DOMAIN.resolve("/admin/v1/SigningCert/jwk"),
                                                 client,
                                                 scope -> {
                                                     assertThat(scope, is("urn:opc:idm:__myscopes__"));
                                                     acquisitions.incrementAndGet();
                                                     return "jwks-only-token";
                                                 }).orElseThrow(),
                       is("jwks-only-token"));
            assertThat(acquisitions.get(), is(1));
            IllegalStateException foreignEndpoint = assertThrows(IllegalStateException.class,
                                                                 () -> adapter.jwkSetAccessToken(
                                                                         tenant,
                                                                         URI.create("https://attacker.example/jwks"),
                                                                         client,
                                                                         scope -> "should-not-be-used"));
            assertThat(foreignEndpoint.getMessage(), containsString("configured IDCS domain"));
            assertThat(acquisitions.get(), is(1));
            OidcTenantConfig wrongTokenEndpoint = OidcTenantConfig.builder()
                    .from(tenant)
                    .endpoints(endpoints -> endpoints.authorizationEndpointUri(DOMAIN.resolve("/oauth2/v1/authorize"))
                            .tokenEndpointUri(URI.create("https://attacker.example/token"))
                            .jwksUri(DOMAIN.resolve("/admin/v1/SigningCert/jwk")))
                    .buildPrototype();
            IllegalStateException wrongToken = assertThrows(IllegalStateException.class,
                                                            () -> adapter.jwkSetAccessToken(wrongTokenEndpoint,
                                                                                           DOMAIN.resolve(
                                                                                                   "/admin/v1/SigningCert/jwk"),
                                                                                           client,
                                                                                           _ -> {
                                                                                               acquisitions.incrementAndGet();
                                                                                               return "unused";
                                                                                           }));
            assertThat(wrongToken.getMessage(), containsString("Token Endpoint on the IDCS domain"));
            assertThat(acquisitions.get(), is(1));
        } finally {
            client.closeResource();
        }
    }

    @Test
    void domainUriMustBeSecureAndIdentifyOnlyAnOrigin() {
        for (String uri : new String[] {
                "http://idcs.example", "https://idcs.example/path", "https://user@idcs.example",
                "https://idcs.example?user=x", "https://idcs.example/#fragment"}) {
            assertThrows(IllegalArgumentException.class,
                         () -> IdcsTenantAdapter.builder().domainUri(URI.create(uri)).build());
        }
        IdcsTenantAdapter normalized = IdcsTenantAdapter.builder()
                .domainUri(URI.create("https://IDCS-ONE.IDENTITY.ORACLECLOUD.COM:443/"))
                .build();
        assertThat(normalized.principalIdentityNamespace().orElseThrow(), is(DOMAIN.toString()));
    }

    @Test
    void explicitJwkSetSourceCannotPointAtAnotherDomain() {
        IdcsTenantAdapter adapter = IdcsTenantAdapter.builder().domainUri(DOMAIN).build();
        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                                                        () -> OidcTenantConfig.builder()
                                                                .adapter(adapter)
                                                                .endpoints(endpoints -> endpoints.jwksUri(
                                                                        URI.create("https://other.example/jwks")))
                                                                .buildPrototype());
        assertThat(failure.getMessage(), containsString("primary or secure domain origin"));
    }
}
