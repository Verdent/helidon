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
import java.util.Arrays;

import io.helidon.http.SetCookie;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.MatcherAssert.assertThat;

class OidcCookieStateHandlerTest {
    private static final String TENANT_ID = "tenant-a";
    private static final String CLIENT_ID = "client-a";
    private static final String PASSWORD = "a-test-password-long-enough";
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    @Test
    void independentlyCreatedHandlersInteroperateAndKeysAreContextBound() {
        OidcTenantConfig tenant = tenant(CLIENT_ID, PASSWORD);
        OidcAuthenticationRequestState state = state();
        SetCookie cookie = OidcCookieStateHandler.create(TENANT_ID, tenant)
                .createAuthenticationRequestCookie(state);

        assertThat(OidcCookieStateHandler.create(TENANT_ID, tenant)
                           .readAuthenticationRequestState(cookie.value(), NOW)
                           .orElseThrow(),
                   is(state));
        assertThat(OidcCookieStateHandler.create("tenant-b", tenant)
                           .readAuthenticationRequestState(cookie.value(), NOW)
                           .isEmpty(),
                   is(true));
        assertThat(OidcCookieStateHandler.create(TENANT_ID, tenant("client-b", PASSWORD))
                           .readAuthenticationRequestState(cookie.value(), NOW)
                           .isEmpty(),
                   is(true));
        assertThat(OidcCookieStateHandler.create(TENANT_ID, tenant(CLIENT_ID, "a-different-password-long-enough"))
                           .readAuthenticationRequestState(cookie.value(), NOW)
                           .isEmpty(),
                   is(true));
    }

    @Test
    void hkdfSeparatesAuthenticationRequestAndLocalAuthenticationKeys() {
        OidcCookieKeys keys = OidcCookieKeys.create(TENANT_ID, tenant(CLIENT_ID, PASSWORD)).orElseThrow();
        OidcCookieKeys.KeyMaterial authenticationRequest =
                keys.keyMaterial(OidcCookieKeys.Purpose.AUTHENTICATION_REQUEST);
        OidcCookieKeys.KeyMaterial localAuthentication =
                keys.keyMaterial(OidcCookieKeys.Purpose.LOCAL_AUTHENTICATION);

        assertThat(Arrays.equals(authenticationRequest.key().getEncoded(), localAuthentication.key().getEncoded()),
                   is(false));
        assertThat(Arrays.equals(authenticationRequest.additionalAuthenticatedData(),
                                 localAuthentication.additionalAuthenticatedData()),
                   is(false));
    }

    @Test
    void explicitSaltIsSharedByReplicasAndIsolatesDeployments() {
        OidcTenantConfig tenant = tenant(CLIENT_ID, PASSWORD, "AAAAAAAAAAAAAAAAAAAAAA");
        SetCookie cookie = OidcCookieStateHandler.create(TENANT_ID, tenant)
                .createAuthenticationRequestCookie(state());

        assertThat(OidcCookieStateHandler.create(TENANT_ID, tenant)
                           .readAuthenticationRequestState(cookie.value(), NOW)
                           .isPresent(),
                   is(true));
        assertThat(OidcCookieStateHandler.create(TENANT_ID,
                                                 tenant(CLIENT_ID, PASSWORD, "yD6wIno2KCq2znbRzL3aUQ"))
                           .readAuthenticationRequestState(cookie.value(), NOW)
                           .isEmpty(),
                   is(true));
    }

    @Test
    void tenantRegistrySharesTheLazyCookieHandlerWithTenantContext() {
        OidcTenantConfig tenant = tenant(CLIENT_ID, PASSWORD);
        OidcProviderConfig config = OidcProviderConfig.builder()
                .putTenant(TENANT_ID, tenant)
                .buildPrototype();
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(
                config,
                OidcTenantContextFactory.create((tenantId, tenantConfig) ->
                                                        OidcTenantContext.ready(tenantId, tenantConfig)));
        OidcCookieStateHandler handler = registry.cookieStateHandler(TENANT_ID).orElseThrow();

        assertThat(registry.cookieStateHandler(TENANT_ID).orElseThrow(), sameInstance(handler));
        assertThat(registry.tenantContext(TENANT_ID).orElseThrow().cookieStateHandler(), sameInstance(handler));
    }

    private static OidcTenantConfig tenant(String clientId, String password) {
        return OidcTenantConfig.builder()
                .clientId(clientId)
                .cookies(cookies -> cookies.protection(protection -> protection.password(password)))
                .buildPrototype();
    }

    private static OidcTenantConfig tenant(String clientId, String password, String salt) {
        return OidcTenantConfig.builder()
                .clientId(clientId)
                .cookies(cookies -> cookies.protection(protection -> protection
                        .password(password)
                        .salt(salt)))
                .buildPrototype();
    }

    private static OidcAuthenticationRequestState state() {
        return new OidcAuthenticationRequestState(TENANT_ID,
                                                  "state",
                                                  "nonce",
                                                  "pkce-verifier",
                                                  "https://issuer.example",
                                                  URI.create("https://rp.example/original"),
                                                  URI.create("https://rp.example/oidc/callback"),
                                                  NOW.minusSeconds(1),
                                                  NOW.plusSeconds(60));
    }
}
