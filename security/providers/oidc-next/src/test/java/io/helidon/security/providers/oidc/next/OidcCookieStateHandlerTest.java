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
import java.util.List;
import java.util.Map;

import io.helidon.common.configurable.Resource;
import io.helidon.http.SetCookie;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkKeys;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.lessThanOrEqualTo;

class OidcCookieStateHandlerTest {
    private static final String TENANT_ID = "tenant-a";
    private static final String CLIENT_ID = "client-a";
    private static final String PASSWORD = "a-test-password-long-enough";
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    @Test
    void largeSessionFitsBrowserCookies() {
        OidcTenantConfig tenant = tenant(CLIENT_ID, PASSWORD);
        OidcCookieStateHandler handler = OidcCookieStateHandler.create(TENANT_ID, tenant);
        JwkKeys keys = JwkKeys.builder().resource(Resource.create("oidc-next-sign-jwk.json")).build();
        SignedJwt signed = SignedJwt.sign(Jwt.builder()
                                                 .subject("subject")
                                                 .issuer("https://issuer.example")
                                                 .addAudience(CLIENT_ID)
                                                 .algorithm("RS256")
                                                 .expirationTime(NOW.plusSeconds(3600))
                                                 .build(),
                                         keys.forKeyId("sign-rsa").orElseThrow());
        OidcLocalAuthenticationResult session = OidcLocalAuthenticationResult.fromStoredValues(
                OidcLocalAuthenticationState.builder()
                        .tenantId(TENANT_ID)
                        .idToken(new OidcValidatedIdToken(signed.tokenContent(), false, signed, signed.getJwt()))
                        .accessToken("a".repeat(5000))
                        .tokenType("Bearer")
                        .createdAt(NOW)
                        .expiresAt(NOW.plusSeconds(3600))
                        .buildPrototype());

        List<SetCookie> cookies = handler.createLocalAuthenticationResultCookies(session, Map.of(), NOW);

        assertThat(cookies.size() > 1, is(true));
        cookies.forEach(cookie -> assertThat(cookie.toString().length(), lessThanOrEqualTo(3800)));
    }

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
    void hkdfSeparatesEveryCookiePurpose() {
        OidcCookieKeys keys = OidcCookieKeys.create(TENANT_ID, tenant(CLIENT_ID, PASSWORD)).orElseThrow();
        OidcCookieKeys.KeyMaterial authenticationRequest =
                keys.keyMaterial(OidcCookieKeys.Purpose.AUTHENTICATION_REQUEST);
        OidcCookieKeys.KeyMaterial localAuthentication =
                keys.keyMaterial(OidcCookieKeys.Purpose.LOCAL_AUTHENTICATION);
        OidcCookieKeys.KeyMaterial browserSessionGeneration =
                keys.keyMaterial(OidcCookieKeys.Purpose.BROWSER_SESSION_GENERATION);

        assertThat(Arrays.equals(authenticationRequest.key().getEncoded(), localAuthentication.key().getEncoded()),
                   is(false));
        assertThat(Arrays.equals(authenticationRequest.key().getEncoded(), browserSessionGeneration.key().getEncoded()),
                   is(false));
        assertThat(Arrays.equals(localAuthentication.key().getEncoded(), browserSessionGeneration.key().getEncoded()),
                   is(false));
        assertThat(Arrays.equals(authenticationRequest.additionalAuthenticatedData(),
                                 localAuthentication.additionalAuthenticatedData()),
                   is(false));
        assertThat(Arrays.equals(authenticationRequest.additionalAuthenticatedData(),
                                 browserSessionGeneration.additionalAuthenticatedData()),
                   is(false));
        assertThat(Arrays.equals(localAuthentication.additionalAuthenticatedData(),
                                 browserSessionGeneration.additionalAuthenticatedData()),
                   is(false));
    }

    @Test
    void browserSessionGenerationCookieIsProtectedScopedAndReplicaReadable() {
        OidcTenantConfig tenant = tenant(CLIENT_ID, PASSWORD);
        OidcCookieStateHandler handler = OidcCookieStateHandler.create(TENANT_ID, tenant);
        OidcCookieStateHandler.BrowserSessionGeneration generation = handler.createBrowserSessionGeneration();
        SetCookie cookie = generation.cookie();

        assertThat(cookie.name(), is("__Host-helidon-oidc-auth-generation"));
        assertThat(cookie.value().contains(generation.value()), is(false));
        assertThat(cookie.path().orElse(""), is("/"));
        assertThat(cookie.httpOnly(), is(true));
        assertThat(cookie.secure(), is(true));
        assertThat(cookie.sameSite().orElseThrow(), is(SetCookie.SameSite.LAX));
        assertThat(cookie.maxAge().orElseThrow(),
                   is(tenant.cookies().authenticationRequestLifetime().plus(tenant.cookies().localAuthenticationLifetime())));
        assertThat(OidcCookieStateHandler.create(TENANT_ID, tenant)
                           .readBrowserSessionGeneration(cookie.value())
                           .orElseThrow(),
                   is(generation.value()));
        assertThat(OidcCookieStateHandler.create("tenant-b", tenant)
                           .readBrowserSessionGeneration(cookie.value())
                           .isEmpty(),
                   is(true));
        assertThat(handler.readBrowserSessionGeneration(tamper(cookie.value())).isEmpty(), is(true));
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
                                                  null,
                                                  "https://issuer.example",
                                                  URI.create("https://rp.example/original"),
                                                  URI.create("https://rp.example/oidc/callback"),
                                                  NOW.minusSeconds(1),
                                                  NOW.plusSeconds(60));
    }

    private static String tamper(String value) {
        int ciphertextStart = value.indexOf('.', value.indexOf('.') + 1) + 1;
        char firstCiphertextChar = value.charAt(ciphertextStart);
        return value.substring(0, ciphertextStart)
                + (firstCiphertextChar == 'A' ? 'B' : 'A')
                + value.substring(ciphertextStart + 1);
    }
}
