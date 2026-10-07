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
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

import io.helidon.common.configurable.Resource;
import io.helidon.http.SetCookie;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkKeys;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
                .createAuthenticationRequestCookies(state, false, Map.of()).getFirst();

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
    void authenticationRequestCookieRequiresRequestedScope() throws GeneralSecurityException {
        OidcTenantConfig tenant = tenant(CLIENT_ID, PASSWORD);
        OidcCookieStateHandler handler = OidcCookieStateHandler.create(TENANT_ID, tenant);
        OidcAuthenticationRequestState state = state();
        String[] parts = handler.createAuthenticationRequestCookies(state, false, Map.of()).getFirst().value().split("\\.");
        OidcCookieKeys.KeyMaterial key = OidcCookieKeys.create(TENANT_ID, tenant).orElseThrow()
                .keyMaterial(OidcCookieKeys.Purpose.AUTHENTICATION_REQUEST);
        byte[] iv = Base64.getUrlDecoder().decode(parts[3]);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key.key(), new GCMParameterSpec(128, iv));
        cipher.updateAAD(key.additionalAuthenticatedData());
        cipher.updateAAD((String.join(".", parts[0], parts[1], parts[2], parts[3]) + ".").getBytes(StandardCharsets.US_ASCII));
        JsonObject json = JsonParser.create(new String(cipher.doFinal(Base64.getUrlDecoder().decode(parts[5])),
                                                      StandardCharsets.UTF_8)).readJsonObject();
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        SecureRandom random = new SecureRandom();

        for (boolean scopePresent : List.of(false, true)) {
            JsonObject.Builder payload = JsonObject.builder().from(json).unset("requested_scope");
            if (scopePresent) {
                payload.set("requested_scope", "openid profile");
            }
            random.nextBytes(iv);
            cipher.init(Cipher.ENCRYPT_MODE, key.key(), new GCMParameterSpec(128, iv));
            cipher.updateAAD(key.additionalAuthenticatedData());
            String framing = "v2.n.1." + encoder.encodeToString(iv) + ".";
            cipher.updateAAD(framing.getBytes(StandardCharsets.US_ASCII));
            String cookie = framing + "0."
                    + encoder.encodeToString(cipher.doFinal(payload.build().toString().getBytes(StandardCharsets.UTF_8)));
            assertThat("requested_scope present=" + scopePresent, handler.decodeAuthenticationRequestState(cookie),
                       is(scopePresent ? Optional.of(state) : Optional.empty()));
        }
    }

    @Test
    void customStateCookieRoutingHintIsUntrustedAndOmittedNonceRoundTrips() {
        OidcTenantConfig tenant = tenant(CLIENT_ID, PASSWORD);
        OidcAuthenticationRequestState withNoNonce = new OidcAuthenticationRequestState(
                TENANT_ID, "custom-state", null, "pkce-verifier", null, "https://issuer.example",
                URI.create("https://rp.example/original"), URI.create("https://rp.example/oidc/callback"),
                List.of("openid"), NOW.minusSeconds(1), NOW.plusSeconds(60));
        SetCookie cookie = OidcCookieStateHandler.create(TENANT_ID, tenant)
                .createAuthenticationRequestCookies(withNoNonce, true, Map.of()).getFirst();
        assertThat(OidcCookieStateHandler.authenticationRequestTenantHint(cookie.value()), is(Optional.of(TENANT_ID)));
        assertThat(OidcCookieStateHandler.create(TENANT_ID, tenant)
                           .readAuthenticationRequestState(cookie.value(), NOW).orElseThrow(),
                   is(withNoNonce));

        String forgedHint = cookie.value().replaceFirst("^r1\\.[^.]+\\.", "r1.dGVuYW50LWI.");
        assertThat(OidcCookieStateHandler.authenticationRequestTenantHint(forgedHint),
                   is(Optional.of("tenant-b")));
        assertThat(OidcCookieStateHandler.create(TENANT_ID, tenant)
                           .readAuthenticationRequestState(forgedHint, NOW).isEmpty(),
                   is(true));
    }

    @Test
    void authenticationRequestCookieHonorsExactByteBudgetForStandardAndCustomState() {
        OidcAuthenticationRequestState state = state();
        OidcTenantConfig base = tenant(CLIENT_ID, PASSWORD);
        for (boolean customState : List.of(false, true)) {
            int size = OidcCookieStateHandler.create(TENANT_ID, base)
                    .createAuthenticationRequestCookies(state, customState, Map.of()).getFirst().toString()
                    .getBytes(StandardCharsets.US_ASCII).length;
            OidcTenantConfig exact = OidcTenantConfig.builder(base)
                    .cookies(OidcCookieConfig.builder(base.cookies()).maxCookieSize(size).buildPrototype()).buildPrototype();
            SetCookie accepted = OidcCookieStateHandler.create(TENANT_ID, exact)
                    .createAuthenticationRequestCookies(state, customState, Map.of()).getFirst();
            assertThat(accepted.toString().getBytes(StandardCharsets.US_ASCII).length, is(size));
            assertThat(OidcCookieStateHandler.create(TENANT_ID, exact)
                               .readAuthenticationRequestState(accepted.value(), NOW),
                       is(Optional.of(state)));

            OidcTenantConfig tooSmall = OidcTenantConfig.builder(base)
                    .cookies(OidcCookieConfig.builder(base.cookies()).maxCookieSize(size - 1).maxChunks(1).buildPrototype())
                    .buildPrototype();
            assertThrows(IllegalStateException.class, () -> OidcCookieStateHandler.create(TENANT_ID, tooSmall)
                    .createAuthenticationRequestCookies(state, customState, Map.of()).getFirst());
        }
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
                .createAuthenticationRequestCookies(state(), false, Map.of()).getFirst();

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
                                                  List.of("openid", "profile"),
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
