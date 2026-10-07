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
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

import io.helidon.common.configurable.Resource;
import io.helidon.http.SetCookie;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkKeys;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OidcStateCookiesTest {
    private static final String TENANT = "tenant";
    private static final Instant NOW = Instant.parse("2026-10-07T10:00:00Z");

    @Test
    void standardAndCustomStateRoundTripInBoundedPieces() {
        OidcTenantConfig tenant = tenant(_ -> { });
        OidcCookieStateHandler handler = OidcCookieStateHandler.create(TENANT, tenant);
        OidcAuthenticationRequestState state = state(3000);
        for (boolean custom : List.of(false, true)) {
            List<SetCookie> cookies = handler.createAuthenticationRequestCookies(state, custom, Map.of());
            assertThat(cookies, hasSize(greaterThan(1)));
            cookies.forEach(cookie -> {
                assertThat(cookie.toString().length(), lessThanOrEqualTo(tenant.cookies().maxCookieSize()));
                assertThat(cookie.maxAge(), is(Optional.of(tenant.cookies().authenticationRequestLifetime())));
                assertThat(cookie.secure(), is(true));
                assertThat(cookie.httpOnly(), is(true));
                assertThat(cookie.sameSite(), is(Optional.of(SetCookie.SameSite.LAX)));
            });
            assertThat(handler.decodeAuthenticationRequestState(cookieMap(cookies)), is(Optional.of(state)));
            assertThat(OidcCookieStateHandler.authenticationRequestTenantHint(cookies.getFirst().value()),
                       is(custom ? Optional.of(TENANT) : Optional.empty()));
        }
    }

    @Test
    void reorderedMissingDuplicateMixedAndTamperedPiecesAreHandled() {
        OidcCookieStateHandler handler = OidcCookieStateHandler.create(TENANT, tenant(_ -> { }));
        OidcAuthenticationRequestState state = state(3000);
        List<SetCookie> first = handler.createAuthenticationRequestCookies(state, false, Map.of());
        List<SetCookie> second = handler.createAuthenticationRequestCookies(state, false, Map.of());
        Map<String, List<String>> reverse = new LinkedHashMap<>();
        first.reversed().forEach(cookie -> reverse.put(cookie.name(), List.of(cookie.value())));
        assertThat(handler.decodeAuthenticationRequestState(reverse), is(Optional.of(state)));
        for (SetCookie cookie : first) {
            Map<String, List<String>> missing = new HashMap<>(cookieMap(first));
            missing.remove(cookie.name());
            assertThat(handler.decodeAuthenticationRequestState(missing), is(Optional.empty()));
            Map<String, List<String>> duplicate = new HashMap<>(cookieMap(first));
            duplicate.put(cookie.name(), List.of(cookie.value(), cookie.value()));
            assertThat(handler.decodeAuthenticationRequestState(duplicate), is(Optional.empty()));
            Map<String, List<String>> mixed = new HashMap<>(cookieMap(first));
            mixed.put(cookie.name(), List.of(second.stream().filter(c -> c.name().equals(cookie.name())).findFirst()
                    .orElseThrow().value()));
            assertThat(handler.decodeAuthenticationRequestState(mixed), is(Optional.empty()));
            Map<String, List<String>> tampered = new HashMap<>(cookieMap(first));
            String value = cookie.value();
            int offset = value.length() - value.split("\\.", 6)[5].length();
            String changed = value.substring(0, offset) + (value.charAt(offset) == 'A' ? 'B' : 'A')
                    + value.substring(offset + 1);
            tampered.put(cookie.name(), List.of(changed));
            assertThat(handler.decodeAuthenticationRequestState(tampered), is(Optional.empty()));
        }
    }

    @Test
    void tenantHintAndChunkCountCannotBeChanged() {
        OidcCookieStateHandler handler = OidcCookieStateHandler.create(TENANT, tenant(_ -> { }));
        List<SetCookie> cookies = handler.createAuthenticationRequestCookies(state(3000), true, Map.of());
        Map<String, List<String>> forged = new HashMap<>();
        cookieMap(cookies).forEach((name, values) ->
                forged.put(name, List.of(values.getFirst().replaceFirst("^r1\\.[^.]+\\.", "r1.b3RoZXI."))));
        assertThat(handler.decodeAuthenticationRequestState(forged), is(Optional.empty()));
        String first = cookies.getFirst().value();
        int payload = first.lastIndexOf('.') + 1;
        StringBuilder ciphertext = new StringBuilder(first.substring(payload));
        cookies.stream().skip(1)
                .forEach(cookie -> ciphertext.append(cookie.value().substring(cookie.value().lastIndexOf('.') + 1)));
        String framing = first.substring(0, payload).replace(".n." + cookies.size() + ".", ".n.1.");
        assertThat(handler.decodeAuthenticationRequestState(Map.of(cookies.getFirst().name(),
                       List.of(framing + ciphertext))), is(Optional.empty()));
    }

    @Test
    void replacingLargeStateRetiresOldPiecesAndCleanupFindsOrphans() {
        OidcCookieStateHandler handler = OidcCookieStateHandler.create(TENANT, tenant(_ -> { }));
        Map<String, List<String>> original = cookieMap(handler.createAuthenticationRequestCookies(state(3000), false, Map.of()));
        List<SetCookie> replacement = handler.createAuthenticationRequestCookies(state(20), false, original);
        Map<String, List<String>> after = new HashMap<>(original);
        replacement.forEach(cookie -> {
            if (cookie.value().isEmpty()) {
                after.remove(cookie.name());
                assertThat(cookie.expires().orElseThrow().toInstant(), is(Instant.EPOCH));
            } else {
                after.put(cookie.name(), List.of(cookie.value()));
            }
        });
        assertThat(after, is(cookieMap(replacement.stream().filter(cookie -> !cookie.value().isEmpty()).toList())));
        assertThat(handler.decodeAuthenticationRequestState(after), is(Optional.of(state(20))));
        String base = tenant(_ -> { }).cookies().authenticationRequestCookieName();
        List<SetCookie> removed = handler.removeAuthenticationRequestCookies(Map.of(base + ".15", List.of("orphan"),
                                                                                  "unrelated", List.of("leave")));
        assertThat(removed.stream().map(SetCookie::name).toList(), is(List.of(base, base + ".15")));
        removed.forEach(cookie -> assertThat(cookie.value(), is("")));
    }

    @Test
    void chunkCountAndPayloadBoundsAreEnforced() {
        OidcTenantConfig one = tenant(cookies -> cookies.maxChunks(1));
        assertThrows(OidcCookieStateHandler.AuthenticationRequestCookieException.class,
                     () -> OidcCookieStateHandler.create(TENANT, one)
                             .createAuthenticationRequestCookies(state(3000), false, Map.of()));
        OidcTenantConfig small = tenant(cookies -> cookies.maxSessionSize(1024));
        assertThrows(OidcCookieStateHandler.AuthenticationRequestCookieException.class,
                     () -> OidcCookieStateHandler.create(TENANT, small)
                             .createAuthenticationRequestCookies(state(3000), false, Map.of()));
    }

    @Test
    void stateAndSessionShareTheAggregateHeaderBudgetAndSeparateKeys() {
        OidcTenantConfig tenant = tenant(_ -> { });
        OidcCookieStateHandler handler = OidcCookieStateHandler.create(TENANT, tenant);
        Map<String, List<String>> stateCookies = cookieMap(
                handler.createAuthenticationRequestCookies(state(5000), false, Map.of()));
        OidcLocalAuthenticationResult session = session(5000);
        assertThrows(OidcCookieStateHandler.SessionCookieException.class,
                     () -> handler.createLocalAuthenticationResultCookies(session, stateCookies, NOW));
        Map<String, List<String>> smallState = cookieMap(
                handler.createAuthenticationRequestCookies(state(3000), false, Map.of()));
        List<SetCookie> sessionCookies = handler.createLocalAuthenticationResultCookies(session(1000), smallState, NOW);
        Map<String, List<String>> combined = new HashMap<>(smallState);
        combined.putAll(cookieMap(sessionCookies));
        assertThat(handler.decodeAuthenticationRequestState(combined), is(Optional.of(state(3000))));
        assertThat(handler.readLocalAuthenticationResult(combined, NOW, OidcIdTokenDecryptor.create(tenant))
                           .orElseThrow().accessToken(), is("a".repeat(1000)));
        Map<String, List<String>> wrongPurpose = new HashMap<>();
        String stateName = tenant.cookies().authenticationRequestCookieName();
        for (int index = 0; index < sessionCookies.size(); index++) {
            wrongPurpose.put(stateName + (index == 0 ? "" : "." + index), List.of(sessionCookies.get(index).value()));
        }
        assertThat(handler.decodeAuthenticationRequestState(wrongPurpose), is(Optional.empty()));
    }

    @Test
    void stateChunkNamespacesCannotOverlapSessionsOrOtherTenants() {
        assertThrows(IllegalArgumentException.class, () -> tenant(cookies ->
                cookies.authenticationRequestCookieName("state").localAuthenticationCookieName("state.1")));
        OidcTenantConfig first = tenant(cookies -> cookies.authenticationRequestCookieName("state")
                .localAuthenticationCookieName("auth"));
        OidcTenantConfig second = tenant(cookies -> cookies.authenticationRequestCookieName("state.1")
                .localAuthenticationCookieName("other"));
        assertThrows(IllegalArgumentException.class, () -> OidcProviderConfig.builder().putTenant("first", first)
                .putTenant("second", second).buildPrototype());
    }

    private static OidcTenantConfig tenant(Consumer<OidcCookieConfig.Builder> customizer) {
        return OidcTenantConfig.builder().clientId("client").cookies(cookies -> {
            cookies.protection(protection -> protection.password("chunk-state-password"));
            customizer.accept(cookies);
        }).buildPrototype();
    }

    private static OidcAuthenticationRequestState state(int length) {
        return new OidcAuthenticationRequestState(TENANT, "state", "nonce", "verifier", null, "https://issuer.example",
                URI.create("/resource?q=" + "a".repeat(length)), URI.create("https://rp.example/callback"),
                List.of("openid"), NOW, NOW.plusSeconds(300));
    }

    private static Map<String, List<String>> cookieMap(List<SetCookie> cookies) {
        Map<String, List<String>> result = new LinkedHashMap<>();
        cookies.forEach(cookie -> result.put(cookie.name(), List.of(cookie.value())));
        return result;
    }

    private static OidcLocalAuthenticationResult session(int size) {
        JwkKeys keys = JwkKeys.builder().resource(Resource.create("oidc-next-sign-jwk.json")).build();
        SignedJwt token = SignedJwt.sign(Jwt.builder().algorithm("RS256").keyId("verify-rsa").issuer("https://issuer.example")
                .subject("alice").addAudience("client").issueTime(NOW).expirationTime(NOW.plusSeconds(3600)).build(),
                                          keys.forKeyId("sign-rsa").orElseThrow());
        return OidcLocalAuthenticationResult.fromStoredValues(OidcLocalAuthenticationState.builder().tenantId(TENANT)
                .idToken(new OidcValidatedIdToken(token.tokenContent(), false, token, token.getJwt()))
                .accessToken("a".repeat(size)).tokenType("Bearer").createdAt(NOW).expiresAt(NOW.plusSeconds(3600))
                .buildPrototype());
    }
}
