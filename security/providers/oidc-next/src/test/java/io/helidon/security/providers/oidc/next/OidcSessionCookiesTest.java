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

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Stream;
import java.util.zip.GZIPOutputStream;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

import io.helidon.common.configurable.Resource;
import io.helidon.config.Config;
import io.helidon.config.ConfigSources;
import io.helidon.http.SetCookie;
import io.helidon.json.JsonObject;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkKeys;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

class OidcSessionCookiesTest {
    private static final Instant NOW = Instant.parse("2026-09-18T08:00:00Z");
    private static final String TENANT = "test";
    private static final String CLIENT = "client";
    private static final String PASSWORD = "a-cookie-password-for-tests";
    private static final String NAME = "__Host-helidon-oidc-auth";
    private static OidcValidatedIdToken idToken;

    @BeforeAll
    static void init() {
        JwkKeys keys = JwkKeys.builder().resource(Resource.create("oidc-next-sign-jwk.json")).build();
        SignedJwt signed = SignedJwt.sign(Jwt.builder()
                                                 .issuer("https://issuer.example").subject("user")
                                                 .addAudience(CLIENT).algorithm("RS256")
                                                 .expirationTime(NOW.plusSeconds(3600)).build(),
                                         keys.forKeyId("sign-rsa").orElseThrow());
        idToken = new OidcValidatedIdToken(signed.tokenContent(), false, signed, signed.getJwt());
    }

    @Test
    void largeSessionRoundTripsAsOneAuthenticatedCookieSet() {
        OidcTenantConfig tenant = tenant(_ -> { });
        OidcCookieStateHandler handler = OidcCookieStateHandler.create(TENANT, tenant);
        OidcLocalAuthenticationResult original = session(6000);
        OidcCookieStateHandler.PreparedCookies prepared = handler.prepareLocalAuthenticationResult(original, Map.of());
        List<SetCookie> cookies = handler.localAuthenticationResultCookies(prepared, NOW);

        assertThat(cookies.size() > 1, is(true));
        assertThat(cookies.size(), lessThanOrEqualTo(4));
        for (SetCookie cookie : cookies) {
            assertThat(cookie.toString().getBytes(StandardCharsets.US_ASCII).length, lessThanOrEqualTo(3800));
            assertThat(cookie.path().orElseThrow(), is("/"));
            assertThat(cookie.domain().isEmpty(), is(true));
            assertThat(cookie.httpOnly(), is(true));
            assertThat(cookie.secure(), is(true));
            assertThat(cookie.sameSite().orElseThrow(), is(SetCookie.SameSite.LAX));
            assertThat(cookie.expires().orElseThrow().toInstant(), is(original.expiresAt()));
        }
        assertThat(cookies.stream().mapToInt(it -> it.name().length() + 1 + it.value().length()).sum()
                           + 2 * (cookies.size() - 1), lessThanOrEqualTo(12288));
        OidcLocalAuthenticationResult decoded = handler.readLocalAuthenticationResult(cookieMap(cookies), NOW,
                                                                                      OidcIdTokenDecryptor.create(tenant))
                .orElseThrow();
        assertThat(decoded.accessToken(), is(original.accessToken()));
        assertThat(decoded.refreshToken(), is(original.refreshToken()));
        assertThat(decoded.idToken().rawToken(), is(original.idToken().rawToken()));
    }

    @Test
    void everyRequiredPartMustBePresentAndCookieOrderingDoesNotMatter() {
        OidcTenantConfig tenant = tenant(_ -> { });
        OidcCookieStateHandler handler = OidcCookieStateHandler.create(TENANT, tenant);
        List<SetCookie> cookies = handler.localAuthenticationResultCookies(handler.prepareLocalAuthenticationResult(session(6000), Map.of()), NOW);
        Map<String, List<String>> input = cookieMap(cookies);
        for (SetCookie cookie : cookies) {
            Map<String, List<String>> missing = new HashMap<>(input);
            missing.remove(cookie.name());
            assertThat(cookie.name(), read(handler, tenant, missing), is(false));
        }
        Map<String, List<String>> reordered = new LinkedHashMap<>();
        cookies.reversed().forEach(cookie -> reordered.put(cookie.name(), List.of(cookie.value())));
        assertThat(read(handler, tenant, reordered), is(true));
        input.put(NAME, List.of(cookies.getFirst().value(), cookies.getFirst().value()));
        assertThat(read(handler, tenant, input), is(false));
    }

    @Test
    void rejectsMixedEnvelopesAndTamperedCiphertext() {
        OidcTenantConfig tenant = tenant(_ -> { });
        OidcCookieStateHandler handler = OidcCookieStateHandler.create(TENANT, tenant);
        OidcCookieStateHandler.PreparedCookies first = handler.prepareLocalAuthenticationResult(session(6000), Map.of());
        OidcCookieStateHandler.PreparedCookies second = handler.prepareLocalAuthenticationResult(session(6000), Map.of());
        Map<String, List<String>> cookies = cookieMap(handler.localAuthenticationResultCookies(first, NOW));
        cookies.put(NAME + ".1", List.of(second.values().get(1)));
        assertThat(read(handler, tenant, cookies), is(false));

        cookies = cookieMap(handler.localAuthenticationResultCookies(first, NOW));
        String part = first.values().get(1);
        int data = part.lastIndexOf('.') + 1;
        cookies.put(NAME + ".1", List.of(part.substring(0, data) + (part.charAt(data) == 'A' ? 'B' : 'A')
                                              + part.substring(data + 1)));
        assertThat(read(handler, tenant, cookies), is(false));
    }

    @Test
    void gzipIsOptionalBoundedAndReadableWhenWritingCompressionIsDisabled() {
        OidcTenantConfig compressed = tenant(it -> it.compression(OidcCookieCompression.GZIP));
        OidcCookieStateHandler writer = OidcCookieStateHandler.create(TENANT, compressed);
        List<SetCookie> cookies = writer.localAuthenticationResultCookies(writer.prepareLocalAuthenticationResult(session(20000), Map.of()), NOW);
        assertThat(cookies.size(), is(1));
        assertThat(cookies.getFirst().value().startsWith("v2.g."), is(true));
        OidcTenantConfig uncompressed = tenant(_ -> { });
        assertThat(read(OidcCookieStateHandler.create(TENANT, uncompressed), uncompressed, cookieMap(cookies)), is(true));
        OidcTenantConfig bounded = tenant(it -> it.maxSessionSize(2000));
        assertThat(read(OidcCookieStateHandler.create(TENANT, bounded), bounded, cookieMap(cookies)), is(false));
        assertThrows(OidcCookieStateHandler.SessionCookieException.class,
                     () -> OidcCookieStateHandler.create(TENANT, bounded).prepareLocalAuthenticationResult(session(20000), Map.of()));
    }

    @Test
    void authenticatedMalformedGzipAndInvalidUtf8AreRejected() throws Exception {
        OidcTenantConfig tenant = tenant(_ -> { });
        OidcCookieStateHandler handler = OidcCookieStateHandler.create(TENANT, tenant);
        String json = JsonObject.builder().set("tenant_id", TENANT).set("id_token", idToken.rawToken())
                .set("access_token", "token-marker").set("token_type", "Bearer")
                .set("created_at", NOW.toString()).set("expires_at", NOW.plusSeconds(3600).toString()).build().toString();
        byte[] valid = json.getBytes(StandardCharsets.UTF_8);
        assertThat(read(handler, tenant, authenticatedPayload(tenant, "n", valid)), is(true));
        assertThat(read(handler, tenant, authenticatedPayload(tenant, "g", valid)), is(false));
        byte[] invalidUtf8 = valid.clone();
        invalidUtf8[json.indexOf("token-marker")] = (byte) 0xff;
        assertThat(read(handler, tenant, authenticatedPayload(tenant, "n", invalidUtf8)), is(false));

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(output)) {
            gzip.write(valid);
        }
        byte[] compressed = output.toByteArray();
        assertThat(read(handler, tenant, authenticatedPayload(tenant, "g", compressed)), is(true));
        compressed[compressed.length - 8] ^= 1;
        assertThat(read(handler, tenant, authenticatedPayload(tenant, "g", compressed)), is(false));
    }

    @Test
    void authenticatedSessionCannotBeMovedAcrossTenantOrClient() {
        OidcTenantConfig tenant = tenant(_ -> { });
        OidcCookieStateHandler original = OidcCookieStateHandler.create(TENANT, tenant);
        Map<String, List<String>> cookies = cookieMap(original.createLocalAuthenticationResultCookies(session(6000), Map.of(), NOW));
        assertThat(read(OidcCookieStateHandler.create("other", tenant), tenant, cookies), is(false));
        OidcTenantConfig otherClient = OidcTenantConfig.builder(tenant).clientId("other-client").buildPrototype();
        assertThat(read(OidcCookieStateHandler.create(TENANT, otherClient), otherClient, cookies), is(false));
    }

    @Test
    void capacityAndDecodedSizeFailuresAreControlled() {
        OidcCookieStateHandler one = OidcCookieStateHandler.create(TENANT, tenant(it -> it.maxChunks(1)));
        OidcCookieStateHandler total = OidcCookieStateHandler.create(TENANT, tenant(it -> it.maxTotalSize(4000)));
        assertThrows(OidcCookieStateHandler.SessionCookieException.class,
                     () -> one.prepareLocalAuthenticationResult(session(6000), Map.of()));
        assertThrows(OidcCookieStateHandler.SessionCookieException.class,
                     () -> total.prepareLocalAuthenticationResult(session(6000), Map.of()));
        OidcCookieStateHandler utf8 = OidcCookieStateHandler.create(TENANT, tenant(it -> it.maxSessionSize(5000)));
        OidcLocalAuthenticationState state = baseState(1)
                .userInfo(JsonObject.builder().set("display", "\u20ac".repeat(1800)).build()).buildPrototype();
        assertThrows(OidcCookieStateHandler.SessionCookieException.class,
                     () -> utf8.prepareLocalAuthenticationResult(OidcLocalAuthenticationResult.fromStoredValues(state), Map.of()));
    }

    @Test
    void shrinkingAndLogoutClearBoundedExactNames() {
        OidcCookieStateHandler handler = OidcCookieStateHandler.create(TENANT, tenant(_ -> { }));
        Map<String, List<String>> original = cookieMap(
                handler.localAuthenticationResultCookies(handler.prepareLocalAuthenticationResult(session(6000), Map.of()), NOW));
        original.put(NAME + ".1000000", List.of("not-our-cookie"));
        original.put("application", List.of("keep"));
        OidcCookieStateHandler.PreparedCookies small = handler.prepareLocalAuthenticationResult(session(1), original);
        List<SetCookie> update = handler.localAuthenticationResultCookies(small, NOW);

        assertThat(small.values().size(), is(1));
        assertThat(update.size(), is(original.size() - 2));
        assertThat(update.getFirst().value().isEmpty(), is(false));
        for (SetCookie removed : update.subList(1, update.size())) {
            assertThat(removed.value(), is(""));
            assertThat(removed.expires().orElseThrow().toInstant(), is(Instant.EPOCH));
            assertThat(removed.name().equals(NAME + ".1000000"), is(false));
            assertThat(removed.name().endsWith("-generation"), is(false));
        }
        OidcCookieStateHandler lowered = OidcCookieStateHandler.create(TENANT, tenant(it -> it.maxChunks(1)));
        List<SetCookie> removed = lowered.removeLocalAuthenticationResultCookies();
        assertThat(removed.size(), is(16));
        assertThat(removed.stream().map(SetCookie::name).distinct().count(), is(16L));
        assertThat(removed.getLast().name(), is(NAME + ".15"));
        assertThat(read(lowered, tenant(it -> it.maxChunks(1)), original), is(false));
    }

    @TestFactory
    Stream<DynamicTest> configurableCookieSizesIncludingTwoDigitIndexesRoundTrip() {
        return Stream.of(512, 1024, 2048, 3800, 4096).map(limit -> dynamicTest("cookie-bytes=" + limit, () -> {
            OidcTenantConfig tenant = tenant(it -> it.maxCookieSize(limit).maxChunks(16));
            OidcCookieStateHandler handler = OidcCookieStateHandler.create(TENANT, tenant);
            List<SetCookie> cookies = handler.createLocalAuthenticationResultCookies(session(2500), Map.of(), NOW);
            if (limit == 512) {
                assertThat(cookies.size() >= 10, is(true));
            }
            cookies.forEach(cookie -> assertThat(cookie.toString().length(), lessThanOrEqualTo(limit)));
            assertThat(read(handler, tenant, cookieMap(cookies)), is(true));
        }));
    }

    @Test
    void exactIncomingHeaderBudgetIsInclusive() {
        OidcTenantConfig tenant = tenant(_ -> { });
        OidcCookieStateHandler handler = OidcCookieStateHandler.create(TENANT, tenant);
        List<SetCookie> cookies = handler.createLocalAuthenticationResultCookies(session(3000), Map.of(), NOW);
        int bytes = cookies.stream().mapToInt(cookie -> cookie.name().length() + 1 + cookie.value().length()).sum()
                + 2 * (cookies.size() - 1);
        OidcTenantConfig exact = tenant(it -> it.maxTotalSize(bytes));
        OidcTenantConfig shortBudget = tenant(it -> it.maxTotalSize(bytes - 1));
        assertThat(read(OidcCookieStateHandler.create(TENANT, exact), exact, cookieMap(cookies)), is(true));
        assertThat(read(OidcCookieStateHandler.create(TENANT, shortBudget), shortBudget, cookieMap(cookies)), is(false));
    }

    @TestFactory
    Stream<DynamicTest> malformedFramingCannotControlAllocationOrCleanup() {
        OidcTenantConfig tenant = tenant(_ -> { });
        OidcCookieStateHandler handler = OidcCookieStateHandler.create(TENANT, tenant);
        String value = handler.prepareLocalAuthenticationResult(session(1), Map.of()).values().getFirst();
        return Stream.of(value.replace(".1.", ".1000000000."),
                         value.replace(".1.", ".01."),
                         value.replace("v2.n.", "v2.x."),
                         value.replace(".0.", ".1."),
                         value + "=", "v2.n.1.", "")
                .map(malformed -> dynamicTest("malformed-" + malformed.length(), () -> {
                    assertThat(read(handler, tenant, Map.of(NAME, List.of(malformed))), is(false));
                    assertThat(handler.removeLocalAuthenticationResultCookies().size(), is(16));
                }));
    }

    @Test
    void cookieOptionsHaveFlatRootAndNamedTenantParity() {
        Map<String, String> values = Map.of("max-cookie-size", "3000", "max-chunks", "3", "max-total-size", "9000",
                                            "max-session-size", "32000", "compression", "GZIP");
        Map<String, String> rootValues = new HashMap<>();
        Map<String, String> namedValues = new HashMap<>();
        values.forEach((key, value) -> {
            rootValues.put("cookies." + key, value);
            namedValues.put("tenants.test.cookies." + key, value);
        });
        OidcProviderConfig root = OidcProviderConfig.create(Config.create(ConfigSources.create(rootValues)));
        OidcProviderConfig named = OidcProviderConfig.create(Config.create(ConfigSources.create(namedValues)));
        OidcCookieConfig expected = OidcCookieConfig.builder().maxCookieSize(3000).maxChunks(3).maxTotalSize(9000)
                .maxSessionSize(32000).compression(OidcCookieCompression.GZIP).buildPrototype();

        assertThat(root.tenants().get("default").cookies(), is(expected));
        assertThat(named.tenants().get("test").cookies(), is(expected));
    }

    @Test
    void rejectsInvalidLimitsAndNamespaceOverlap() {
        List<Consumer<OidcCookieConfig.Builder>> invalid = new ArrayList<>();
        invalid.add(it -> it.maxChunks(0));
        invalid.add(it -> it.maxChunks(17));
        invalid.add(it -> it.maxCookieSize(4097));
        invalid.add(it -> it.maxCookieSize(20));
        invalid.add(it -> it.maxTotalSize(0));
        invalid.add(it -> it.maxTotalSize(65537));
        invalid.add(it -> it.maxTotalSize(100));
        invalid.add(it -> it.maxSessionSize(0));
        invalid.add(it -> it.maxSessionSize(1048577));
        invalid.add(it -> it.authenticationRequestCookieName(NAME + ".15"));
        invalid.forEach(customizer -> assertThrows(IllegalArgumentException.class, () -> tenant(customizer)));
        OidcTenantConfig first = tenant(it -> it.localAuthenticationCookieName("auth"));
        OidcTenantConfig second = tenant(it -> it.localAuthenticationCookieName("auth.1"));
        assertThrows(IllegalArgumentException.class, () -> OidcProviderConfig.builder()
                .putTenant("a", first).putTenant("b", second).buildPrototype());
        OidcProviderConfig.builder().putTenant("a", first).putTenant("b", first).buildPrototype();
    }

    private static OidcTenantConfig tenant(Consumer<OidcCookieConfig.Builder> customizer) {
        return OidcTenantConfig.builder().clientId(CLIENT).cookies(it -> {
            it.password(PASSWORD);
            customizer.accept(it);
        }).buildPrototype();
    }

    private static OidcLocalAuthenticationResult session(int size) {
        return OidcLocalAuthenticationResult.fromStoredValues(baseState(size).buildPrototype());
    }

    private static OidcLocalAuthenticationState.Builder baseState(int size) {
        return OidcLocalAuthenticationState.builder().tenantId(TENANT).idToken(idToken)
                .accessToken("a".repeat(size)).tokenType("Bearer").refreshToken("refresh-token")
                .createdAt(NOW).expiresAt(NOW.plusSeconds(3600)).accessTokenExpiresAt(NOW.plusSeconds(600));
    }

    private static Map<String, List<String>> cookieMap(List<SetCookie> cookies) {
        Map<String, List<String>> result = new LinkedHashMap<>();
        cookies.forEach(cookie -> result.put(cookie.name(), List.of(cookie.value())));
        return result;
    }

    private static boolean read(OidcCookieStateHandler handler, OidcTenantConfig tenant, Map<String, List<String>> cookies) {
        return handler.readLocalAuthenticationResult(cookies, NOW, OidcIdTokenDecryptor.create(tenant)).isPresent();
    }

    private static Map<String, List<String>> authenticatedPayload(OidcTenantConfig tenant, String mode, byte[] payload)
            throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        String encodedIv = Base64.getUrlEncoder().withoutPadding().encodeToString(iv);
        String framing = "v2." + mode + ".1." + encodedIv + ".";
        OidcCookieKeys.KeyMaterial key = OidcCookieKeys.create(TENANT, tenant).orElseThrow()
                .keyMaterial(OidcCookieKeys.Purpose.LOCAL_AUTHENTICATION);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key.key(), new GCMParameterSpec(128, iv));
        cipher.updateAAD(key.additionalAuthenticatedData());
        cipher.updateAAD(framing.getBytes(StandardCharsets.US_ASCII));
        String value = framing + "0." + Base64.getUrlEncoder().withoutPadding().encodeToString(cipher.doFinal(payload));
        return Map.of(NAME, List.of(value));
    }
}
