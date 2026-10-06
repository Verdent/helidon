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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import io.helidon.common.configurable.Resource;
import io.helidon.common.configurable.ResourceConfig;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.JwtHeaders;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkKeys;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OidcJweCriticalHeadersTest {
    private static final String ISSUER = "https://issuer.example";
    private static final String CLIENT_ID = "client-id";
    private static final String NONCE = "nonce-value";
    private static final Instant VALIDATION_TIME = Instant.parse("2026-09-17T12:00:00Z");
    private static final OidcIdTokenValidator ID_TOKEN_VALIDATOR = new OidcIdTokenValidator();
    private static final OidcAuthenticationRequestState REQUEST_STATE = new OidcAuthenticationRequestState(
            "default",
            "state-value",
            NONCE,
            "pkce-verifier",
            null,
            ISSUER,
            URI.create("https://rp.example/resource"),
            URI.create("https://rp.example/oidc/callback"),
            List.of("openid"),
            VALIDATION_TIME.minusSeconds(1),
            VALIDATION_TIME.plusSeconds(300));

    private static JwkKeys encryptionKeys;
    private static OidcValidatedIdToken signedIdToken;
    private static OidcTenantContext nestedTenant;
    private static OidcTenantContext encryptionOnlyTenant;

    @BeforeAll
    static void initClass() throws Exception {
        JwkKeys signingKeys = JwkKeys.builder()
                .resource(Resource.create("oidc-next-sign-jwk.json"))
                .build();
        encryptionKeys = JwkKeys.builder()
                .resource(Resource.create("oidc-next-encrypt-jwk.json"))
                .build();
        Jwt jwt = Jwt.builder()
                .algorithm("RS256")
                .keyId("verify-rsa")
                .issuer(ISSUER)
                .subject("user1")
                .addAudience(CLIENT_ID)
                .issueTime(VALIDATION_TIME)
                .expirationTime(VALIDATION_TIME.plusSeconds(3600))
                .nonce(NONCE)
                .build();
        SignedJwt signedJwt = SignedJwt.sign(jwt, signingKeys.forKeyId("sign-rsa").orElseThrow());
        signedIdToken = new OidcValidatedIdToken(signedJwt.tokenContent(), false, signedJwt, jwt);
        URI jwksUri = OidcJweCriticalHeadersTest.class.getClassLoader()
                .getResource("oidc-next-verify-public-jwk.json")
                .toURI();
        nestedTenant = tenant(jwksUri, true);
        encryptionOnlyTenant = tenant(jwksUri, false);
    }

    @TestFactory
    Stream<DynamicTest> authorizationRejectsCriticalHeaders() {
        return invalidHeaders().stream().map(header -> dynamicTest(header.name(), () -> {
            String token = OidcTestJwe.encrypt(signedIdToken.rawToken(), encryptionKeys, true, header.json());
            assertRejected(ID_TOKEN_VALIDATOR.validate(token, nestedTenant, REQUEST_STATE, VALIDATION_TIME));
        }));
    }

    @TestFactory
    Stream<DynamicTest> refreshRejectsCriticalHeaders() {
        return invalidHeaders().stream().map(header -> dynamicTest(header.name(), () -> {
            String token = OidcTestJwe.encrypt(signedIdToken.rawToken(), encryptionKeys, true, header.json());
            assertRejected(ID_TOKEN_VALIDATOR.validateRefresh(token, nestedTenant, signedIdToken, VALIDATION_TIME));
        }));
    }

    @TestFactory
    Stream<DynamicTest> nestedUserInfoRejectsCriticalHeaders() {
        return invalidHeaders().stream().map(header -> dynamicTest(header.name(), () -> {
            String token = OidcTestJwe.encrypt(signedIdToken.rawToken(), encryptionKeys, true, header.json());
            assertRejected(nestedTenant.userInfoJwtProcessor().orElseThrow()
                                   .validate(token, nestedTenant, signedIdToken, VALIDATION_TIME));
        }));
    }

    @TestFactory
    Stream<DynamicTest> encryptionOnlyUserInfoRejectsCriticalHeaders() {
        return invalidHeaders().stream().map(header -> dynamicTest(header.name(), () -> {
            String token = OidcTestJwe.encrypt("{\"sub\":\"user1\"}", encryptionKeys, false, header.json());
            assertRejected(encryptionOnlyTenant.userInfoJwtProcessor().orElseThrow()
                                   .validate(token, encryptionOnlyTenant, signedIdToken, VALIDATION_TIME));
        }));
    }

    @Test
    void ordinaryEncryptedTokensRemainAccepted() throws Exception {
        assertAccepted(JsonObject.empty());
    }

    @Test
    void unknownNonCriticalHeadersRemainAccepted() throws Exception {
        assertAccepted(JsonObject.builder().set("urn:helidon:test:extension", true).build());
    }

    @Test
    void criticalHeaderIsRejectedBeforeKeySelectionOrDecryption() {
        OidcJweDecryptor decryptor = OidcJweDecryptor.create(Optional.empty(), "test", "ID Token");
        JwtHeaders headers = JwtHeaders.builder()
                .algorithm("RSA-OAEP-256")
                .encryption("A256GCM")
                .addHeaderCritical("urn:helidon:test:extension")
                .build();

        IllegalStateException exception = assertThrows(IllegalStateException.class,
                                                       () -> decryptor.decrypt("unused", headers));

        assertThat(exception.getMessage(), is("ID Token JWE contains unsupported critical headers"));
    }

    @Test
    void storedEncryptedIdTokenCannotBypassCriticalHeaderPolicy() throws Exception {
        OidcCookieStateHandler cookies = nestedTenant.cookieStateHandler();
        for (boolean critical : List.of(false, true)) {
            JsonObject headers = critical
                    ? JsonObject.builder().setStrings("crit", List.of("extension")).set("extension", true).build()
                    : JsonObject.empty();
            String token = OidcTestJwe.encrypt(signedIdToken.rawToken(), encryptionKeys, true, headers);
            OidcValidatedIdToken storedIdToken = new OidcValidatedIdToken(token,
                                                                         true,
                                                                         signedIdToken.signedJwt(),
                                                                         signedIdToken.jwt());
            OidcLocalAuthenticationResult stored = OidcLocalAuthenticationResult.fromStoredValues(
                    OidcLocalAuthenticationState.builder()
                            .tenantId("default")
                            .idToken(storedIdToken)
                            .accessToken("access-token")
                            .tokenType("Bearer")
                            .createdAt(VALIDATION_TIME)
                            .expiresAt(VALIDATION_TIME.plusSeconds(600))
                            .buildPrototype());
            Map<String, List<String>> cookieSet = new LinkedHashMap<>();
            cookies.createLocalAuthenticationResultCookies(stored, Map.of(), VALIDATION_TIME)
                    .forEach(cookie -> cookieSet.put(cookie.name(), List.of(cookie.value())));

            assertThat(cookies.readLocalAuthenticationResult(cookieSet,
                                                              VALIDATION_TIME,
                                                              nestedTenant.idTokenDecryptor()).isPresent(),
                       is(!critical));
        }
    }

    private static void assertAccepted(JsonObject additionalHeaders) throws Exception {
        String nested = OidcTestJwe.encrypt(signedIdToken.rawToken(), encryptionKeys, true, additionalHeaders);
        assertThat(ID_TOKEN_VALIDATOR.validate(nested, nestedTenant, REQUEST_STATE, VALIDATION_TIME).succeeded(), is(true));
        assertThat(ID_TOKEN_VALIDATOR.validateRefresh(nested, nestedTenant, signedIdToken, VALIDATION_TIME).succeeded(),
                   is(true));
        assertThat(nestedTenant.userInfoJwtProcessor().orElseThrow()
                           .validate(nested, nestedTenant, signedIdToken, VALIDATION_TIME).succeeded(), is(true));
        String encryptionOnly = OidcTestJwe.encrypt("{\"sub\":\"user1\"}", encryptionKeys, false, additionalHeaders);
        assertThat(encryptionOnlyTenant.userInfoJwtProcessor().orElseThrow()
                           .validate(encryptionOnly, encryptionOnlyTenant, signedIdToken, VALIDATION_TIME).succeeded(),
                   is(true));
    }

    private static void assertRejected(OidcValidationResult<?> result) {
        assertThat(result.succeeded(), is(false));
        assertThat(result.validatedToken().isEmpty(), is(true));
    }

    private static OidcTenantContext tenant(URI jwksUri, boolean signedUserInfo) {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId(CLIENT_ID)
                .clientSecret("test-client-secret")
                .endpoints(endpoints -> endpoints.authorizationEndpointUri(URI.create(ISSUER + "/authorize"))
                        .tokenEndpointUri(URI.create(ISSUER + "/token"))
                        .userInfoEndpointUri(URI.create(ISSUER + "/userinfo"))
                        .jwksUri(jwksUri)
                        .tlsRequired(false))
                .authorizationCode(config -> config.redirectionEndpointUri(REQUEST_STATE.redirectionEndpointUri()))
                .idToken(config -> config.decryptionJwk(ResourceConfig.builder()
                        .resourcePath("oidc-next-encrypt-jwk.json")
                        .buildPrototype()))
                .userInfo(userInfo -> userInfo.jwt(config -> {
                    config.encryptionAlgorithm("RSA-OAEP-256")
                            .contentEncryptionAlgorithm("A256GCM")
                            .decryptionJwk(ResourceConfig.builder()
                                    .resourcePath("oidc-next-encrypt-jwk.json")
                                    .buildPrototype());
                    if (signedUserInfo) {
                        config.signingAlgorithm("RS256");
                    }
                }))
                .cookies(config -> config.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();
        return OidcTenantContext.ready("default", tenant);
    }

    private static List<HeaderCase> invalidHeaders() {
        return List.of(
                new HeaderCase("unsupported extension", "{\"crit\":[\"extension\"],\"extension\":true}"),
                new HeaderCase("empty list", "{\"crit\":[]}"),
                new HeaderCase("duplicate names", "{\"crit\":[\"extension\",\"extension\"],\"extension\":true}"),
                new HeaderCase("missing listed parameter", "{\"crit\":[\"extension\"]}"),
                new HeaderCase("registered alg", "{\"crit\":[\"alg\"]}"),
                new HeaderCase("registered enc", "{\"crit\":[\"enc\"]}"),
                new HeaderCase("string instead of array", "{\"crit\":\"extension\",\"extension\":true}"),
                new HeaderCase("empty string", "{\"crit\":\"\"}"),
                new HeaderCase("null", "{\"crit\":null}"),
                new HeaderCase("number", "{\"crit\":7}"),
                new HeaderCase("boolean", "{\"crit\":false}"),
                new HeaderCase("object", "{\"crit\":{\"extension\":true}}"),
                new HeaderCase("mixed array", "{\"crit\":[\"extension\",7],\"extension\":true}"),
                new HeaderCase("null array member", "{\"crit\":[null]}"));
    }

    private record HeaderCase(String name, String header) {
        private JsonObject json() {
            return JsonParser.create(header).readJsonObject();
        }
    }
}
