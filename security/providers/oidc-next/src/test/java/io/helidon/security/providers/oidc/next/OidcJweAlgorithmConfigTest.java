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
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Stream;

import io.helidon.common.configurable.Resource;
import io.helidon.config.Config;
import io.helidon.config.ConfigSources;
import io.helidon.json.JsonObject;
import io.helidon.security.jwt.EncryptedJwt;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.jwt.jwk.JwkRSA;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

class OidcJweAlgorithmConfigTest {
    private static final String ISSUER = "https://issuer.example";
    private static final String CLIENT_ID = "client-id";
    private static final String PRIVATE_KEYS = Resource.create("oidc-next-encrypt-jwk.json").string();
    private static final Instant VALIDATION_TIME = Instant.parse("2026-09-17T12:00:00Z");
    private static final OidcIdTokenValidator ID_TOKEN_VALIDATOR = new OidcIdTokenValidator();
    private static final OidcAuthenticationRequestState REQUEST_STATE = new OidcAuthenticationRequestState(
            "default", "state-value", "nonce-value", "pkce-verifier", null, ISSUER,
            URI.create("https://rp.example/resource"), URI.create("https://rp.example/oidc/callback"),
            VALIDATION_TIME.minusSeconds(1), VALIDATION_TIME.plusSeconds(300));

    private static JwkRSA encryptionKey;
    private static OidcValidatedIdToken signedIdToken;
    private static URI jwksUri;

    @BeforeAll
    static void initClass() throws Exception {
        JwkKeys signingKeys = JwkKeys.builder().resource(Resource.create("oidc-next-sign-jwk.json")).build();
        encryptionKey = (JwkRSA) JwkKeys.builder().resource(Resource.create("test decryption keys", PRIVATE_KEYS))
                .build().forKeyId("encrypt-rsa").orElseThrow();
        Jwt jwt = Jwt.builder().algorithm("RS256").keyId("verify-rsa")
                .issuer(ISSUER).subject("user1").addAudience(CLIENT_ID)
                .issueTime(VALIDATION_TIME).expirationTime(VALIDATION_TIME.plusSeconds(3600))
                .nonce(REQUEST_STATE.nonce()).build();
        SignedJwt signed = SignedJwt.sign(jwt, signingKeys.forKeyId("sign-rsa").orElseThrow());
        signedIdToken = new OidcValidatedIdToken(signed.tokenContent(), false, signed, jwt);
        jwksUri = OidcJweAlgorithmConfigTest.class.getClassLoader().getResource("oidc-next-verify-public-jwk.json").toURI();
    }

    @TestFactory
    Stream<DynamicTest> requiredIdTokenEncryptionNeedsDecryptionKey() {
        return invalidConfigurations("id-token.encryption-required", "", "true",
                                     tenant -> tenant.idToken(idToken -> idToken.encryptionRequired(true)));
    }

    @Test
    void disabledTenantMayRetainIncompleteIdTokenEncryptionConfiguration() {
        OidcTenantConfig tenant = tenantBuilder().enabled(false)
                .idToken(idToken -> idToken.encryptionRequired(true)).buildPrototype();
        assertThat(tenant.enabled(), is(false));
        assertThat(tenant.idToken().encryptionRequired(), is(true));
        assertThat(tenant.idToken().decryptionJwk().isEmpty(), is(true));

        for (String prefix : List.of("", "tenants.default.")) {
            OidcProviderConfig provider = OidcProviderConfig.create(config(prefix, Map.of(
                    "enabled", "false", "id-token.encryption-required", "true")));
            OidcTenantConfig configuredTenant = provider.tenants().get("default");
            assertThat(configuredTenant.enabled(), is(false));
            assertThat(configuredTenant.idToken().encryptionRequired(), is(true));
            assertThat(configuredTenant.idToken().decryptionJwk().isEmpty(), is(true));
        }
    }

    @TestFactory
    Stream<DynamicTest> idTokenRejectsUnsupportedKeyManagementAlgorithms() {
        return unsupportedKeyManagementAlgorithms().flatMap(algorithm -> invalidConfigurations(
                "id-token.allowed-encryption-algorithms", ".1", algorithm,
                tenant -> tenant.idToken(idToken -> idToken.allowedEncryptionAlgorithms(List.of("RSA-OAEP", algorithm)))));
    }

    @TestFactory
    Stream<DynamicTest> idTokenRejectsUnsupportedContentEncryptionAlgorithms() {
        return unsupportedContentEncryptionAlgorithms().flatMap(algorithm -> invalidConfigurations(
                "id-token.allowed-content-encryption-algorithms", ".1", algorithm,
                tenant -> tenant.idToken(idToken -> idToken.allowedContentEncryptionAlgorithms(List.of("A256GCM", algorithm)))));
    }

    @TestFactory
    Stream<DynamicTest> userInfoRejectsUnsupportedKeyManagementAlgorithms() {
        return unsupportedKeyManagementAlgorithms().flatMap(algorithm -> invalidConfigurations(
                "user-info.jwt.encryption-algorithm", "", algorithm,
                tenant -> tenant.userInfo(userInfo -> userInfo.jwt(jwt -> jwt.encryptionAlgorithm(algorithm)
                        .contentEncryptionAlgorithm("A256GCM")
                        .decryptionJwk(Resource.create("test decryption keys", PRIVATE_KEYS))))));
    }

    @TestFactory
    Stream<DynamicTest> userInfoRejectsUnsupportedContentEncryptionAlgorithms() {
        return unsupportedContentEncryptionAlgorithms().flatMap(algorithm -> invalidConfigurations(
                "user-info.jwt.content-encryption-algorithm", "", algorithm,
                tenant -> tenant.userInfo(userInfo -> userInfo.jwt(jwt -> jwt.encryptionAlgorithm("RSA-OAEP")
                        .contentEncryptionAlgorithm(algorithm)
                        .decryptionJwk(Resource.create("test decryption keys", PRIVATE_KEYS))))));
    }

    @TestFactory
    Stream<DynamicTest> supportedConfigurationsProcessEncryptedResponses() {
        return Arrays.stream(EncryptedJwt.SupportedAlgorithm.values())
                .filter(EncryptedJwt.SupportedAlgorithm::supported)
                .flatMap(algorithm -> Arrays.stream(EncryptedJwt.SupportedEncryption.values())
                        .map(encryption -> dynamicTest(algorithm + "/" + encryption,
                                                       () -> assertSupportedCombination(algorithm.toString(),
                                                                                         encryption.toString()))));
    }

    @TestFactory
    Stream<DynamicTest> omittedUserInfoEncUsesRegistrationDefault() {
        return Arrays.stream(EncryptedJwt.SupportedAlgorithm.values())
                .filter(EncryptedJwt.SupportedAlgorithm::supported)
                .flatMap(algorithm -> Stream.of(false, true).map(signed -> dynamicTest(algorithm + "/signed=" + signed, () -> {
                    String alg = algorithm.toString();
                    OidcTenantContext tenant = tenant(alg, Optional.empty(), signed);
                    try {
                        String token = encrypt(alg, "A128CBC-HS256", true);
                        assertThat(ID_TOKEN_VALIDATOR.validate(token, tenant, REQUEST_STATE, VALIDATION_TIME).succeeded(),
                                   is(true));
                        OidcUserInfoJwtProcessor userInfo = tenant.userInfoJwtProcessor().orElseThrow();
                        assertUserInfo(userInfo.validate(encrypt(alg, "A128CBC-HS256", signed),
                                                         tenant, signedIdToken, VALIDATION_TIME));
                        OidcValidationResult<JsonObject> wrongEnc = userInfo.validate(encrypt(alg, "A256GCM", signed),
                                                                                      tenant, signedIdToken, VALIDATION_TIME);
                        assertThat(wrongEnc.succeeded(), is(false));
                        assertThat(wrongEnc.errorDescription().orElseThrow(),
                                   is("UserInfo JWE enc header does not match registration"));
                        String otherAlg = alg.equals("RSA-OAEP") ? "RSA-OAEP-256" : "RSA-OAEP";
                        OidcValidationResult<JsonObject> wrongAlg = userInfo.validate(encrypt(otherAlg, "A128CBC-HS256", signed),
                                                                                      tenant, signedIdToken, VALIDATION_TIME);
                        assertThat(wrongAlg.succeeded(), is(false));
                        assertThat(wrongAlg.errorDescription().orElseThrow(),
                                   is("UserInfo JWE alg header does not match registration"));
                    } finally {
                        tenant.webClient().closeResource();
                    }
                })));
    }

    private static Stream<String> unsupportedKeyManagementAlgorithms() {
        return Stream.of("RSA1_5", "dir", "A128KW", "ECDH-ES", "PBES2-HS256+A128KW", "none", "unknown",
                         "rsa-oaep-256", " RSA-OAEP");
    }

    private static Stream<String> unsupportedContentEncryptionAlgorithms() {
        return Stream.of("A256CBC", "RSA-OAEP", "unknown", "a256gcm", " A256GCM", "");
    }

    private static Stream<DynamicTest> invalidConfigurations(String property,
                                                             String index,
                                                             String value,
                                                             Consumer<OidcTenantConfig.Builder> customizer) {
        DynamicTest builderTest = dynamicTest("builder: " + property + "=" + value, () -> {
            OidcTenantConfig.Builder builder = tenantBuilder();
            customizer.accept(builder);
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::buildPrototype);
            assertThat(exception.getMessage(), containsString(property));
        });
        Stream<DynamicTest> configTests = Stream.of("", "tenants.default.").map(prefix -> dynamicTest(
                "config: " + prefix + property + "=" + value, () -> {
                    Config config = config(prefix, Map.of(property + index, value));
                    IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                                                                     () -> OidcProviderConfig.create(config));
                    assertThat(exception.getMessage(), containsString(property));
                }));
        return Stream.concat(Stream.of(builderTest), configTests);
    }

    private static OidcTenantConfig.Builder tenantBuilder() {
        return OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId(CLIENT_ID)
                .endpoints(endpoints -> endpoints.authorizationEndpointUri(URI.create(ISSUER + "/authorize"))
                        .tokenEndpointUri(URI.create(ISSUER + "/token"))
                        .userInfoEndpointUri(URI.create(ISSUER + "/userinfo"))
                        .jwksUri(URI.create(ISSUER + "/jwks")))
                .authorizationCode(code -> code.redirectionEndpointUri(URI.create("https://rp.example/oidc/callback")))
                .idToken(idToken -> idToken.allowedEncryptionAlgorithms(List.of("RSA-OAEP"))
                        .allowedContentEncryptionAlgorithms(List.of("A256GCM")))
                .userInfo(userInfo -> userInfo.jwt(jwt -> jwt.encryptionAlgorithm("RSA-OAEP")
                        .contentEncryptionAlgorithm("A256GCM")
                        .decryptionJwk(Resource.create("test decryption keys", PRIVATE_KEYS))))
                .cookies(cookies -> cookies.protection(protection -> protection.password("test-cookie-password")));
    }

    private static Config config(String prefix, Map<String, String> overrides) {
        Map<String, String> values = new HashMap<>(Map.ofEntries(
                Map.entry("issuer", ISSUER),
                Map.entry("client-id", CLIENT_ID),
                Map.entry("endpoints.authorization-endpoint-uri", ISSUER + "/authorize"),
                Map.entry("endpoints.token-endpoint-uri", ISSUER + "/token"),
                Map.entry("endpoints.user-info-endpoint-uri", ISSUER + "/userinfo"),
                Map.entry("endpoints.jwks-uri", ISSUER + "/jwks"),
                Map.entry("authorization-code.redirection-endpoint-uri", "https://rp.example/oidc/callback"),
                Map.entry("cookies.protection.password", "test-cookie-password"),
                Map.entry("id-token.allowed-encryption-algorithms.0", "RSA-OAEP"),
                Map.entry("id-token.allowed-content-encryption-algorithms.0", "A256GCM"),
                Map.entry("user-info.jwt.encryption-algorithm", "RSA-OAEP"),
                Map.entry("user-info.jwt.content-encryption-algorithm", "A256GCM"),
                Map.entry("user-info.jwt.decryption-jwk.content-plain", PRIVATE_KEYS)));
        values.putAll(overrides);
        Map<String, String> properties = new HashMap<>();
        values.forEach((key, value) -> properties.put(prefix + key, value));
        return Config.builder().disableEnvironmentVariablesSource().disableSystemPropertiesSource()
                .sources(ConfigSources.create(properties)).build();
    }

    private static void assertSupportedCombination(String algorithm, String encryption) throws JOSEException {
        for (String prefix : List.of("", "tenants.default.")) {
            OidcProviderConfig provider = OidcProviderConfig.create(config(prefix, Map.of(
                    "id-token.allowed-encryption-algorithms.0", algorithm,
                    "id-token.allowed-content-encryption-algorithms.0", encryption,
                    "user-info.jwt.encryption-algorithm", algorithm,
                    "user-info.jwt.content-encryption-algorithm", encryption)));
            assertAlgorithms(provider.tenants().get("default"), algorithm, encryption);
        }
        for (boolean signed : List.of(false, true)) {
            OidcTenantContext tenant = tenant(algorithm, Optional.of(encryption), signed);
            try {
                assertAlgorithms(tenant.tenantConfig(), algorithm, encryption);
                if (signed) {
                    String token = encrypt(algorithm, encryption, true);
                    OidcValidationResult<OidcValidatedIdToken> result =
                            ID_TOKEN_VALIDATOR.validate(token, tenant, REQUEST_STATE, VALIDATION_TIME);
                    assertThat(result.errorDescription().orElse("ID Token validation"), result.succeeded(), is(true));
                    OidcValidatedIdToken validated = result.validatedToken().orElseThrow();
                    assertThat(validated.encrypted(), is(true));
                    assertThat(validated.rawToken(), is(token));
                    assertThat(validated.signedJwt().tokenContent(), is(signedIdToken.rawToken()));
                    assertThat(ID_TOKEN_VALIDATOR.validateRefresh(token, tenant, validated, VALIDATION_TIME).succeeded(),
                               is(true));
                }
                assertUserInfo(tenant.userInfoJwtProcessor().orElseThrow()
                                       .validate(encrypt(algorithm, encryption, signed), tenant, signedIdToken, VALIDATION_TIME));
            } finally {
                tenant.webClient().closeResource();
            }
        }
    }

    private static void assertAlgorithms(OidcTenantConfig tenant, String algorithm, String encryption) {
        assertThat(tenant.idToken().allowedEncryptionAlgorithms(), is(List.of(algorithm)));
        assertThat(tenant.idToken().allowedContentEncryptionAlgorithms(), is(List.of(encryption)));
        OidcUserInfoJwtConfig userInfo = tenant.userInfo().orElseThrow().jwt().orElseThrow();
        assertThat(userInfo.encryptionAlgorithm().orElseThrow(), is(algorithm));
        assertThat(userInfo.contentEncryptionAlgorithm().orElseThrow(), is(encryption));
    }

    private static void assertUserInfo(OidcValidationResult<JsonObject> result) {
        assertThat(result.errorDescription().orElse("UserInfo validation"), result.succeeded(), is(true));
        assertThat(result.validatedToken().orElseThrow().stringValue("sub").orElseThrow(), is("user1"));
    }

    private static OidcTenantContext tenant(String algorithm, Optional<String> encryption, boolean signedUserInfo) {
        OidcIdTokenConfig.Builder idToken = OidcIdTokenConfig.builder()
                .decryptionJwk(Resource.create("test ID Token keys", PRIVATE_KEYS))
                .encryptionRequired(true).allowedEncryptionAlgorithms(List.of(algorithm));
        encryption.ifPresent(enc -> idToken.allowedContentEncryptionAlgorithms(List.of(enc)));
        OidcUserInfoJwtConfig.Builder userInfo = OidcUserInfoJwtConfig.builder()
                .decryptionJwk(Resource.create("test UserInfo keys", PRIVATE_KEYS)).encryptionAlgorithm(algorithm);
        encryption.ifPresent(userInfo::contentEncryptionAlgorithm);
        if (signedUserInfo) {
            userInfo.signingAlgorithm("RS256");
        }
        OidcTenantConfig config = tenantBuilder()
                .endpoints(endpoints -> endpoints.authorizationEndpointUri(URI.create(ISSUER + "/authorize"))
                        .tokenEndpointUri(URI.create(ISSUER + "/token"))
                        .userInfoEndpointUri(URI.create(ISSUER + "/userinfo"))
                        .jwksUri(jwksUri).tlsRequired(false))
                .idToken(idToken).userInfo(info -> info.jwt(userInfo)).buildPrototype();
        return OidcTenantContext.ready("default", config);
    }

    private static String encrypt(String algorithm, String encryption, boolean signed) throws JOSEException {
        JWEHeader.Builder header = new JWEHeader.Builder(JWEAlgorithm.parse(algorithm), EncryptionMethod.parse(encryption))
                .keyID("encrypt-rsa");
        if (signed) {
            header.contentType("JWT");
        }
        Payload payload = new Payload(signed ? signedIdToken.rawToken() : "{\"sub\":\"user1\"}");
        JWEObject jwe = new JWEObject(header.build(), payload);
        jwe.encrypt(new RSAEncrypter((RSAPublicKey) encryptionKey.publicKey()));
        return jwe.serialize();
    }
}
