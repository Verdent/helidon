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
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.function.Consumer;

import io.helidon.common.configurable.Resource;
import io.helidon.common.configurable.ResourceConfig;
import io.helidon.json.JsonObject;
import io.helidon.security.jwt.EncryptedJwt;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkKeys;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class OidcUserInfoJwtValidatorTest {
    private static final String ISSUER = "https://issuer.example";
    private static final String CLIENT_ID = "client-id";
    private static final String SUBJECT = "user1";
    private static final Instant VALIDATION_TIME = Instant.parse("2026-09-17T12:00:00Z");

    private static JwkKeys signingKeys;
    private static JwkKeys encryptionKeys;
    private static URI jwksUri;
    private static OidcValidatedIdToken idToken;

    @BeforeAll
    static void initClass() throws Exception {
        signingKeys = JwkKeys.builder().resource(Resource.create("oidc-next-sign-jwk.json")).build();
        encryptionKeys = JwkKeys.builder().resource(Resource.create("oidc-next-encrypt-jwk.json")).build();
        jwksUri = OidcUserInfoJwtValidatorTest.class.getClassLoader()
                .getResource("oidc-next-verify-public-jwk.json").toURI();
        Jwt jwt = Jwt.builder()
                .algorithm("RS256")
                .keyId("verify-rsa")
                .issuer(ISSUER)
                .subject(SUBJECT)
                .addAudience(CLIENT_ID)
                .issueTime(VALIDATION_TIME.minusSeconds(60))
                .expirationTime(VALIDATION_TIME.plusSeconds(3600))
                .build();
        SignedJwt signed = SignedJwt.sign(jwt, signingKeys.forKeyId("sign-rsa").orElseThrow());
        idToken = new OidcValidatedIdToken(signed.tokenContent(), false, signed, signed.getJwt());
    }

    @Test
    void signedAndNestedUserInfoMayOmitOptionalTimeClaims() {
        // Core requires sub/iss/aud, but does not require an exp, iat, or nbf in the UserInfo JWT.
        for (boolean nested : List.of(false, true)) {
            OidcTenantContext tenant = tenant(nested, Duration.ofSeconds(30));
            try {
                OidcValidationResult<JsonObject> result = validate(tenant, nested, _ -> { });

                assertThat("nested=" + nested, result.succeeded(), is(true));
                assertThat(result.validatedToken().orElseThrow().stringValue("sub").orElseThrow(), is(SUBJECT));
            } finally {
                tenant.webClient().closeResource();
            }
        }
    }

    @Test
    void signedAndNestedUserInfoExpirationRespectsConfiguredSkewStrictly() {
        for (boolean nested : List.of(false, true)) {
            OidcTenantContext tenant = tenant(nested, Duration.ofSeconds(30));
            try {
                assertThat("nested=" + nested, validate(tenant, nested, jwt -> jwt
                        .issueTime(VALIDATION_TIME.minusSeconds(60))
                        .expirationTime(VALIDATION_TIME.minusSeconds(29))).succeeded(), is(true));
                assertClaimsRejected(validate(tenant, nested, jwt -> jwt
                        .issueTime(VALIDATION_TIME.minusSeconds(60))
                        .expirationTime(VALIDATION_TIME.minusSeconds(30))));
                assertClaimsRejected(validate(tenant, nested, jwt -> jwt
                        .issueTime(VALIDATION_TIME.minusSeconds(60))
                        .expirationTime(VALIDATION_TIME.minusSeconds(31))));
            } finally {
                tenant.webClient().closeResource();
            }
        }
    }

    @Test
    void signedAndNestedUserInfoOptionalTimeClaimsRespectConfiguredSkew() {
        for (boolean nested : List.of(false, true)) {
            OidcTenantContext tenant = tenant(nested, Duration.ofSeconds(30));
            try {
                assertThat("nested=" + nested, validate(tenant, nested, jwt -> jwt
                        .issueTime(VALIDATION_TIME.plusSeconds(30))).succeeded(), is(true));
                assertClaimsRejected(validate(tenant, nested, jwt -> jwt
                        .issueTime(VALIDATION_TIME.plusSeconds(31))));

                assertThat("nested=" + nested, validate(tenant, nested, jwt -> jwt
                        .notBefore(VALIDATION_TIME.plusSeconds(30))).succeeded(), is(true));
                assertClaimsRejected(validate(tenant, nested, jwt -> jwt
                        .notBefore(VALIDATION_TIME.plusSeconds(31))));
            } finally {
                tenant.webClient().closeResource();
            }
        }
    }

    @Test
    void signedAndNestedUserInfoExpirationAtValidationTimeIsInvalidWithoutSkew() {
        for (boolean nested : List.of(false, true)) {
            OidcTenantContext tenant = tenant(nested, Duration.ZERO);
            try {
                assertThat("nested=" + nested, validate(tenant, nested, jwt -> jwt
                        .expirationTime(VALIDATION_TIME.plusSeconds(1))).succeeded(), is(true));
                assertClaimsRejected(validate(tenant, nested, jwt -> jwt
                        .expirationTime(VALIDATION_TIME)));
            } finally {
                tenant.webClient().closeResource();
            }
        }
    }

    private static OidcTenantContext tenant(boolean nested, Duration skew) {
        OidcTenantConfig config = OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId(CLIENT_ID)
                .endpoints(endpoints -> endpoints.authorizationEndpointUri(URI.create(ISSUER + "/authorize"))
                        .tokenEndpointUri(URI.create(ISSUER + "/token"))
                        .userInfoEndpointUri(URI.create(ISSUER + "/userinfo"))
                        .jwksUri(jwksUri)
                        .tlsRequired(false))
                .authorizationCode(code -> code.redirectionEndpointUri(URI.create("https://rp.example/oidc/callback")))
                .userInfo(userInfo -> userInfo.jwt(jwt -> {
                    jwt.signingAlgorithm("RS256").clockSkew(skew);
                    if (nested) {
                        jwt.encryptionAlgorithm("RSA-OAEP-256")
                                .contentEncryptionAlgorithm("A256GCM")
                                .decryptionJwk(ResourceConfig.builder()
                                        .resourcePath("oidc-next-encrypt-jwk.json")
                                        .buildPrototype());
                    }
                }))
                .cookies(cookies -> cookies.password("test-cookie-password"))
                .buildPrototype();
        return OidcTenantContext.ready("default", config);
    }

    private static OidcValidationResult<JsonObject> validate(OidcTenantContext tenant,
                                                              boolean nested,
                                                              Consumer<Jwt.Builder> customizer) {
        Jwt.Builder builder = Jwt.builder()
                .algorithm("RS256")
                .keyId("verify-rsa")
                .issuer(ISSUER)
                .subject(SUBJECT)
                .addAudience(CLIENT_ID);
        customizer.accept(builder);
        SignedJwt signed = SignedJwt.sign(builder.build(), signingKeys.forKeyId("sign-rsa").orElseThrow());
        String token = nested ? EncryptedJwt.builder(signed)
                .jwks(encryptionKeys, "encrypt-rsa")
                .algorithm(EncryptedJwt.SupportedAlgorithm.RSA_OAEP_256)
                .encryption(EncryptedJwt.SupportedEncryption.A256GCM)
                .build()
                .token() : signed.tokenContent();
        return tenant.userInfoJwtProcessor().orElseThrow().validate(token, tenant, idToken, VALIDATION_TIME);
    }

    private static void assertClaimsRejected(OidcValidationResult<JsonObject> result) {
        assertThat(result.errorDescription().orElse(""), is("UserInfo JWT claims are invalid"));
    }
}
