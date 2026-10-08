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
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

import io.helidon.common.configurable.Resource;
import io.helidon.common.configurable.ResourceConfig;
import io.helidon.json.JsonObject;
import io.helidon.security.jwt.EncryptedJwt;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.Jwk;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.providers.oidc.next.spi.OidcBackChannelLogoutStore;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class OidcLogoutTokenValidatorTest {
    private static final String ISSUER = "https://issuer.example";
    private static final String CLIENT_ID = "client-id";
    private static final String EVENT = "http://schemas.openid.net/event/backchannel-logout";
    private static final Instant NOW = Instant.parse("2026-10-08T10:00:00Z");

    private static JwkKeys signKeys;
    private static JwkKeys encryptionKeys;
    private static URI verificationUri;

    private final OidcLogoutTokenValidator validator = new OidcLogoutTokenValidator();

    @BeforeAll
    static void loadKeys() throws Exception {
        signKeys = JwkKeys.builder().resource(Resource.create("oidc-next-sign-jwk.json")).build();
        encryptionKeys = JwkKeys.builder().resource(Resource.create("oidc-next-encrypt-jwk.json")).build();
        verificationUri = OidcLogoutTokenValidatorTest.class.getClassLoader()
                .getResource("oidc-next-verify-public-jwk.json").toURI();
    }

    @Test
    void acceptsTypedAndUntypedSignedTokensWithExtraClaimsAndNonemptyEventObject() {
        for (String type : List.of("logout+jwt", "JWT", "")) {
            Jwt.Builder builder = baseToken(type.isEmpty() ? null : type);
            String signed = sign(builder, tokenBuilder -> {
                tokenBuilder.addPayloadClaim("extra_claim", "ignored");
                tokenBuilder.addPayloadClaim("events", JsonObject.builder()
                        .set(EVENT, JsonObject.builder().set("extra", "ignored").build()).build());
            });
            OidcValidationResult<OidcBackChannelLogoutStore.LogoutEvent> result = validate(signed, false, false);

            assertThat("typ=" + type + ", error=" + result.errorDescription().orElse("<none>"),
                       result.succeeded(), is(true));
            assertThat(result.validatedToken().orElseThrow().subject(), is(Optional.of("alice")));
            assertThat(result.validatedToken().orElseThrow().sid(), is(Optional.of("session-1")));
        }
    }

    @Test
    void sidOnlyAndSubjectOnlyAreValidUnlessSidIsRequired() {
        String sidOnly = token(builder -> builder.subject(null));
        String subjectOnly = token(builder -> builder.removePayloadClaim("sid"));

        assertThat(validate(sidOnly, false, false).succeeded(), is(true));
        assertThat(validate(subjectOnly, false, false).succeeded(), is(true));
        assertThat(validate(sidOnly, true, false).succeeded(), is(true));
        assertThat(validate(subjectOnly, true, false).succeeded(), is(false));
    }

    @Test
    void rejectsMissingOrInvalidLogoutSpecificClaims() {
        for (Consumer<Jwt.Builder> mutation : List.<Consumer<Jwt.Builder>>of(
                builder -> builder.jwtId(null),
                builder -> builder.addPayloadClaim("events", null),
                builder -> builder.addPayloadClaim("events", JsonObject.builder()
                        .set("other", JsonObject.builder().build()).build()),
                builder -> builder.addPayloadClaim("events", JsonObject.builder().set(EVENT, "not-an-object").build()),
                builder -> builder.nonce("forbidden"),
                builder -> builder.subject(null).removePayloadClaim("sid"),
                builder -> builder.addPayloadClaim("sid", 123),
                builder -> builder.type("at+jwt"),
                builder -> builder.issuer("https://other.example"),
                builder -> builder.addAudience("other-client"),
                builder -> builder.expirationTime(NOW.minusSeconds(120)),
                builder -> builder.issueTime(NOW.plusSeconds(600)))) {
            assertThat(validate(token(mutation), false, false).succeeded(), is(false));
        }
    }

    @Test
    void rejectsUnsignedAndTamperedLogoutTokens() {
        Jwt unsigned = baseToken().algorithm(Jwk.ALG_NONE).build();
        String none = SignedJwt.sign(unsigned, Jwk.NONE_JWK).tokenContent();
        String valid = token(_ -> { });
        int signatureIndex = valid.lastIndexOf('.') + 1;
        String altered = valid.substring(0, signatureIndex)
                + (valid.charAt(signatureIndex) == 'A' ? 'B' : 'A')
                + valid.substring(signatureIndex + 1);

        assertThat(validate(none, false, false).succeeded(), is(false));
        assertThat(validate(altered, false, false).succeeded(), is(false));
    }

    @Test
    void encryptedLogoutTokenUsesIdTokenDecryptionProfile() {
        String signed = token(_ -> { });
        String encrypted = EncryptedJwt.builder(SignedJwt.parseToken(signed))
                .jwks(encryptionKeys, "encrypt-rsa").build().token();

        assertThat(validate(encrypted, false, true).succeeded(), is(true));
        assertThat(validate(signed, false, true).succeeded(), is(false));
    }

    private OidcValidationResult<OidcBackChannelLogoutStore.LogoutEvent> validate(String value,
                                                                                    boolean sidRequired,
                                                                                    boolean encryptionRequired) {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId(CLIENT_ID)
                .endpoints(endpoints -> endpoints.authorizationEndpointUri(URI.create(ISSUER + "/authorize"))
                        .tokenEndpointUri(URI.create(ISSUER + "/token"))
                        .jwksUri(verificationUri)
                        .tlsRequired(false))
                .authorizationCode(code -> code.redirectionEndpointUri(URI.create("https://rp.example/oidc/callback")))
                .idToken(idToken -> idToken.encryptionRequired(encryptionRequired)
                        .decryptionJwk(ResourceConfig.builder()
                                               .resourcePath("oidc-next-encrypt-jwk.json").buildPrototype()))
                .logout(logout -> logout.backChannel(backChannel -> backChannel
                        .uri(URI.create("https://rp.example/oidc/backchannel"))
                        .sessionRequired(sidRequired)))
                .cookies(cookies -> cookies.password("test-cookie-password"))
                .buildPrototype();
        return validator.validate(value, OidcTenantContext.ready("default", tenant), NOW);
    }

    private static Jwt.Builder baseToken() {
        return baseToken("logout+jwt");
    }

    private static Jwt.Builder baseToken(String type) {
        Jwt.Builder builder = Jwt.builder()
                .algorithm("RS256")
                .keyId("verify-rsa")
                .issuer(ISSUER)
                .subject("alice")
                .addAudience(CLIENT_ID)
                .issueTime(NOW)
                .expirationTime(NOW.plusSeconds(120))
                .jwtId("jwt-1")
                .addPayloadClaim("sid", "session-1")
                .addPayloadClaim("events", JsonObject.builder().set(EVENT, JsonObject.builder().build()).build());
        if (type != null) {
            builder.type(type);
        }
        return builder;
    }

    private static String token(Consumer<Jwt.Builder> customizer) {
        return sign(baseToken(), customizer);
    }

    private static String sign(Jwt.Builder builder, Consumer<Jwt.Builder> customizer) {
        customizer.accept(builder);
        return SignedJwt.sign(builder.build(), signKeys.forKeyId("sign-rsa").orElseThrow()).tokenContent();
    }
}
